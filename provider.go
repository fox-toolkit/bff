// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Provider is an OpenID Provider configured from its metadata. A Provider can be shared by several clients.
type Provider struct {
	oidc                 *oidc.Provider
	client               *http.Client
	keys                 *keySet
	nonces               *nonceCache
	issuer               string
	endSessionEndpoint   string
	revocationEndpoint   string
	parEndpoint          string
	promptValues         []string
	acrValues            []string
	dpopAlgs             []string
	idTokenAlgs          []string
	authMethods          []string
	authAlgs             []string
	requestObjectAlgs    []string
	issParameter         bool
	requirePAR           bool
	requireRequestObject bool
}

// The token response arrives within refreshTimeout with time left to store the session.
const providerTimeout = 10 * time.Second

// NewProvider retrieves the provider metadata of the issuer with OpenID Connect Discovery. The issuer must use https,
// except for a loopback host.
func NewProvider(ctx context.Context, issuer string, opts ...ProviderOption) (*Provider, error) {
	cfg := &providerConfig{client: &http.Client{Timeout: providerTimeout}}
	for _, opt := range opts {
		if err := opt.applyProvider(cfg); err != nil {
			return nil, err
		}
	}

	if err := checkURL(issuer); err != nil {
		return nil, fmt.Errorf("%w: issuer %w", ErrInvalidConfig, err)
	}

	p, err := oidc.NewProvider(oidc.ClientContext(ctx, cfg.client), issuer)
	if err != nil {
		return nil, err
	}

	var metadata struct {
		JWKSURI              string   `json:"jwks_uri"`
		EndSessionEndpoint   string   `json:"end_session_endpoint"`
		RevocationEndpoint   string   `json:"revocation_endpoint"`
		PAREndpoint          string   `json:"pushed_authorization_request_endpoint"`
		PromptValues         []string `json:"prompt_values_supported"`
		ACRValues            []string `json:"acr_values_supported"`
		DPoPAlgs             []string `json:"dpop_signing_alg_values_supported"`
		IDTokenAlgs          []string `json:"id_token_signing_alg_values_supported"`
		AuthMethods          []string `json:"token_endpoint_auth_methods_supported"`
		AuthAlgs             []string `json:"token_endpoint_auth_signing_alg_values_supported"`
		RequestObjectAlgs    []string `json:"request_object_signing_alg_values_supported"`
		ISSParameter         bool     `json:"authorization_response_iss_parameter_supported"`
		RequirePAR           bool     `json:"require_pushed_authorization_requests"`
		RequireRequestObject bool     `json:"require_signed_request_object"`
	}
	if err := p.Claims(&metadata); err != nil {
		return nil, err
	}
	metadata.EndSessionEndpoint = cmp.Or(cfg.endSessionEndpoint, metadata.EndSessionEndpoint)
	metadata.RevocationEndpoint = cmp.Or(cfg.revocationEndpoint, metadata.RevocationEndpoint)
	endpoints := []string{p.Endpoint().AuthURL, p.Endpoint().TokenURL, metadata.JWKSURI}
	optional := []string{p.UserInfoEndpoint(), metadata.EndSessionEndpoint, metadata.RevocationEndpoint, metadata.PAREndpoint}
	for _, endpoint := range optional {
		if endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	for _, endpoint := range endpoints {
		if err := checkURL(endpoint); err != nil {
			return nil, fmt.Errorf("%w: provider endpoint %q %w", ErrInvalidConfig, endpoint, err)
		}
	}
	if metadata.RequirePAR && metadata.PAREndpoint == "" {
		return nil, fmt.Errorf("%w: provider requires pushed authorization requests without endpoint", ErrInvalidConfig)
	}

	return &Provider{
		oidc:                 p,
		client:               cfg.client,
		issuer:               issuer,
		keys:                 newKeySet(cfg.client, metadata.JWKSURI),
		endSessionEndpoint:   metadata.EndSessionEndpoint,
		revocationEndpoint:   metadata.RevocationEndpoint,
		parEndpoint:          metadata.PAREndpoint,
		promptValues:         metadata.PromptValues,
		acrValues:            metadata.ACRValues,
		dpopAlgs:             metadata.DPoPAlgs,
		idTokenAlgs:          metadata.IDTokenAlgs,
		authMethods:          metadata.AuthMethods,
		authAlgs:             metadata.AuthAlgs,
		requestObjectAlgs:    metadata.RequestObjectAlgs,
		nonces:               newNonceCache(),
		issParameter:         metadata.ISSParameter,
		requirePAR:           metadata.RequirePAR,
		requireRequestObject: metadata.RequireRequestObject,
	}, nil
}

// ProviderOption configures a [Provider].
type ProviderOption interface {
	applyProvider(*providerConfig) error
}

type providerOptionFunc func(*providerConfig) error

func (f providerOptionFunc) applyProvider(c *providerConfig) error {
	return f(c)
}

type providerConfig struct {
	client             *http.Client
	endSessionEndpoint string
	revocationEndpoint string
}

// WithHTTPClient sets the HTTP client used for the requests to the provider. The default client uses
// [http.DefaultTransport] with a timeout of 10 seconds.
func WithHTTPClient(client *http.Client) ProviderOption {
	return providerOptionFunc(func(c *providerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: nil http client", ErrInvalidConfig)
		}
		c.client = client
		return nil
	})
}

// WithEndSessionEndpoint sets the end session endpoint of OpenID Connect RP-Initiated Logout, for a provider that
// supports it without publishing it. It replaces the endpoint of the provider metadata.
func WithEndSessionEndpoint(endpoint string) ProviderOption {
	return providerOptionFunc(func(c *providerConfig) error {
		if err := checkURL(endpoint); err != nil {
			return fmt.Errorf("%w: end session endpoint %w", ErrInvalidConfig, err)
		}
		c.endSessionEndpoint = endpoint
		return nil
	})
}

// WithRevocationEndpoint sets the token revocation endpoint (RFC 7009), for a provider that supports it without
// publishing it. It replaces the endpoint of the provider metadata.
func WithRevocationEndpoint(endpoint string) ProviderOption {
	return providerOptionFunc(func(c *providerConfig) error {
		if err := checkURL(endpoint); err != nil {
			return fmt.Errorf("%w: revocation endpoint %w", ErrInvalidConfig, err)
		}
		c.revocationEndpoint = endpoint
		return nil
	})
}

var (
	errNotAbsolute = errors.New("must be an absolute URL without fragment")
	errNotHTTPS    = errors.New("must use https")
)

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" {
		return errNotAbsolute
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errNotHTTPS
}

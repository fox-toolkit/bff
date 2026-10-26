// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Provider is an OpenID Provider configured from its metadata. A Provider can be shared by several clients.
type Provider struct {
	oidc   *oidc.Provider
	client *http.Client
	issuer string
	// ctx provides the HTTP client to the requests to the provider, without the cancellation of the caller's context.
	ctx                context.Context
	endSessionEndpoint string
	revocationEndpoint string
	promptValues       []string
	issParameter       bool
}

// NewProvider retrieves the provider metadata of the issuer with OpenID Connect Discovery. The issuer must use https,
// except for a loopback host.
func NewProvider(ctx context.Context, issuer string, opts ...ProviderOption) (*Provider, error) {
	cfg := &providerConfig{client: http.DefaultClient}
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
		EndSessionEndpoint string   `json:"end_session_endpoint"`
		RevocationEndpoint string   `json:"revocation_endpoint"`
		PromptValues       []string `json:"prompt_values_supported"`
		ISSParameter       bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if err := p.Claims(&metadata); err != nil {
		return nil, err
	}

	return &Provider{
		oidc:               p,
		client:             cfg.client,
		issuer:             issuer,
		ctx:                oidc.ClientContext(context.Background(), cfg.client),
		endSessionEndpoint: metadata.EndSessionEndpoint,
		revocationEndpoint: metadata.RevocationEndpoint,
		promptValues:       metadata.PromptValues,
		issParameter:       metadata.ISSParameter,
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
	client *http.Client
}

// WithHTTPClient sets the HTTP client used for the requests to the provider. The default is [http.DefaultClient].
func WithHTTPClient(client *http.Client) ProviderOption {
	return providerOptionFunc(func(c *providerConfig) error {
		if client == nil {
			return fmt.Errorf("%w: nil http client", ErrInvalidConfig)
		}
		c.client = client
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

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Frontend is the BFF of a browser-based application, with its own OpenID Connect client and user sessions.
type Frontend struct {
	oauth2                oauth2.Config
	auth                  clientAuth
	aead                  AEAD
	cfg                   *config
	provider              *Provider
	verifier              *oidc.IDTokenVerifier
	logoutVerifier        *oidc.IDTokenVerifier
	now                   func() time.Time
	cop                   *http.CrossOriginProtection
	tokens                *tokenGroup
	logger                *slog.Logger
	postLogoutRedirectURL string
	parEndpoint           string
	requestObjectAlg      string
	// partition identifies the frontend, by its issuer and client ID.
	partition string
}

// NewFrontend returns a [Frontend] for the OpenID Connect client.
//
// The aead encrypts the data the frontend stores in cookies and in its store, such as the access, refresh and ID
// tokens. When the frontend is served by several replicas, they must all use the same keys.
func NewFrontend(client Client, aead AEAD, opts ...Option) (*Frontend, error) {
	if err := client.validate(); err != nil {
		return nil, err
	}
	if aead == nil {
		return nil, fmt.Errorf("%w: nil aead", ErrInvalidConfig)
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt.apply(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.idleTimeout > cfg.absoluteTimeout {
		return nil, fmt.Errorf("%w: idle timeout exceeds absolute timeout", ErrInvalidConfig)
	}
	redirect, _ := url.Parse(client.RedirectURL)
	for _, origin := range cfg.trustedOrigins {
		if u, _ := url.Parse(origin); !sameSite(u, redirect) {
			return nil, fmt.Errorf("%w: trusted origin %q not same site with the redirect url", ErrInvalidConfig, origin)
		}
	}

	p := client.Provider
	parEndpoint := p.parEndpoint
	switch cfg.par {
	case PushedAuthorizationRequired:
		if parEndpoint == "" {
			return nil, fmt.Errorf("%w: provider has no pushed authorization request endpoint", ErrInvalidConfig)
		}
	case PushedAuthorizationDisabled:
		if p.requirePAR {
			return nil, fmt.Errorf("%w: provider requires pushed authorization requests", ErrInvalidConfig)
		}
		parEndpoint = ""
	}

	if cfg.dpop && len(p.dpopAlgs) > 0 && !slices.Contains(p.dpopAlgs, dpopAlg) {
		return nil, fmt.Errorf("%w: provider does not support dpop with %s", ErrInvalidConfig, dpopAlg)
	}

	if len(cfg.signingAlgs) > 0 && len(p.idTokenAlgs) > 0 &&
		!slices.ContainsFunc(cfg.signingAlgs, func(alg string) bool { return slices.Contains(p.idTokenAlgs, alg) }) {
		return nil, fmt.Errorf("%w: no signing algorithm in common with the provider", ErrInvalidConfig)
	}

	algs := cfg.signingAlgs
	if len(algs) == 0 {
		algs = slices.DeleteFunc(slices.Clone(p.idTokenAlgs), func(alg string) bool { return !slices.Contains(signingAlgs, alg) })
		if len(algs) == 0 && len(p.idTokenAlgs) > 0 {
			return nil, fmt.Errorf("%w: no supported signing algorithm advertised by the provider", ErrInvalidConfig)
		}
	}
	verifierConfig := &oidc.Config{ClientID: client.ClientID, SupportedSigningAlgs: algs}

	auth, err := newClientAuth(client, p)
	if err != nil {
		return nil, err
	}

	var requestObjectAlg string
	if cfg.requestObject {
		if client.ClientKey == nil {
			return nil, fmt.Errorf("%w: request object without client key", ErrInvalidConfig)
		}
		if parEndpoint == "" {
			return nil, fmt.Errorf("%w: request object without pushed authorization requests", ErrInvalidConfig)
		}
		var ok bool
		requestObjectAlg, ok = keyAlg(client.ClientKey.Public(), p.requestObjectAlgs)
		if !ok {
			return nil, fmt.Errorf("%w: provider does not support the algorithm of the client key for request objects", ErrInvalidConfig)
		}
	} else if p.requireRequestObject {
		return nil, fmt.Errorf("%w: provider requires request objects", ErrInvalidConfig)
	}

	sum := sha256.Sum256([]byte(p.issuer + "\x00" + client.ClientID))
	partition := base64.RawURLEncoding.EncodeToString(sum[:])
	fe := &Frontend{
		cfg:            cfg,
		aead:           scopedAEAD{AEAD: aead, scope: partition},
		provider:       p,
		verifier:       oidc.NewVerifier(p.issuer, providerKeySet{p.keys}, verifierConfig),
		logoutVerifier: oidc.NewVerifier(p.issuer, p.keys, verifierConfig),
		oauth2: oauth2.Config{
			ClientID:    client.ClientID,
			Endpoint:    p.oidc.Endpoint(),
			RedirectURL: client.RedirectURL,
			Scopes:      slices.Clone(client.Scopes),
		},
		auth:                  auth,
		postLogoutRedirectURL: client.PostLogoutRedirectURL,
		parEndpoint:           parEndpoint,
		requestObjectAlg:      requestObjectAlg,
		now:                   time.Now,
		cop:                   http.NewCrossOriginProtection(),
		logger:                slog.New(cfg.logHandler).With("client_id", client.ClientID),
		partition:             partition,
	}
	for _, origin := range cfg.trustedOrigins {
		if err := fe.cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	fe.tokens = newTokenGroup(func() time.Time { return fe.now() })
	return fe, nil
}

// providerClient returns the HTTP client of the provider, which sends DPoP proofs of the key when it is not nil.
func (fe *Frontend) providerClient(key *dpopKey) *http.Client {
	client := fe.provider.client
	if key == nil {
		return client
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c := *client
	c.Transport = &dpopTransport{base: base, key: key, nonces: fe.provider.nonces, now: fe.now}
	return &c
}

// logRejected logs a request rejected because it is invalid.
func (fe *Frontend) logRejected(r *http.Request, msg string, err error) {
	fe.logger.WarnContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

// logFailed logs a request that failed because of the store or the provider.
func (fe *Frontend) logFailed(r *http.Request, msg string, err error) {
	fe.logger.ErrorContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

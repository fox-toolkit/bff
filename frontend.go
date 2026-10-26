// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Frontend is a browser application served by the BFF, with its own OpenID Connect client and user sessions.
type Frontend struct {
	oauth2                oauth2.Config
	aead                  AEAD
	cfg                   *config
	provider              *Provider
	verifier              *oidc.IDTokenVerifier
	now                   func() time.Time
	cop                   *http.CrossOriginProtection
	refreshGroup          *refreshGroup
	postLogoutRedirectURL string
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

	p := client.Provider
	fe := &Frontend{
		cfg:      cfg,
		aead:     aead,
		provider: p,
		verifier: p.oidc.VerifierContext(p.ctx, &oidc.Config{ClientID: client.ClientID}),
		oauth2: oauth2.Config{
			ClientID:     client.ClientID,
			ClientSecret: client.ClientSecret,
			Endpoint:     p.oidc.Endpoint(),
			RedirectURL:  client.RedirectURL,
			Scopes:       slices.Clone(client.Scopes),
		},
		postLogoutRedirectURL: client.PostLogoutRedirectURL,
		now:                   time.Now,
		cop:                   http.NewCrossOriginProtection(),
	}
	fe.refreshGroup = newRefreshGroup(func() time.Time { return fe.now() })
	return fe, nil
}

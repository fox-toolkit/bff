// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"fmt"
	"net/url"
)

// Frontend is the BFF of a browser-based application, with its own OpenID Connect client and user sessions.
type Frontend struct {
	rp *relyingParty
}

// NewFrontend returns a [Frontend] for the OpenID Connect client.
//
// The aead encrypts the data the frontend stores in cookies and in its store, such as the access, refresh and ID
// tokens. When the frontend is served by several replicas, they must all use the same keys.
func NewFrontend(client Client, aead AEAD, opts ...FrontendOption) (*Frontend, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt.applyFrontend(cfg); err != nil {
			return nil, err
		}
	}
	rp, err := newRelyingParty(client, aead, cfg, sessionCookie)
	if err != nil {
		return nil, err
	}
	redirect, _ := url.Parse(client.RedirectURL)
	for _, origin := range cfg.trustedOrigins {
		if u, _ := url.Parse(origin); !sameSite(u, redirect) {
			return nil, fmt.Errorf("%w: trusted origin %q not same site with the redirect url", ErrInvalidConfig, origin)
		}
		if err := rp.cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	return &Frontend{rp: rp}, nil
}

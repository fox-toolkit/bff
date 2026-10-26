// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
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
	logger                *slog.Logger
	postLogoutRedirectURL string
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

	p := client.Provider
	sum := sha256.Sum256([]byte(p.issuer + "\x00" + client.ClientID))
	partition := base64.RawURLEncoding.EncodeToString(sum[:])
	fe := &Frontend{
		cfg:      cfg,
		aead:     scopedAEAD{AEAD: aead, scope: partition},
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
		logger:                slog.New(cfg.logHandler).With("client_id", client.ClientID),
		partition:             partition,
	}
	fe.refreshGroup = newRefreshGroup(func() time.Time { return fe.now() })
	return fe, nil
}

// logRejected logs a request rejected because it is invalid.
func (fe *Frontend) logRejected(r *http.Request, msg string, err error) {
	fe.logger.WarnContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

// logFailed logs a request that failed because of the store or the provider.
func (fe *Frontend) logFailed(r *http.Request, msg string, err error) {
	fe.logger.ErrorContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

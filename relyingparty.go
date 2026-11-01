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
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type relyingParty struct {
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
	// partition identifies the relying party, by its issuer and client ID.
	partition string
	cookie    cookieSpec
}

func newRelyingParty(client Client, aead AEAD, cfg *config, cookie cookieSpec) (*relyingParty, error) {
	if err := client.validate(); err != nil {
		return nil, err
	}
	if aead == nil {
		return nil, fmt.Errorf("%w: nil aead", ErrInvalidConfig)
	}
	if cfg.idleTimeout > cfg.absoluteTimeout {
		return nil, fmt.Errorf("%w: idle timeout exceeds absolute timeout", ErrInvalidConfig)
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
	rp := &relyingParty{
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
		cookie:                cookie,
	}
	rp.tokens = newTokenGroup(func() time.Time { return rp.now() })
	return rp, nil
}

func (rp *relyingParty) loginCookie(id string) cookieSpec {
	return loginCookie(rp.cookie, id)
}

// providerClient returns the HTTP client of the provider, which sends DPoP proofs of the key when it is not nil.
func (rp *relyingParty) providerClient(key *dpopKey) *http.Client {
	client := rp.provider.client
	if key == nil {
		return client
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c := *client
	c.Transport = &dpopTransport{base: base, key: key, nonces: rp.provider.nonces, now: rp.now}
	return &c
}

// logRejected logs a request rejected because it is invalid.
func (rp *relyingParty) logRejected(r *http.Request, msg string, err error) {
	rp.logger.WarnContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

// logFailed logs a request that failed because of the store or the provider.
func (rp *relyingParty) logFailed(r *http.Request, msg string, err error) {
	rp.logger.ErrorContext(r.Context(), msg, "path", r.URL.Path, "error", err)
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/rp/store"
	"golang.org/x/oauth2"
)

const (
	refreshSkew = time.Minute
	// refreshReuse is how long the latest tokens of a session are kept, since a browser sends concurrent requests with
	// the same session.
	refreshReuse = time.Minute
	// refreshTimeout bounds a refresh, which is not canceled with the request that started it.
	refreshTimeout = 15 * time.Second
	// endSessionTimeout bounds the end of a session, which waits for a refresh in flight.
	endSessionTimeout = time.Minute
)

var (
	errSessionEnded = errors.New("session ended")
	errStore        = errors.New("session store")
)

type refreshResult struct {
	at       time.Time
	token    *oauth2.Token
	idToken  string
	userInfo json.RawMessage
}

// tokenGroup runs the token requests of a session one at a time in this process, so a provider that rotates refresh
// tokens never sees one used twice. It keeps the latest tokens of each session for refreshReuse, for the requests sent
// with an older cookie and for the requests that run before the session is stored.
type tokenGroup struct {
	now       func() time.Time
	sessions  map[[sha256.Size]byte]*sessionTokens
	lastSweep time.Time
	mu        sync.Mutex
}

type sessionTokens struct {
	at     time.Time
	lock   chan struct{}
	latest *session
	failed map[string]tokenFailure
	refs   int
	// epoch changes when the tokens are forgotten, so a call that started before does not keep its result.
	epoch int
	calls int
}

type tokenFailure struct {
	err  error
	call int
}

type sharedError struct {
	err error
}

func (e *sharedError) Error() string { return e.err.Error() }
func (e *sharedError) Unwrap() error { return e.err }

func newTokenGroup(now func() time.Time) *tokenGroup {
	return &tokenGroup{now: now, sessions: make(map[[sha256.Size]byte]*sessionTokens)}
}

// Do runs fn with the lock of the session id. fn receives the latest tokens of the session kept by a previous call, or
// nil, and returns the session to keep, or nil, even when it fails.
func (g *tokenGroup) Do(ctx context.Context, id string, fn func(latest *session) (*session, error)) error {
	return g.do(ctx, id, nil, func(latest *session, _ error) (*session, error) { return fn(latest) })
}

// Request is like Do for a token request of the resource. When fn returns a sharedError, the calls for the same
// resource that waited for the lock receive its error as shared. The provider receives one token request for all of
// them.
func (g *tokenGroup) Request(ctx context.Context, id, resource string, fn func(latest *session, shared error) (*session, error)) error {
	return g.do(ctx, id, &resource, fn)
}

func (g *tokenGroup) do(ctx context.Context, id string, resource *string, fn func(latest *session, shared error) (*session, error)) error {
	key := sha256.Sum256([]byte(id))
	t, calls := g.acquire(key)
	defer g.release(key, t)
	select {
	case t.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-t.lock }()

	g.mu.Lock()
	var shared error
	if resource != nil {
		if f, ok := t.failed[*resource]; ok && f.call > calls {
			shared = f.err
		}
	}
	latest, epoch := t.latest, t.epoch
	if latest != nil && g.now().Sub(t.at) >= refreshReuse {
		latest = nil
	}
	g.mu.Unlock()

	keep, err := fn(latest, shared)
	se, failed := errors.AsType[*sharedError](err)
	if failed {
		err = se.err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	t.calls++
	if t.epoch != epoch {
		return err
	}
	if keep != nil {
		t.latest, t.at = keep, g.now()
	}
	switch {
	case resource == nil, shared != nil:
	case failed:
		if t.failed == nil {
			t.failed = make(map[string]tokenFailure)
		}
		t.failed[*resource] = tokenFailure{err: err, call: t.calls}
	default:
		delete(t.failed, *resource)
	}
	return err
}

// Forget removes the tokens kept for the session id.
func (g *tokenGroup) Forget(id string) {
	key := sha256.Sum256([]byte(id))
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.sessions[key]
	if t == nil {
		return
	}
	// A request holding the lock keeps using it, so the entry is only deleted when no request holds it.
	t.latest, t.at, t.failed = nil, time.Time{}, nil
	t.epoch++
	if t.refs == 0 {
		delete(g.sessions, key)
	}
}

func (g *tokenGroup) acquire(key [sha256.Size]byte) (*sessionTokens, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Sub(g.lastSweep) >= refreshReuse {
		for k, t := range g.sessions {
			if t.refs == 0 && now.Sub(t.at) >= refreshReuse {
				delete(g.sessions, k)
			}
		}
		g.lastSweep = now
	}
	t := g.sessions[key]
	if t == nil {
		t = &sessionTokens{lock: make(chan struct{}, 1)}
		g.sessions[key] = t
	}
	t.refs++
	return t, t.calls
}

func (g *tokenGroup) release(key [sha256.Size]byte, t *sessionTokens) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t.refs--
	if t.refs == 0 && t.latest == nil {
		delete(g.sessions, key)
	}
}

// updateTokens runs update with the lock of the session. It reports whether s changed.
func (rp *relyingParty) updateTokens(ctx context.Context, s *session, st sessionState, resource string, tr *tokenRequest, update func() (bool, error)) (bool, error) {
	changed := false
	err := rp.tokens.Request(ctx, s.LogoutCSRFToken, resource, func(latest *session, shared error) (*session, error) {
		tr.start(ctx)
		if st.id != "" {
			// Other replicas may have changed the stored session. The tokens kept in memory may be newer, as the
			// session is stored after the lock is released.
			stored, err := rp.loadSession(ctx, st.id)
			if err != nil {
				return nil, err
			}
			if latest == nil || stored.Generation > latest.Generation {
				latest = stored
			}
		}
		if latest != nil && latest.Generation > s.Generation {
			s.mergeTokens(latest)
			changed = true
		}
		updated, err := false, shared
		if shared == nil {
			if updated, err = update(); err != nil {
				err = &sharedError{err}
			}
		}
		changed = changed || updated
		if !changed {
			return nil, err
		}
		return s.clone(), err
	})
	return changed, err
}

// tokenRequest is the context of a token request and of the write of its result. It starts once the lock of the
// session is held, and the request that started it does not cancel it, since the provider may replace the refresh
// token. A new token request replaces the context of the previous one.
type tokenRequest struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (tr *tokenRequest) start(ctx context.Context) {
	tr.stop()
	tr.ctx, tr.cancel = context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
}

func (tr *tokenRequest) stop() {
	if tr.cancel != nil {
		tr.cancel()
	}
}

// loadSession returns the stored session of the id. It returns errSessionEnded when the session no longer exists.
func (rp *relyingParty) loadSession(ctx context.Context, id string) (*session, error) {
	r, err := rp.cfg.store.Load(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errSessionEnded
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStore, err)
	}
	data, err := rp.aead.Decrypt(r.Data, storeAssociatedData(id))
	if err != nil {
		return nil, errSessionEnded
	}
	s, err := decodeSession(data)
	if err != nil {
		return nil, errSessionEnded
	}
	return s, nil
}

// refresh renews the access token of s when it is stale. It reports whether s changed. It returns errSessionEnded when
// the provider rejects the refresh token.
func (rp *relyingParty) refresh(ctx context.Context, s *session, st sessionState, tr *tokenRequest) (bool, error) {
	return rp.updateTokens(ctx, s, st, "", tr, func() (bool, error) {
		if !s.stale(rp.now()) {
			return false, nil
		}
		res, err := rp.redeem(tr.ctx, s, "")
		if err != nil {
			return keepRefreshToken(s, res, err)
		}
		s.setToken(res.token, res.at)
		if res.idToken != "" {
			s.IDToken = res.idToken
		}
		if res.userInfo != nil {
			s.UserInfo = res.userInfo
		}
		return true, nil
	})
}

// refreshResource requests the access token of the resource when s has none or when it is stale. It reports whether s
// changed. It returns errSessionEnded when the provider rejects the refresh token.
func (rp *relyingParty) refreshResource(ctx context.Context, s *session, st sessionState, resource string, tr *tokenRequest) (bool, error) {
	if s.RefreshToken == "" {
		return false, errNoRefreshToken
	}
	return rp.updateTokens(ctx, s, st, resource, tr, func() (bool, error) {
		if t, ok := s.Resources[resource]; ok && !t.stale(rp.now()) {
			return false, nil
		}
		res, err := rp.redeem(tr.ctx, s, resource)
		if err != nil {
			return keepRefreshToken(s, res, err)
		}
		s.setResourceToken(resource, res.token, res.at)
		if res.idToken != "" {
			s.IDToken = res.idToken
		}
		return true, nil
	})
}

// keepRefreshToken keeps the refresh token of a response whose access token is rejected, since the provider may have
// replaced the previous one (RFC 6749 6).
func keepRefreshToken(s *session, res refreshResult, err error) (bool, error) {
	if res.token == nil || res.token.RefreshToken == "" {
		return false, err
	}
	s.setRefreshToken(res.token)
	return true, err
}

// redeem sends the refresh token of s to the provider, for an access token of the resource when it is not empty. With
// errNotDPoPBound, it also returns the rejected token.
func (rp *relyingParty) redeem(ctx context.Context, s *session, resource string) (refreshResult, error) {
	var key *dpopKey
	if s.DPoPKey != nil {
		var err error
		if key, err = parseDPoPKey(s.DPoPKey); err != nil {
			return refreshResult{}, err
		}
	}
	client := rp.providerClient(key)
	ctx = oidc.ClientContext(ctx, client)

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}}
	if resource != "" {
		form.Set("resource", resource)
	}
	token, err := rp.requestToken(ctx, client, form)
	if err != nil {
		if te, ok := errors.AsType[*tokenError](err); ok && te.Code == "invalid_grant" {
			return refreshResult{}, errSessionEnded
		}
		return refreshResult{}, err
	}
	if key != nil && !isDPoP(token.TokenType) {
		return refreshResult{token: token, at: rp.now()}, errNotDPoPBound
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken != "" {
		idToken, err := rp.verifyIDToken(ctx, rawIDToken)
		// OpenID Connect Core 12.2 requires the same subject. Other claims vary between providers and are not compared.
		if err == nil && idToken.Subject != s.Subject {
			err = errors.New("sub changed")
		}
		if err != nil {
			// Do not revoke the refresh token. A login in the same provider session may hold tokens of the same grant.
			return refreshResult{}, fmt.Errorf("%w: refreshed id token: %w", errSessionEnded, err)
		}
	}
	res := refreshResult{token: token, idToken: rawIDToken, at: rp.now()}
	if resource == "" && rp.cfg.userInfo {
		info, err := rp.provider.oidc.UserInfo(ctx, oauth2.StaticTokenSource(token))
		switch {
		case err != nil:
			// The claims of the previous UserInfo response are kept.
			rp.logger.WarnContext(ctx, "userinfo request failed", "error", err)
		case info.Subject != s.Subject:
			// OpenID Connect Core 5.3.2 requires the sub of the UserInfo response to match the ID token.
			return refreshResult{}, fmt.Errorf("%w: refreshed userinfo: sub changed", errSessionEnded)
		default:
			if err := info.Claims(&res.userInfo); err != nil {
				rp.logger.WarnContext(ctx, "userinfo request failed", "error", err)
			}
		}
	}
	return res, nil
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

const (
	// refreshSkew is how long before its expiration an access token is refreshed.
	refreshSkew = time.Minute
	// refreshReuse is how long the result of a refresh is reused for the requests sent with the refresh token it
	// replaced, since a browser sends concurrent requests with the same session.
	refreshReuse = time.Minute
	// refreshTimeout bounds a refresh, which is not canceled with the request that started it.
	refreshTimeout = 30 * time.Second
)

var errSessionEnded = errors.New("session ended")

type refreshResult struct {
	at      time.Time
	token   *oauth2.Token
	idToken string
}

// refreshGroup makes the concurrent and recent refreshes of a refresh token in this process share one call to the
// provider, so a provider that rotates refresh tokens never sees one used twice.
type refreshGroup struct {
	now       func() time.Time
	group     singleflight.Group
	recent    map[[sha256.Size]byte]refreshResult
	lastSweep time.Time
	mu        sync.Mutex
}

func newRefreshGroup(now func() time.Time) *refreshGroup {
	return &refreshGroup{now: now, recent: make(map[[sha256.Size]byte]refreshResult)}
}

// Do returns the result of fn for the refresh token. Concurrent calls share one call to fn, and a successful result
// answers the calls made within refreshReuse. Errors are not kept.
func (g *refreshGroup) Do(refreshToken string, fn func() (refreshResult, error)) (refreshResult, error) {
	key := sha256.Sum256([]byte(refreshToken))
	v, err, _ := g.group.Do(string(key[:]), func() (any, error) {
		// The lookup is done within the flight, so a call that starts once another one has completed reuses its result.
		if res, ok := g.lookup(key); ok {
			return res, nil
		}
		res, err := fn()
		if err != nil {
			return nil, err
		}
		res.at = g.now()
		g.remember(key, res)
		return res, nil
	})
	if err != nil {
		return refreshResult{}, err
	}
	return v.(refreshResult), nil
}

func (g *refreshGroup) lookup(key [sha256.Size]byte) (refreshResult, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	res, ok := g.recent[key]
	return res, ok && g.now().Sub(res.at) < refreshReuse
}

func (g *refreshGroup) remember(key [sha256.Size]byte, res refreshResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if res.at.Sub(g.lastSweep) >= refreshReuse {
		for k, v := range g.recent {
			if res.at.Sub(v.at) >= refreshReuse {
				delete(g.recent, k)
			}
		}
		g.lastSweep = res.at
	}
	g.recent[key] = res
}

// refresh renews the tokens of s. It returns errSessionEnded when the provider rejects the refresh token.
func (fe *Frontend) refresh(ctx context.Context, s *session) error {
	res, err := fe.refreshGroup.Do(s.RefreshToken, func() (refreshResult, error) {
		return fe.redeem(ctx, s.RefreshToken, s.Subject)
	})
	if err != nil {
		return err
	}

	s.setToken(res.token, res.at)
	if res.idToken != "" {
		s.IDToken = res.idToken
	}
	return nil
}

func (fe *Frontend) redeem(ctx context.Context, refreshToken, subject string) (refreshResult, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	ctx = oidc.ClientContext(ctx, fe.provider.client)

	token, err := fe.oauth2.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.ErrorCode == "invalid_grant" {
			return refreshResult{}, errSessionEnded
		}
		return refreshResult{}, err
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken != "" {
		// OpenID Connect Core 12.2: a refreshed ID token must be valid and keep the same subject.
		idToken, err := fe.verifyIDToken(ctx, rawIDToken)
		if err != nil || idToken.Subject != subject {
			return refreshResult{}, errSessionEnded
		}
	}
	return refreshResult{token: token, idToken: rawIDToken}, nil
}

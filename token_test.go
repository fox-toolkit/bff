// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken(t *testing.T) {
	_, ok := Token(t.Context())
	assert.False(t, ok)

	ctx := context.WithValue(t.Context(), sessionKey{}, &requestState{})
	_, ok = Token(ctx)
	assert.False(t, ok)

	s := testSession()
	s.TokenType = "Bearer"
	ctx = context.WithValue(t.Context(), sessionKey{}, &requestState{session: s})
	token, ok := Token(ctx)
	require.True(t, ok)
	assert.Equal(t, "access-token", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, time.Unix(s.Expiry, 0), token.Expiry)
	assert.Empty(t, token.RefreshToken)
}

type upstream struct {
	*httptest.Server
	requests chan *http.Request
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{requests: make(chan *http.Request, 1)}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.requests <- r
		w.Header().Add("Set-Cookie", "__Host-bff.0=evil; Path=/")
		w.Header().Add("Set-Cookie", "api=1")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(u.Close)
	return u
}

func (e *testEnv) mountProxy(t *testing.T, pattern string, u *upstream, opts ...fox.RouteOption) {
	t.Helper()
	target, err := url.Parse(u.URL)
	require.NoError(t, err)
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		Transport: Transport(nil),
	}
	_, err = e.router.Add(fox.MethodAny, pattern, fox.WrapH(proxy), append(opts, fox.WithMiddleware(e.fe.Middleware()))...)
	require.NoError(t, err)
}

func TestTransport(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour})
	u := newUpstream(t)
	e.mountProxy(t, "/api/*{any}", u)
	e.mountProxy(t, "/public/*{any}", u, AllowAnonymous())
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	rec := e.do(http.MethodGet, "/api/orders", append(cookies, &http.Cookie{Name: "other", Value: "1"}), nil)
	require.Equal(t, http.StatusOK, rec.Code)
	req := <-u.requests
	assert.Equal(t, "Bearer "+s.AccessToken, req.Header.Get("Authorization"))
	assert.Equal(t, "other=1", req.Header.Get("Cookie"))
	assert.Equal(t, []string{"api=1"}, rec.Header().Values("Set-Cookie"))

	rec = e.do(http.MethodGet, "/public/catalog", nil, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	req = <-u.requests
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestTransportKeepsRequest(t *testing.T) {
	u := newUpstream(t)
	s := testSession()
	ctx := context.WithValue(t.Context(), sessionKey{}, &requestState{session: s})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	require.NoError(t, err)

	resp, err := Transport(nil).RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, "Bearer access-token", (<-u.requests).Header.Get("Authorization"))
	assert.Empty(t, req.Header.Get("Authorization"))
}

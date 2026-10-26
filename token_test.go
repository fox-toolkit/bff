// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessToken(t *testing.T) {
	_, ok := AccessToken(t.Context())
	assert.False(t, ok)

	ctx := context.WithValue(t.Context(), sessionKey{}, &requestState{})
	_, ok = AccessToken(ctx)
	assert.False(t, ok)

	s := testSession()
	s.TokenType = "Bearer"
	ctx = context.WithValue(t.Context(), sessionKey{}, &requestState{session: s})
	token, ok := AccessToken(ctx)
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

func TestTransportRedirect(t *testing.T) {
	var got string
	record := func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }
	other := httptest.NewServer(http.HandlerFunc(record))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/next", record)
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/next", http.StatusFound) })
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/next", http.StatusFound)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	s := testSession()
	s.TokenType = "Bearer"
	ctx := context.WithValue(t.Context(), sessionKey{}, &requestState{session: s})
	for path, want := range map[string]string{"/same": "Bearer access-token", "/other": ""} {
		t.Run(path, func(t *testing.T) {
			got = "unset"
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.URL+path, nil)
			require.NoError(t, err)
			resp, err := (&http.Client{Transport: Transport(nil)}).Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, want, got)
		})
	}
}

func TestTransportUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
			"Set-Cookie: __Host-bff.0=evil; Path=/\r\nSet-Cookie: api=1\r\n\r\n")
		_ = brw.Flush()
		time.Sleep(100 * time.Millisecond)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) }, Transport: Transport(nil)}
	_, err = e.router.Add(fox.MethodAny, "/ws", fox.WrapH(proxy), fox.WithMiddleware(e.fe.Middleware()))
	require.NoError(t, err)
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)
	app := httptest.NewServer(e.router)
	defer app.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(app.URL, "http://"))
	require.NoError(t, err)
	defer conn.Close()
	var pairs []string
	for _, c := range cookies {
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	_, err = conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: app\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCookie: " +
		strings.Join(pairs, "; ") + "\r\n\r\n"))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	lines := resp.Header.Values("Set-Cookie")
	assert.Contains(t, lines, "api=1")
	assert.NotContains(t, strings.Join(lines, "\n"), "evil")
	assert.Len(t, sessionCookieLines(resp.Header), 1)
}

func TestClaims(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Claims: map[string]any{"name": "Alice"}})
	var got map[string]any
	var ok bool
	h := func(c *fox.Context) {
		got, ok = Claims(c.Request().Context())
		c.Writer().WriteHeader(http.StatusOK)
	}
	_, err := e.router.Add(fox.MethodGet, "/me", h, fox.WithMiddleware(e.fe.Middleware()), AllowAnonymous())
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/me", e.loggedIn(t), nil).Code)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"sub": "alice", "name": "Alice"}, got)

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/me", nil, nil).Code)
	assert.False(t, ok)

	_, ok = Claims(t.Context())
	assert.False(t, ok)
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
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
	_, err = e.router.Add(fox.MethodAny, pattern, fox.WrapH(proxy), append(opts, fox.WithMiddleware(e.fe.Authenticate()))...)
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
	_, err = e.router.Add(fox.MethodAny, "/ws", fox.WrapH(proxy), fox.WithMiddleware(e.fe.Authenticate()))
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

func TestUserClaims(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Claims: map[string]any{"name": "Alice"}})
	var got map[string]any
	var ok bool
	h := func(c *fox.Context) {
		got, ok = UserClaims(c.Request().Context())
		c.Writer().WriteHeader(http.StatusOK)
	}
	_, err := e.router.Add(fox.MethodGet, "/me", h, fox.WithMiddleware(e.fe.Authenticate()), AllowAnonymous())
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/me", e.loggedIn(t), nil).Code)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"sub": "alice", "name": "Alice"}, got)

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/me", nil, nil).Code)
	assert.False(t, ok)

	_, ok = UserClaims(t.Context())
	assert.False(t, ok)
}

const (
	billing = "https://billing.example.com/"
	orders  = "urn:orders"
)

func (e *testEnv) mountResourceProxy(t *testing.T, pattern string, u *upstream, resource string, opts ...fox.RouteOption) {
	t.Helper()
	target, err := url.Parse(u.URL)
	require.NoError(t, err)
	proxy := &httputil.ReverseProxy{
		Rewrite:      func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		Transport:    ResourceTransport(nil, resource),
		ErrorHandler: ProxyErrorHandler,
	}
	_, err = e.router.Add(fox.MethodAny, pattern, fox.WrapH(proxy), append(opts, fox.WithMiddleware(e.fe.Authenticate()))...)
	require.NoError(t, err)
}

func (e *testEnv) mountHandler(t *testing.T, pattern string, h fox.HandlerFunc, opts ...fox.RouteOption) {
	t.Helper()
	_, err := e.router.Add(fox.MethodAny, pattern, h, append(opts, fox.WithMiddleware(e.fe.Authenticate()))...)
	require.NoError(t, err)
}

func bearer(t *testing.T, r *http.Request) string {
	t.Helper()
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	require.True(t, ok)
	return token
}

func TestResourceTransport(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		opts := []Option{WithResources(billing, orders)}
		if stateful {
			opts = append(opts, WithStore(&mapStore{records: make(map[string]store.Record)}))
		}
		e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour}, opts...)
		u := newUpstream(t)
		e.mountResourceProxy(t, "/billing/*{any}", u, billing)
		e.mountProxy(t, "/api/*{any}", u)
		cookies := e.loggedIn(t)

		rec := e.do(http.MethodGet, "/billing/invoices", cookies, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		token := bearer(t, <-u.requests)
		resource, ok := e.idp.AccessTokenResource(token)
		require.True(t, ok)
		assert.Equal(t, billing, resource)
		assert.Equal(t, 1, e.idp.Refreshes())

		lines := sessionCookieLines(rec.Header())
		if stateful {
			assert.Empty(t, lines)
		} else {
			require.NotEmpty(t, lines)
			cookies = requestCookies(t, rec.Header())
		}

		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
		assert.Equal(t, token, bearer(t, <-u.requests))
		assert.Equal(t, 1, e.idp.Refreshes())

		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api/orders", cookies, nil).Code)
		resource, ok = e.idp.AccessTokenResource(bearer(t, <-u.requests))
		require.True(t, ok)
		assert.Empty(t, resource)
	}
}

func TestResourceTokenRenewal(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second}, WithResources(billing))
	var tokens []string
	e.mountHandler(t, "/api", func(c *fox.Context) {
		token, err := ResourceAccessToken(c.Request().Context(), billing)
		require.NoError(t, err)
		tokens = append(tokens, token.AccessToken)
	})
	cookies := e.loggedIn(t)

	rec := e.do(http.MethodGet, "/api", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	cookies = requestCookies(t, rec.Header())
	e.skipAhead(10 * time.Second)
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
	e.skipAhead(20 * time.Second)
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)

	require.Len(t, tokens, 3)
	assert.Equal(t, tokens[0], tokens[1])
	assert.NotEqual(t, tokens[1], tokens[2])
}

func TestResourceConcurrent(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		opts := []Option{WithResources(billing, orders)}
		if stateful {
			opts = append(opts, WithStore(slowStore{&mapStore{records: make(map[string]store.Record)}}))
		}
		testResourceConcurrent(t, newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, opts...))
	}
}

func testResourceConcurrent(t *testing.T, e *testEnv) {
	e.mountHandler(t, "/dashboard", func(c *fox.Context) {
		var wg sync.WaitGroup
		for _, resource := range []string{billing, orders} {
			wg.Go(func() {
				token, err := ResourceAccessToken(c.Request().Context(), resource)
				if assert.NoError(t, err) {
					got, _ := e.idp.AccessTokenResource(token.AccessToken)
					assert.Equal(t, resource, got)
				}
			})
		}
		wg.Wait()
	})
	cookies := e.loggedIn(t)

	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Go(func() { codes[i] = e.do(http.MethodGet, "/dashboard", cookies, nil).Code })
	}
	wg.Wait()
	for _, code := range codes {
		assert.Equal(t, http.StatusOK, code)
	}
	assert.Equal(t, 2, e.idp.Refreshes())
}

func TestResourceTransportErrors(t *testing.T) {
	t.Run("invalid target", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{InvalidTargets: []string{billing}}, WithResources(billing))
		u := newUpstream(t)
		e.mountResourceProxy(t, "/billing/*{any}", u, billing)
		e.mountProxy(t, "/api/*{any}", u)
		cookies := e.loggedIn(t)

		rec := e.do(http.MethodGet, "/billing/invoices", cookies, nil)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		assert.Empty(t, sessionCookieLines(rec.Header()))
		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api/orders", cookies, nil).Code)
		assert.NotEmpty(t, bearer(t, <-u.requests))
	})

	t.Run("session ended", func(t *testing.T) {
		cases := []struct {
			name string
			opts []Option
			code int
		}{
			{name: "default unauthorized handler", code: http.StatusUnauthorized},
			{name: "custom unauthorized handler", code: http.StatusTeapot, opts: []Option{WithUnauthorizedHandler(func(c *fox.Context) {
				c.Writer().WriteHeader(http.StatusTeapot)
			})}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newTestEnv(t, oidctest.Options{}, append(tc.opts, WithResources(billing))...)
				u := newUpstream(t)
				e.mountResourceProxy(t, "/billing/*{any}", u, billing)
				e.mountResourceProxy(t, "/public/*{any}", u, billing, AllowAnonymous())
				cookies := e.loggedIn(t)
				s, _, err := e.fe.readSession(t.Context(), cookies)
				require.NoError(t, err)
				require.NoError(t, e.fe.revoke(t.Context(), s.RefreshToken))

				rec := e.do(http.MethodGet, "/billing/invoices", cookies, nil)
				assert.Equal(t, tc.code, rec.Code)
				assert.Empty(t, u.requests)
				lines := sessionCookieLines(rec.Header())
				require.Len(t, lines, 1)
				assert.Contains(t, lines[0], "Max-Age=0")

				cookies = e.loggedIn(t)
				s, _, err = e.fe.readSession(t.Context(), cookies)
				require.NoError(t, err)
				require.NoError(t, e.fe.revoke(t.Context(), s.RefreshToken))
				require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/public/catalog", cookies, nil).Code)
				assert.Empty(t, (<-u.requests).Header.Get("Authorization"))
			})
		}
	})

	t.Run("refreshed id token with another issuer", func(t *testing.T) {
		var logs bytes.Buffer
		e := newTestEnv(t, oidctest.Options{RotateRefreshTokens: true}, WithResources(billing), WithLogHandler(slog.NewTextHandler(&logs, nil)))
		u := newUpstream(t)
		e.mountResourceProxy(t, "/billing/*{any}", u, billing)
		cookies := e.loggedIn(t)
		s, _, err := e.fe.readSession(t.Context(), cookies)
		require.NoError(t, err)
		e.idp.Update(func(o *oidctest.Options) { o.Claims = map[string]any{"iss": "https://other.example.com"} })

		assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
		assert.Empty(t, u.requests)
		assert.Contains(t, logs.String(), "refreshed id token")
		revoked := e.idp.Revoked()
		require.Len(t, revoked, 1)
		assert.NotEqual(t, s.RefreshToken, revoked[0])
	})

	t.Run("session store failure", func(t *testing.T) {
		fs := &flakyStore{mapStore: &mapStore{records: make(map[string]store.Record)}}
		e := newTestEnv(t, oidctest.Options{}, WithResources(billing), WithStore(fs))
		u := newUpstream(t)
		e.mountResourceProxy(t, "/billing/*{any}", u, billing)
		cookies := e.loggedIn(t)

		fs.failAfter.Store(1)
		assert.Equal(t, http.StatusInternalServerError, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
		assert.Empty(t, u.requests)
	})

	t.Run("undeclared resource and anonymous", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{}, WithResources(billing))
		u := newUpstream(t)
		e.mountResourceProxy(t, "/orders/*{any}", u, orders)
		e.mountResourceProxy(t, "/public/*{any}", u, billing, AllowAnonymous())
		cookies := e.loggedIn(t)

		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/orders/pending", cookies, nil).Code)
		assert.Empty(t, (<-u.requests).Header.Get("Authorization"))
		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/public/catalog", nil, nil).Code)
		assert.Empty(t, (<-u.requests).Header.Get("Authorization"))
		assert.Zero(t, e.idp.Refreshes())
	})
}

func TestResourceAccessTokenErrors(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithResources(billing))
	errs := make(chan error, 1)
	e.mountHandler(t, "/undeclared", func(c *fox.Context) {
		_, err := ResourceAccessToken(c.Request().Context(), orders)
		errs <- err
	})
	e.mountHandler(t, "/started", func(c *fox.Context) {
		c.Writer().WriteHeader(http.StatusOK)
		_, err := ResourceAccessToken(c.Request().Context(), billing)
		errs <- err
	})
	e.mountHandler(t, "/anonymous", func(c *fox.Context) {
		_, err := ResourceAccessToken(c.Request().Context(), billing)
		errs <- err
	}, AllowAnonymous())
	cookies := e.loggedIn(t)

	_, err := ResourceAccessToken(t.Context(), billing)
	require.ErrorIs(t, err, ErrNoSession)
	e.do(http.MethodGet, "/undeclared", cookies, nil)
	require.ErrorIs(t, <-errs, errUndeclaredResource)
	e.do(http.MethodGet, "/started", cookies, nil)
	require.ErrorIs(t, <-errs, errResponseStarted)
	e.do(http.MethodGet, "/anonymous", nil, nil)
	require.ErrorIs(t, <-errs, ErrNoSession)

	s := testSession()
	s.RefreshToken = ""
	rs := &requestState{fe: e.fe, session: s, request: httptest.NewRequest(http.MethodGet, "/", nil)}
	_, err = ResourceAccessToken(context.WithValue(t.Context(), sessionKey{}, rs), billing)
	assert.ErrorIs(t, err, errNoRefreshToken)
}

func TestResourceTransportDPoP(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithResources(billing), WithDPoP(true))
	u := newUpstream(t)
	e.mountResourceProxy(t, "/billing/*{any}", u, billing)
	cookies := e.loggedIn(t)

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
	req := <-u.requests
	token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "DPoP ")
	require.True(t, ok)
	_, err := oidctest.VerifyDPoPProof(req, token, "")
	assert.NoError(t, err)
	resource, _ := e.idp.AccessTokenResource(token)
	assert.Equal(t, billing, resource)
}

func TestResourceCookieWrittenOnce(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 24 * time.Hour}, WithResources(billing))
	u := newUpstream(t)
	e.mountResourceProxy(t, "/billing/*{any}", u, billing)
	cookies := e.loggedIn(t)
	e.skipAhead(DefaultIdleTimeout/2 + time.Second)

	rec := e.do(http.MethodGet, "/billing/invoices", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	<-u.requests
	names := make(map[string]bool)
	for _, c := range requestCookies(t, rec.Header()) {
		assert.False(t, names[c.Name], c.Name)
		names[c.Name] = true
	}
	s, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
	require.NoError(t, err)
	assert.Contains(t, s.Resources, billing)
}

// flakyStore fails the loads that follow the first failAfter ones.
type flakyStore struct {
	*mapStore
	failAfter atomic.Int32
	loads     atomic.Int32
}

func (s *flakyStore) Load(ctx context.Context, id string) (store.Record, error) {
	if n := s.failAfter.Load(); n > 0 && s.loads.Add(1) > n {
		return store.Record{}, errors.New("store unavailable")
	}
	return s.mapStore.Load(ctx, id)
}

func TestUnauthorized(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithResources(billing), WithUnauthorizedHandler(func(c *fox.Context) {
		c.Writer().WriteHeader(http.StatusTeapot)
	}))
	e.mountHandler(t, "/export", func(c *fox.Context) {
		if _, err := ResourceAccessToken(c.Request().Context(), billing); errors.Is(err, ErrNoSession) {
			e.fe.Unauthorized(c)
		}
	})
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	require.NoError(t, e.fe.revoke(t.Context(), s.RefreshToken))

	assert.Equal(t, http.StatusTeapot, e.do(http.MethodGet, "/export", cookies, nil).Code)
}

func TestProxyErrorHandler(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	rec := httptest.NewRecorder()
	ProxyErrorHandler(rec, httptest.NewRequest(http.MethodGet, "/", nil), errors.New("connection refused"))
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, logs.String(), "connection refused")

	e := newTestEnv(t, oidctest.Options{})
	target, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	proxy := &httputil.ReverseProxy{
		Rewrite:      func(pr *httputil.ProxyRequest) { pr.SetURL(target) },
		Transport:    Transport(nil),
		ErrorHandler: ProxyErrorHandler,
	}
	e.mountHandler(t, "/api/*{any}", fox.WrapH(proxy))
	assert.Equal(t, http.StatusBadGateway, e.do(http.MethodGet, "/api/orders", e.loggedIn(t), nil).Code)
}

// gatingStore blocks its first Update until release is closed.
type gatingStore struct {
	*mapStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatingStore) Update(ctx context.Context, id string, r store.Record) error {
	first := false
	s.once.Do(func() { first = true })
	if first {
		close(s.entered)
		<-s.release
	}
	return s.mapStore.Update(ctx, id, r)
}

func (e *testEnv) mountResourceToken(t *testing.T, pattern, resource string, errs chan error) {
	t.Helper()
	e.mountHandler(t, pattern, func(c *fox.Context) {
		_, err := ResourceAccessToken(c.Request().Context(), resource)
		errs <- err
	})
}

func TestResourceStatefulLostUpdate(t *testing.T) {
	gs := &gatingStore{mapStore: &mapStore{records: make(map[string]store.Record)}, entered: make(chan struct{}), release: make(chan struct{})}
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing, orders), WithStore(gs))
	errs := make(chan error, 4)
	e.mountResourceToken(t, "/r1", billing, errs)
	e.mountResourceToken(t, "/r2", orders, errs)
	cookies := e.loggedIn(t)

	done := make(chan struct{})
	go func() { e.do(http.MethodGet, "/r1", cookies, nil); close(done) }()
	<-gs.entered
	e.do(http.MethodGet, "/r2", cookies, nil)
	close(gs.release)
	<-done
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)

	_, st, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	stored, err := e.fe.loadSession(t.Context(), st.id)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stored.Generation)
	assert.Contains(t, stored.Resources, orders)

	e.skipAhead(2 * time.Minute)
	e.do(http.MethodGet, "/r2", cookies, nil)
	assert.NoError(t, <-errs)
}

// ctxStore fails its writes once the context is canceled, like a store backed by a network client.
type ctxStore struct{ *mapStore }

func (s ctxStore) Update(ctx context.Context, id string, r store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.mapStore.Update(ctx, id, r)
}

// cancelOnRefresh cancels the request that started a refresh token grant once the provider responded.
type cancelOnRefresh struct {
	base   http.RoundTripper
	cancel func()
}

func (c *cancelOnRefresh) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	resp, err := c.base.RoundTrip(r)
	if bytes.Contains(body, []byte("grant_type=refresh_token")) && c.cancel != nil {
		c.cancel()
	}
	return resp, err
}

// cancelOnRefresh makes the next refresh token grant cancel the request that started it, and returns the context of
// that request.
func (e *testEnv) cancelOnRefresh(t *testing.T) context.Context {
	t.Helper()
	client := *e.fe.provider.client
	ct := &cancelOnRefresh{base: client.Transport}
	client.Transport = ct
	e.fe.provider.client = &client
	ctx, cancel := context.WithCancel(t.Context())
	ct.cancel = sync.OnceFunc(func() {
		cancel()
		ct.cancel = nil
	})
	return ctx
}

func (e *testEnv) doContext(ctx context.Context, target string, cookies []*http.Cookie) {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, appOrigin+target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	e.router.ServeHTTP(httptest.NewRecorder(), req)
}

func TestResourceCanceledRequest(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing), WithStore(ctxStore{&mapStore{records: make(map[string]store.Record)}}))
	errs := make(chan error, 2)
	e.mountResourceToken(t, "/r1", billing, errs)
	cookies := e.loggedIn(t)

	e.doContext(e.cancelOnRefresh(t), "/r1", cookies)
	require.NoError(t, <-errs)

	e.skipAhead(2 * time.Minute)
	e.do(http.MethodGet, "/r1", cookies, nil)
	assert.NoError(t, <-errs)
}

func TestResourceBearerUnderDPoP(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing, orders), WithDPoP(true))
	errs := make(chan error, 2)
	e.mountResourceToken(t, "/r1", billing, errs)
	e.mountResourceToken(t, "/r2", orders, errs)
	cookies := e.loggedIn(t)

	e.idp.Update(func(o *oidctest.Options) { o.IgnoreDPoP = true })
	rec := e.do(http.MethodGet, "/r1", cookies, nil)
	require.ErrorIs(t, <-errs, errNotDPoPBound)
	cookies = requestCookies(t, rec.Header())

	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	e.fe.tokens.Forget(s.LogoutCSRFToken)
	e.idp.Update(func(o *oidctest.Options) { o.IgnoreDPoP = false })
	e.do(http.MethodGet, "/r2", cookies, nil)
	assert.NoError(t, <-errs)
}

// failRefresh answers 503 to the refresh token grants once enabled.
type failRefresh struct {
	base http.RoundTripper
	fail atomic.Bool
}

func (f *failRefresh) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if f.fail.Load() && bytes.Contains(body, []byte("grant_type=refresh_token")) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"error":"temporarily_unavailable"}`)),
			Request:    r,
		}, nil
	}
	return f.base.RoundTrip(r)
}

func TestResourceStaleTokenProviderDown(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 10 * time.Minute}, WithResources(billing))
	u := newUpstream(t)
	e.mountResourceProxy(t, "/billing/*{any}", u, billing)
	client := *e.fe.provider.client
	fr := &failRefresh{base: client.Transport}
	client.Transport = fr
	e.fe.provider.client = &client
	cookies := e.loggedIn(t)

	rec := e.do(http.MethodGet, "/billing/invoices", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	token := bearer(t, <-u.requests)
	cookies = requestCookies(t, rec.Header())

	fr.fail.Store(true)
	e.skipAhead(10*time.Minute - 30*time.Second)
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
	assert.Equal(t, token, bearer(t, <-u.requests))

	e.skipAhead(10 * time.Minute)
	assert.Equal(t, http.StatusBadGateway, e.do(http.MethodGet, "/billing/invoices", cookies, nil).Code)
}

// deadlineRefresh records the time left to the refresh token grants.
type deadlineRefresh struct {
	base http.RoundTripper
	left chan time.Duration
}

func (d *deadlineRefresh) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if deadline, ok := r.Context().Deadline(); ok && bytes.Contains(body, []byte("grant_type=refresh_token")) {
		d.left <- time.Until(deadline)
	}
	return d.base.RoundTrip(r)
}

func TestResourceTokenRequestStartsWithLock(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour}, WithResources(billing))
	errs := make(chan error, 1)
	e.mountResourceToken(t, "/r1", billing, errs)
	client := *e.fe.provider.client
	dr := &deadlineRefresh{base: client.Transport, left: make(chan time.Duration, 1)}
	client.Transport = dr
	e.fe.provider.client = &client
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = e.fe.tokens.Do(t.Context(), s.LogoutCSRFToken, func(*session) (*session, error) {
			close(started)
			<-release
			return nil, nil
		})
	}()
	<-started
	done := make(chan struct{})
	go func() { e.do(http.MethodGet, "/r1", cookies, nil); close(done) }()
	time.Sleep(1500 * time.Millisecond)
	close(release)
	<-done
	require.NoError(t, <-errs)
	assert.Greater(t, <-dr.left, refreshTimeout-time.Second)
}

func TestTransportAfterHandler(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour})
	u := newUpstream(t)
	ctxs := make(chan context.Context, 1)
	e.mountHandler(t, "/public", func(c *fox.Context) {
		ctxs <- context.WithoutCancel(c.Request().Context())
	}, AllowAnonymous())
	e.mountHandler(t, "/private", func(*fox.Context) {})

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/public", nil, nil).Code)
	ctx := <-ctxs
	require.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/private", nil, nil).Code)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	require.NoError(t, err)
	resp, err := Transport(nil).RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Empty(t, (<-u.requests).Header.Get("Authorization"))
}

func TestTransportAfterHandlerConcurrent(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour})
	u := newUpstream(t)
	u.requests = make(chan *http.Request, 100)
	var wg sync.WaitGroup
	e.mountHandler(t, "/public", func(c *fox.Context) {
		ctx := context.WithoutCancel(c.Request().Context())
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
			resp, err := Transport(nil).RoundTrip(req)
			if assert.NoError(t, err) {
				_ = resp.Body.Close()
			}
		})
	}, AllowAnonymous())
	e.mountHandler(t, "/private", func(*fox.Context) {})

	var clients sync.WaitGroup
	for range 4 {
		clients.Go(func() {
			for range 20 {
				e.do(http.MethodGet, "/public", nil, nil)
				e.do(http.MethodGet, "/private", nil, nil)
			}
		})
	}
	clients.Wait()
	wg.Wait()
}

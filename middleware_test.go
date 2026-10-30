// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type seen struct {
	state  *requestState
	cookie string
}

func (e *testEnv) mount(t *testing.T, pattern string, opts ...fox.RouteOption) *[]seen {
	t.Helper()
	var (
		mu  sync.Mutex
		got []seen
	)
	h := func(c *fox.Context) {
		st, _ := c.Request().Context().Value(sessionKey{}).(*requestState)
		mu.Lock()
		got = append(got, seen{state: st, cookie: c.Request().Header.Get("Cookie")})
		mu.Unlock()
		c.Writer().WriteHeader(http.StatusOK)
	}
	_, err := e.router.Add(fox.MethodAny, pattern, h, append(opts, fox.WithMiddleware(e.fe.Authenticate()))...)
	require.NoError(t, err)
	return &got
}

func (e *testEnv) do(method, target string, cookies []*http.Cookie, header http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, appOrigin+target, nil)
	maps.Copy(req.Header, header)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) loggedIn(t testing.TB) []*http.Cookie {
	t.Helper()
	rec := e.login(t, "", nil)
	require.Equal(t, http.StatusFound, rec.Code)
	return requestCookies(t, rec.Header())
}

func (e *testEnv) skipAhead(d time.Duration) {
	e.fe.now = func() time.Time { return time.Now().Add(d) }
}

func sessionCookieLines(h http.Header) []string {
	var lines []string
	for _, line := range h.Values("Set-Cookie") {
		if strings.HasPrefix(line, "__Host-bff.") {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestMiddleware(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour})
	got := e.mount(t, "/api")
	cookies := e.loggedIn(t)

	rec := e.do(http.MethodGet, "/api", append(cookies, &http.Cookie{Name: "other", Value: "1"}), nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	require.Len(t, *got, 1)
	require.NotNil(t, (*got)[0].state.session)
	assert.NotEmpty(t, (*got)[0].state.session.AccessToken)
	assert.Equal(t, "other=1", (*got)[0].cookie)

	rec = e.do(http.MethodGet, "/api", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Len(t, *got, 1)
}

func TestMiddlewareAnonymous(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	got := e.mount(t, "/catalog", AllowAnonymous())

	rec := e.do(http.MethodGet, "/catalog", nil, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, *got, 1)
	assert.Nil(t, (*got)[0].state.session)

	rec = e.do(http.MethodGet, "/catalog", e.loggedIn(t), nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, (*got)[1].state.session)
}

func TestMiddlewareCSRF(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithCSRFHeader("X-CSRF", "1"))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)

	cases := []struct {
		name   string
		method string
		header http.Header
		code   int
	}{
		{name: "cross-site post", method: http.MethodPost, header: http.Header{"Sec-Fetch-Site": {"cross-site"}, "X-Csrf": {"1"}}, code: http.StatusForbidden},
		{name: "same-site post", method: http.MethodPost, header: http.Header{"Sec-Fetch-Site": {"same-site"}, "X-Csrf": {"1"}}, code: http.StatusForbidden},
		{name: "foreign origin", method: http.MethodPost, header: http.Header{"Origin": {"https://evil.example.com"}, "X-Csrf": {"1"}}, code: http.StatusForbidden},
		{name: "missing header", method: http.MethodGet, header: http.Header{"Sec-Fetch-Site": {"same-origin"}}, code: http.StatusForbidden},
		{name: "wrong header", method: http.MethodGet, header: http.Header{"X-Csrf": {"0"}}, code: http.StatusForbidden},
		{name: "same-origin post", method: http.MethodPost, header: http.Header{"Sec-Fetch-Site": {"same-origin"}, "X-Csrf": {"1"}}, code: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.code, e.do(tc.method, "/api", cookies, tc.header).Code)
		})
	}
}

func TestMiddlewareInvalidCookie(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	e.mount(t, "/api")
	rec := e.do(http.MethodGet, "/api", []*http.Cookie{{Name: "__Host-bff.0", Value: "garbage"}}, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, []string{"__Host-bff.0=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"}, rec.Header().Values("Set-Cookie"))
}

func TestMiddlewareExpiry(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 24 * time.Hour}, WithStore(ms))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	start := time.Now()

	t.Run("idle timeout slides", func(t *testing.T) {
		e.fe.now = func() time.Time { return start.Add(DefaultIdleTimeout/2 + time.Second) }
		assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
		e.fe.now = func() time.Time { return start.Add(DefaultIdleTimeout + time.Minute) }
		assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
	})

	t.Run("absolute timeout", func(t *testing.T) {
		e.fe.now = func() time.Time { return start.Add(DefaultAbsoluteTimeout) }
		rec := e.do(http.MethodGet, "/api", cookies, nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Len(t, sessionCookieLines(rec.Header()), 1)
		assert.Empty(t, ms.records)
	})
}

func TestMiddlewareRefresh(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		var opts []Option
		if stateful {
			opts = append(opts, WithStore(&mapStore{records: make(map[string]store.Record)}))
		}
		e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second}, opts...)
		got := e.mount(t, "/api")
		cookies := e.loggedIn(t)
		e.skipAhead(20 * time.Second)
		before, _, err := e.fe.readSession(t.Context(), cookies)
		require.NoError(t, err)

		rec := e.do(http.MethodGet, "/api", cookies, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		refreshed := (*got)[0].state.session
		assert.NotEqual(t, before.AccessToken, refreshed.AccessToken)
		assert.GreaterOrEqual(t, refreshed.Expiry, before.Expiry)

		lines := sessionCookieLines(rec.Header())
		if stateful {
			assert.Empty(t, lines)
		} else {
			require.NotEmpty(t, lines)
			cookies = requestCookies(t, rec.Header())
		}
		after, _, err := e.fe.readSession(t.Context(), cookies)
		require.NoError(t, err)
		assert.Equal(t, refreshed.AccessToken, after.AccessToken)
	}
}

func TestMiddlewareRefreshRotation(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		var opts []Option
		if stateful {
			opts = append(opts, WithStore(slowStore{&mapStore{records: make(map[string]store.Record)}}))
		}
		testMiddlewareRefreshRotation(t, newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second, RotateRefreshTokens: true}, opts...))
	}
}

func testMiddlewareRefreshRotation(t *testing.T, e *testEnv) {
	got := e.mount(t, "/api")
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)

	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Go(func() { codes[i] = e.do(http.MethodGet, "/api", cookies, nil).Code })
	}
	wg.Wait()
	for _, code := range codes {
		assert.Equal(t, http.StatusOK, code)
	}
	token := (*got)[0].state.session.AccessToken
	for _, s := range *got {
		assert.Equal(t, token, s.state.session.AccessToken)
	}

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
	assert.Equal(t, token, (*got)[len(*got)-1].state.session.AccessToken)
}

func TestMiddlewareRefreshKeyRotation(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	e.mount(t, "/api")
	cookies := e.loggedIn(t)

	e.idp.RotateKey()
	e.skipAhead(20 * time.Second)
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

func TestMiddlewareRefreshRejected(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	resp, err := e.idp.Client().PostForm(e.idp.URL+"/revoke", url.Values{
		"token":         {s.RefreshToken},
		"client_id":     {"app"},
		"client_secret": {oidctest.ClientSecret},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()

	rec := e.do(http.MethodGet, "/api", cookies, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Len(t, sessionCookieLines(rec.Header()), 1)
}

func TestMiddlewareProviderDown(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)
	e.idp.Close()

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
	e.fe.now = func() time.Time { return time.Now().Add(time.Minute) }
	assert.Equal(t, http.StatusBadGateway, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

func TestMiddlewareResponseCookies(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	_, err := e.router.Add(fox.MethodGet, "/api", func(c *fox.Context) {
		c.Writer().Header().Add("Set-Cookie", "__Host-bff.0=evil; Path=/")
		c.Writer().Header().Add("Set-Cookie", "__Host-bff-login-x.0=evil; Path=/")
		c.Writer().Header().Add("Set-Cookie", "other=1")
		_, _ = c.Writer().WriteString("ok")
	}, fox.WithMiddleware(e.fe.Authenticate()))
	require.NoError(t, err)

	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)
	rec := e.do(http.MethodGet, "/api", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 2)
	assert.Equal(t, "other=1", lines[0])
	assert.True(t, strings.HasPrefix(lines[1], "__Host-bff.0="))
	assert.NotContains(t, lines[1], "evil")
}

func TestRemoveOwnCookies(t *testing.T) {
	h := http.Header{"Cookie": {"a=1; __Host-bff.0=x; b=2", "__Host-bff-login-s.0=y", " c=3 "}}
	removeOwnCookies(h)
	assert.Equal(t, []string{"a=1; b=2", "c=3"}, h["Cookie"])

	h = http.Header{"Cookie": {"__Host-bff.0=x"}}
	removeOwnCookies(h)
	assert.NotContains(t, h, "Cookie")
}

type deletingStore struct {
	*mapStore
	deleteOnLoad   bool
	deleteOnUpdate bool
}

func (s *deletingStore) Load(ctx context.Context, id string) (store.Record, error) {
	r, err := s.mapStore.Load(ctx, id)
	if err == nil && s.deleteOnLoad {
		delete(s.records, id)
	}
	return r, err
}

func (s *deletingStore) Update(ctx context.Context, id string, r store.Record) error {
	if s.deleteOnUpdate {
		delete(s.records, id)
	}
	return s.mapStore.Update(ctx, id, r)
}

func TestMiddlewareSessionEndedDuringRequest(t *testing.T) {
	cases := []struct {
		name           string
		deleteOnLoad   bool
		deleteOnUpdate bool
		refreshes      int
	}{
		{name: "before the refresh", deleteOnLoad: true},
		{name: "after the refresh", deleteOnUpdate: true, refreshes: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := &deletingStore{mapStore: &mapStore{records: make(map[string]store.Record)}}
			e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second}, WithStore(ds))
			got := e.mount(t, "/api")
			cookies := e.loggedIn(t)
			e.skipAhead(20 * time.Second)

			ds.deleteOnLoad, ds.deleteOnUpdate = tc.deleteOnLoad, tc.deleteOnUpdate
			rec := e.do(http.MethodGet, "/api", cookies, nil)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Len(t, sessionCookieLines(rec.Header()), 1)
			assert.Empty(t, ds.records)
			assert.Empty(t, *got)
			assert.Empty(t, e.idp.Revoked())
			assert.Equal(t, tc.refreshes, e.idp.Refreshes())
		})
	}
}

func TestMiddlewareRefreshFailureShared(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second})
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	e.fe.now = func() time.Time { return time.Now().Add(time.Minute) }
	client := *e.fe.provider.client
	fr := &failRefresh{base: client.Transport, release: make(chan struct{})}
	fr.fail.Store(true)
	client.Transport = fr
	e.fe.provider.client = &client

	codes := make(chan int, 3)
	for range 3 {
		go func() { codes <- e.do(http.MethodGet, "/api", cookies, nil).Code }()
	}
	e.waitQueued(t, s.LogoutCSRFToken, 3)
	close(fr.release)
	for range 3 {
		assert.Equal(t, http.StatusBadGateway, <-codes)
	}
	assert.Equal(t, int32(1), fr.calls.Load())
}

func TestMiddlewareRefreshFailureSharedKeepsLatest(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second, RotateRefreshTokens: true}, WithIdleTimeout(70*time.Second))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	e.skipAhead(20 * time.Second)
	e.doContext(e.cancelOnRefresh(t), "/api", cookies)

	e.skipAhead(40 * time.Second)
	client := *e.fe.provider.client
	fr := &failRefresh{base: client.Transport, release: make(chan struct{})}
	fr.fail.Store(true)
	client.Transport = fr
	e.fe.provider.client = &client

	recs := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { recs <- e.do(http.MethodGet, "/api", cookies, nil) }()
	}
	e.waitQueued(t, s.LogoutCSRFToken, 2)
	close(fr.release)

	var tokens []string
	for range 2 {
		rec := <-recs
		assert.Equal(t, http.StatusBadGateway, rec.Code)
		got, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
		require.NoError(t, err)
		tokens = append(tokens, got.RefreshToken)
	}
	assert.NotEqual(t, s.RefreshToken, tokens[0])
	assert.Equal(t, tokens[0], tokens[1])
	assert.Equal(t, int32(1), fr.calls.Load())
}

func TestMiddlewareRefreshRejectedCanceledRequest(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second}, WithStore(ctxStore{ms}))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	resp, err := e.idp.Client().PostForm(e.idp.URL+"/revoke", url.Values{
		"token":         {s.RefreshToken},
		"client_id":     {"app"},
		"client_secret": {oidctest.ClientSecret},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()

	e.doContext(e.cancelOnRefresh(t), "/api", cookies)
	assert.Empty(t, ms.records)
}

func TestMiddlewareRefreshCanceledRequest(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second, RotateRefreshTokens: true}, WithStore(ctxStore{&mapStore{records: make(map[string]store.Record)}}))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)
	e.skipAhead(20 * time.Second)

	e.doContext(e.cancelOnRefresh(t), "/api", cookies)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	e.fe.tokens.Forget(s.LogoutCSRFToken)

	e.skipAhead(50 * time.Second)
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

func TestMiddlewareRefreshBearerUnderDPoP(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 2 * time.Second, RotateRefreshTokens: true}, WithDPoP(true))
	e.mount(t, "/api")
	cookies := e.loggedIn(t)

	e.idp.Update(func(o *oidctest.Options) { o.IgnoreDPoP = true })
	time.Sleep(2 * time.Second)
	rec := e.do(http.MethodGet, "/api", cookies, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	cookies = requestCookies(t, rec.Header())
	require.NotEmpty(t, cookies)

	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	e.fe.tokens.Forget(s.LogoutCSRFToken)
	e.idp.Update(func(o *oidctest.Options) { o.IgnoreDPoP = false })
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/bff/store/memory"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (e *testEnv) mountLogout(t *testing.T) {
	t.Helper()
	_, err := e.router.Add(fox.MethodAny, "/bff/logout", e.fe.LogoutHandler())
	require.NoError(t, err)
}

func TestLogout(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{}, WithStore(ms))
	e.mountLogout(t)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	rec := e.do(http.MethodGet, "/bff/logout?csrf_token="+s.LogoutCSRFToken, cookies, nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Len(t, sessionCookieLines(rec.Header()), 1)
	assert.Empty(t, ms.records)
	assert.Equal(t, []string{s.RefreshToken}, e.idp.Revoked())

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, e.idp.URL+"/end_session", loc.Scheme+"://"+loc.Host+loc.Path)
	assert.Equal(t, url.Values{
		"client_id":                {"app"},
		"id_token_hint":            {s.IDToken},
		"post_logout_redirect_uri": {appOrigin + "/"},
	}, loc.Query())
}

func (e *testEnv) doForm(method, target string, cookies []*http.Cookie, header http.Header, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, appOrigin+target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	maps.Copy(req.Header, header)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func TestLogoutMethods(t *testing.T) {
	sameOrigin := http.Header{"Sec-Fetch-Site": {"same-origin"}}
	crossSite := http.Header{"Sec-Fetch-Site": {"cross-site"}}
	cases := []struct {
		name   string
		method string
		header http.Header
		query  func(token string) string
		form   func(token string) url.Values
		code   int
	}{
		{name: "get with token", method: http.MethodGet, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusSeeOther},
		{name: "get without token", method: http.MethodGet, code: http.StatusBadRequest},
		{name: "get with wrong token", method: http.MethodGet, query: func(string) string { return "csrf_token=x" }, code: http.StatusBadRequest},
		{name: "get with token and malformed query", method: http.MethodGet, query: func(tk string) string { return "csrf_token=" + tk + "&utm=a;b" }, code: http.StatusSeeOther},
		{name: "form post with token", method: http.MethodPost, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusSeeOther},
		{name: "same-origin post with token", method: http.MethodPost, header: sameOrigin, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusSeeOther},
		{name: "post without token", method: http.MethodPost, header: sameOrigin, code: http.StatusBadRequest},
		{name: "post with token in query", method: http.MethodPost, header: sameOrigin, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusSeeOther},
		{name: "post with wrong token in body and token in query", method: http.MethodPost, header: sameOrigin, query: func(tk string) string { return "csrf_token=" + tk }, form: func(string) url.Values { return url.Values{"csrf_token": {"x"}} }, code: http.StatusBadRequest},
		{name: "cross-site post with token in query", method: http.MethodPost, header: crossSite, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusForbidden},
		{name: "post with oversized body", method: http.MethodPost, form: func(tk string) url.Values {
			return url.Values{"csrf_token": {tk}, "pad": {strings.Repeat("a", maxLogoutBody)}}
		}, code: http.StatusBadRequest},
		{name: "cross-site post with token", method: http.MethodPost, header: crossSite, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusForbidden},
		{name: "head with token in query", method: http.MethodHead, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusSeeOther},
		{name: "options with token in query", method: http.MethodOptions, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusSeeOther},
		{name: "cross-site put with token", method: http.MethodPut, header: crossSite, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusForbidden},
		{name: "cross-site patch with token", method: http.MethodPatch, header: crossSite, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{}, WithCSRFHeader("X-CSRF", "1"))
			e.mountLogout(t)
			cookies := e.loggedIn(t)
			s, _, err := e.fe.readSession(t.Context(), cookies)
			require.NoError(t, err)

			target := "/bff/logout"
			if tc.query != nil {
				target += "?" + tc.query(s.LogoutCSRFToken)
			}
			var form url.Values
			if tc.form != nil {
				form = tc.form(s.LogoutCSRFToken)
			}
			rec := e.doForm(tc.method, target, cookies, tc.header, form)
			assert.Equal(t, tc.code, rec.Code)
			if tc.code == http.StatusSeeOther {
				assert.Equal(t, []string{s.RefreshToken}, e.idp.Revoked())
			} else {
				assert.Empty(t, rec.Header().Values("Set-Cookie"))
				assert.Empty(t, e.idp.Revoked())
			}
		})
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	e.mountLogout(t)
	rec := e.do(http.MethodGet, "/bff/logout", nil, nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, appOrigin+"/", rec.Header().Get("Location"))
	assert.Empty(t, e.idp.Revoked())
}

func TestLogoutWithoutProviderEndpoints(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Metadata: map[string]any{"end_session_endpoint": nil, "revocation_endpoint": nil}})
	e.mountLogout(t)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	rec := e.doForm(http.MethodPost, "/bff/logout", cookies, nil, url.Values{"csrf_token": {s.LogoutCSRFToken}})
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, appOrigin+"/", rec.Header().Get("Location"))
	assert.Empty(t, e.idp.Revoked())
}

func TestLogoutWithProviderEndpointOptions(t *testing.T) {
	opts := oidctest.Options{Metadata: map[string]any{"end_session_endpoint": nil, "revocation_endpoint": nil}}
	e := newTestEnvWithClient(t, opts, func(c *Client) {
		issuer := c.Provider.issuer
		p, err := NewProvider(t.Context(), issuer, WithHTTPClient(c.Provider.client),
			WithEndSessionEndpoint(issuer+"/end_session"), WithRevocationEndpoint(issuer+"/revoke"))
		require.NoError(t, err)
		c.Provider = p
	})
	e.mountLogout(t)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	rec := e.doForm(http.MethodPost, "/bff/logout", cookies, nil, url.Values{"csrf_token": {s.LogoutCSRFToken}})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, []string{s.RefreshToken}, e.idp.Revoked())
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, e.idp.URL+"/end_session", loc.Scheme+"://"+loc.Host+loc.Path)
}

type failingStore struct {
	store.Store
	fail bool
}

func (s *failingStore) Load(ctx context.Context, id string) (store.Record, error) {
	if s.fail {
		return store.Record{}, errors.New("store down")
	}
	return s.Store.Load(ctx, id)
}

func TestLogoutStoreError(t *testing.T) {
	fs := &failingStore{Store: memory.NewStore()}
	e := newTestEnv(t, oidctest.Options{}, WithStore(fs))
	e.mountLogout(t)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	fs.fail = true
	rec := e.do(http.MethodGet, "/bff/logout?csrf_token="+s.LogoutCSRFToken, cookies, nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Empty(t, e.idp.EndSessions())
}

func TestLogoutForgetsTokens(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing))
	e.mountLogout(t)
	found := make(chan bool, 2)
	e.mountResourceToken(t, "/r1", billing, found)
	old := e.loggedIn(t)

	rec := e.do(http.MethodGet, "/r1", old, nil)
	require.True(t, <-found)
	latest := requestCookies(t, rec.Header())
	s, _, err := e.fe.readSession(t.Context(), latest)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, e.do(http.MethodGet, "/bff/logout?csrf_token="+s.LogoutCSRFToken, latest, nil).Code)
	refreshes := e.idp.Refreshes()

	assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/r1", old, nil).Code)
	assert.Empty(t, found)
	assert.Equal(t, refreshes, e.idp.Refreshes())
}

func TestLogoutStaleCookie(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing))
	e.mountLogout(t)
	found := make(chan bool, 1)
	e.mountResourceToken(t, "/r1", billing, found)
	old := e.loggedIn(t)

	rec := e.do(http.MethodGet, "/r1", old, nil)
	require.True(t, <-found)
	latest, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
	require.NoError(t, err)

	require.Equal(t, http.StatusSeeOther, e.do(http.MethodGet, "/bff/logout?csrf_token="+latest.LogoutCSRFToken, old, nil).Code)
	assert.Equal(t, []string{latest.RefreshToken}, e.idp.Revoked())
}

// holdRefresh holds the refresh token grants until released.
type holdRefresh struct {
	base    http.RoundTripper
	started chan struct{}
	release chan struct{}
}

func (h *holdRefresh) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if bytes.Contains(body, []byte("grant_type=refresh_token")) {
		h.started <- struct{}{}
		<-h.release
	}
	return h.base.RoundTrip(r)
}

func (e *testEnv) waitQueued(t *testing.T, id string, n int) {
	t.Helper()
	key := sha256.Sum256([]byte(id))
	require.Eventually(t, func() bool {
		e.fe.tokens.mu.Lock()
		defer e.fe.tokens.mu.Unlock()
		st := e.fe.tokens.sessions[key]
		return st != nil && st.refs == n
	}, time.Second, time.Millisecond)
}

func TestLogoutDuringRefresh(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour, RotateRefreshTokens: true}, WithResources(billing))
	e.mountLogout(t)
	found := make(chan bool, 1)
	e.mountResourceToken(t, "/r1", billing, found)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	client := *e.fe.provider.client
	hr := &holdRefresh{base: client.Transport, started: make(chan struct{}), release: make(chan struct{})}
	client.Transport = hr
	e.fe.provider.client = &client
	release := sync.OnceFunc(func() { close(hr.release) })
	t.Cleanup(release)

	refreshed := make(chan *httptest.ResponseRecorder)
	go func() { refreshed <- e.do(http.MethodGet, "/r1", cookies, nil) }()
	<-hr.started
	ctx, cancel := context.WithCancel(t.Context())
	logout := make(chan *httptest.ResponseRecorder)
	go func() {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, appOrigin+"/bff/logout?csrf_token="+s.LogoutCSRFToken, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		logout <- rec
	}()
	e.waitQueued(t, s.LogoutCSRFToken, 2)
	cancel()
	release()

	rec := <-refreshed
	require.True(t, <-found)
	latest, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, (<-logout).Code)
	assert.Equal(t, []string{latest.RefreshToken}, e.idp.Revoked())
}

func TestLogoutStoredByReplica(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{}, WithStore(ms))
	e.mountLogout(t)
	cookies := e.loggedIn(t)
	s, st, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = e.fe.tokens.Do(t.Context(), s.LogoutCSRFToken, func(*session) (*session, error) {
			close(held)
			<-release
			return nil, nil
		})
	}()
	<-held
	logout := make(chan int)
	go func() { logout <- e.do(http.MethodGet, "/bff/logout?csrf_token="+s.LogoutCSRFToken, cookies, nil).Code }()
	e.waitQueued(t, s.LogoutCSRFToken, 2)
	replica := *s
	replica.RefreshToken = "replica"
	replica.Generation++
	require.NoError(t, e.fe.writeSession(t.Context(), http.Header{}, &replica, st))
	close(release)

	assert.Equal(t, http.StatusSeeOther, <-logout)
	assert.Equal(t, []string{"replica"}, e.idp.Revoked())
	assert.Empty(t, ms.records)
}

func TestRevocationRetry(t *testing.T) {
	cases := []struct {
		name       string
		retryAfter string
		failures   int32
		attempts   int32
		revoked    bool
	}{
		{name: "retried after 503", retryAfter: "0", failures: 2, attempts: 3, revoked: true},
		{name: "bounded attempts", retryAfter: "0", failures: 5, attempts: 3},
		{name: "retry after beyond the timeout", retryAfter: "60", failures: 1, attempts: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{})
			client := *e.fe.provider.client
			base := client.Transport
			var attempts atomic.Int32
			client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/revoke" && attempts.Add(1) <= tc.failures {
					return &http.Response{
						StatusCode: http.StatusServiceUnavailable,
						Header:     http.Header{"Retry-After": {tc.retryAfter}},
						Body:       http.NoBody,
						Request:    r,
					}, nil
				}
				return base.RoundTrip(r)
			})
			e.fe.provider.client = &client

			start := time.Now()
			err := e.fe.revoke(t.Context(), "rt")
			assert.Less(t, time.Since(start), time.Second)
			assert.Equal(t, tc.revoked, err == nil)
			assert.Equal(t, tc.attempts, attempts.Load())
		})
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: time.Second},
		{value: "3", want: 3 * time.Second},
		{value: "-1", want: time.Second},
		{value: "9223372037", want: revocationTimeout + time.Second},
		{value: now.Add(5 * time.Second).Format(http.TimeFormat), want: 5 * time.Second},
		{value: now.Add(-5 * time.Second).Format(http.TimeFormat), want: 0},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, retryAfter(tc.value, now))
	}
}

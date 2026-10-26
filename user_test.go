// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (e *testEnv) mountUser(t *testing.T) {
	t.Helper()
	_, err := e.router.Add(fox.MethodGet, "/bff/user", e.fe.UserHandler())
	require.NoError(t, err)
}

func TestUserHandler(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{
		Subject:  "alice",
		SID:      "s1",
		Claims:   map[string]any{"name": "Alice", "auth_time": 1_000_000},
		UserInfo: map[string]any{"email": "alice@example.com", "name": "Alice Liddell"},
	}, WithUserInfo(true))
	e.mountUser(t)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	rec := e.do(http.MethodGet, "/bff/user", cookies, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var body struct {
		Claims          map[string]any `json:"claims"`
		LogoutCSRFToken string         `json:"logoutCsrfToken"`
		ExpiresIn       int64          `json:"expiresIn"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, map[string]any{
		"sub":       "alice",
		"name":      "Alice Liddell",
		"email":     "alice@example.com",
		"auth_time": float64(1_000_000),
	}, body.Claims)
	assert.Equal(t, s.LogoutCSRFToken, body.LogoutCSRFToken)
	assert.InDelta(t, DefaultIdleTimeout.Seconds(), body.ExpiresIn, 5)
}

func TestUserHandlerUnauthorized(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	e.mountUser(t)
	rec := e.do(http.MethodGet, "/bff/user", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	cookies := e.loggedIn(t)
	e.fe.now = func() time.Time { return time.Now().Add(DefaultAbsoluteTimeout) }
	rec = e.do(http.MethodGet, "/bff/user", cookies, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Len(t, sessionCookieLines(rec.Header()), 1)
}

func TestUserHandlerCSRF(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithCSRFHeader("X-CSRF", "1"))
	e.mountUser(t)
	cookies := e.loggedIn(t)
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodGet, "/bff/user", cookies, nil).Code)
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/bff/user", cookies, http.Header{"X-Csrf": {"1"}}).Code)
}

func BenchmarkUserHandler(b *testing.B) {
	fe := &Frontend{cfg: defaultConfig(), aead: newGCMAEAD(b), now: time.Now, cop: http.NewCrossOriginProtection()}
	idp := oidctest.NewServer(oidctest.Options{})
	b.Cleanup(idp.Close)
	s := newSession(time.Now())
	s.IDToken = idp.Sign("JWT", map[string]any{
		"iss": "https://idp.example.com", "aud": "app", "sub": "alice", "name": "Alice", "email": "alice@example.com",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": "n",
	})
	s.AccessToken = "access-token"
	h := make(http.Header)
	require.NoError(b, fe.writeSession(b.Context(), h, s, sessionState{}))
	cookies := requestCookies(b, h)

	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/bff/user", fe.UserHandler())
	req, err := http.NewRequest(http.MethodGet, appOrigin+"/bff/user", nil)
	require.NoError(b, err)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	b.ReportAllocs()
	for b.Loop() {
		w := new(discardWriter)
		f.ServeHTTP(w, req)
	}
}

type discardWriter struct {
	h http.Header
}

func (w *discardWriter) Header() http.Header {
	if w.h == nil {
		w.h = make(http.Header)
	}
	return w.h
}
func (w *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *discardWriter) WriteHeader(int)             {}

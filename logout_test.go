// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
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
	for k, v := range header {
		req.Header[k] = v
	}
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
		{name: "form post with token", method: http.MethodPost, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusSeeOther},
		{name: "same-origin post with token", method: http.MethodPost, header: sameOrigin, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusSeeOther},
		{name: "post without token", method: http.MethodPost, header: sameOrigin, code: http.StatusBadRequest},
		{name: "post with token in query", method: http.MethodPost, header: sameOrigin, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusBadRequest},
		{name: "post with oversized body", method: http.MethodPost, form: func(tk string) url.Values {
			return url.Values{"csrf_token": {tk}, "pad": {strings.Repeat("a", maxLogoutBody)}}
		}, code: http.StatusBadRequest},
		{name: "cross-site post with token", method: http.MethodPost, header: crossSite, form: func(tk string) url.Values { return url.Values{"csrf_token": {tk}} }, code: http.StatusForbidden},
		{name: "head", method: http.MethodHead, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusMethodNotAllowed},
		{name: "options", method: http.MethodOptions, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusMethodNotAllowed},
		{name: "put", method: http.MethodPut, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusMethodNotAllowed},
		{name: "delete", method: http.MethodDelete, query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusMethodNotAllowed},
		{name: "query", method: "QUERY", query: func(tk string) string { return "csrf_token=" + tk }, code: http.StatusMethodNotAllowed},
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
			if tc.code == http.StatusMethodNotAllowed {
				assert.Equal(t, "GET, POST", rec.Header().Get("Allow"))
			}
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

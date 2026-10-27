// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const appOrigin = "https://app.example.com"

type testEnv struct {
	idp    *oidctest.Server
	fe     *Frontend
	router *fox.Router
}

func newTestEnv(t testing.TB, opts oidctest.Options, feOpts ...Option) *testEnv {
	t.Helper()
	return newTestEnvWithClient(t, opts, func(*Client) {}, feOpts...)
}

func newTestEnvWithClient(t testing.TB, opts oidctest.Options, client func(*Client), feOpts ...Option) *testEnv {
	t.Helper()
	if opts.Subject == "" {
		opts.Subject = "alice"
	}
	idp := oidctest.NewServer(opts)
	t.Cleanup(idp.Close)
	p, err := NewProvider(t.Context(), idp.URL, WithHTTPClient(idp.Client()))
	require.NoError(t, err)
	c := Client{
		Provider:              p,
		ClientID:              "app",
		ClientSecret:          oidctest.ClientSecret,
		RedirectURL:           appOrigin + "/bff/callback",
		PostLogoutRedirectURL: appOrigin + "/",
		Scopes:                []string{"openid"},
	}
	client(&c)
	fe, err := NewFrontend(c, newGCMAEAD(t), feOpts...)
	require.NoError(t, err)

	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/bff/login", fe.LoginHandler())
	f.MustAdd(fox.MethodGet, "/bff/callback", fe.CallbackHandler())
	return &testEnv{idp: idp, fe: fe, router: f}
}

func (e *testEnv) serve(target string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, appOrigin+target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) startLogin(t testing.TB, query string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := e.serve("/bff/login?"+query, nil)
	require.Equal(t, http.StatusFound, rec.Code)

	hc := e.idp.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(rec.Header().Get("Location"))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, appOrigin+"/bff/callback", callback.Scheme+"://"+callback.Host+callback.Path)
	return rec, callback.RequestURI()
}

func (e *testEnv) login(t testing.TB, query string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec, callback := e.startLogin(t, query)
	return e.serve(callback, append(cookies, requestCookies(t, rec.Header())...))
}

func TestLogin(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Subject: "alice", SID: "s1"})
	rec, _ := e.startLogin(t, "returnUrl=/orders?id=1")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	authorize, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	q := authorize.Query()
	assert.Equal(t, "app", q.Get("client_id"))
	assert.Equal(t, appOrigin+"/bff/callback", q.Get("redirect_uri"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("nonce"))
	assert.Empty(t, q.Get("prompt"))

	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "__Host-bff-login-"+q.Get("state")+".0="))
	assert.Contains(t, lines[0], "Max-Age=900; HttpOnly; Secure; SameSite=Lax")
}

func TestLoginPushedAuthorization(t *testing.T) {
	cases := []struct {
		name   string
		opts   oidctest.Options
		mode   PushedAuthorization
		pushed bool
	}{
		{name: "if available", opts: oidctest.Options{PAR: true}, mode: PushedAuthorizationIfAvailable, pushed: true},
		{name: "required by provider", opts: oidctest.Options{PAR: true, Metadata: map[string]any{"require_pushed_authorization_requests": true}}, pushed: true},
		{name: "required", opts: oidctest.Options{PAR: true}, mode: PushedAuthorizationRequired, pushed: true},
		{name: "disabled", opts: oidctest.Options{PAR: true}, mode: PushedAuthorizationDisabled},
		{name: "not available", mode: PushedAuthorizationIfAvailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, tc.opts, WithPushedAuthorization(tc.mode))
			rec, callback := e.startLogin(t, "prompt=login&returnUrl=/orders")
			authorize, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			q := authorize.Query()
			if tc.pushed {
				assert.Len(t, q, 2)
				assert.Equal(t, "app", q.Get("client_id"))
				assert.True(t, strings.HasPrefix(q.Get("request_uri"), "urn:ietf:params:oauth:request_uri:"))
			} else {
				assert.Empty(t, q.Get("request_uri"))
				assert.Equal(t, "login", q.Get("prompt"))
			}

			res := e.serve(callback, requestCookies(t, rec.Header()))
			require.Equal(t, http.StatusFound, res.Code)
			assert.Equal(t, "/orders", res.Header().Get("Location"))
		})
	}
}

func TestLoginPushedAuthorizationFailure(t *testing.T) {
	cases := []struct {
		name   string
		update func(e *testEnv)
	}{
		{name: "not found", update: func(e *testEnv) { e.fe.parEndpoint = e.idp.URL + "/missing" }},
		{name: "invalid client", update: func(e *testEnv) { e.fe.auth.secret = "other" }},
		{name: "unreachable", update: func(e *testEnv) { e.idp.Close() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{PAR: true})
			tc.update(e)
			rec := e.serve("/bff/login", nil)
			assert.Equal(t, http.StatusBadGateway, rec.Code)
			assert.Empty(t, rec.Header().Values("Set-Cookie"))
		})
	}
}

func TestLoginCrossOrigin(t *testing.T) {
	cases := []struct {
		site    string
		allow   bool
		started bool
	}{
		{site: "", started: true},
		{site: "same-origin", started: true},
		{site: "none", started: true},
		{site: "same-site"},
		{site: "cross-site"},
		{site: "cross-site", allow: true, started: true},
	}
	for _, tc := range cases {
		t.Run(tc.site+" "+strconv.FormatBool(tc.allow), func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{}, WithCrossOriginLogin(tc.allow))
			req := httptest.NewRequest(http.MethodGet, appOrigin+"/bff/login?returnUrl=/orders", nil)
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			rec := httptest.NewRecorder()
			e.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusFound, rec.Code)
			if tc.started {
				assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), e.idp.URL))
				assert.Len(t, rec.Header().Values("Set-Cookie"), 1)
			} else {
				assert.Equal(t, "/orders", rec.Header().Get("Location"))
				assert.Empty(t, rec.Header().Values("Set-Cookie"))
			}
		})
	}
}

func TestCallback(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		var opts []Option
		if stateful {
			opts = append(opts, WithStore(&mapStore{records: make(map[string]store.Record)}))
		}
		e := newTestEnv(t, oidctest.Options{Subject: "alice", SID: "s1"}, opts...)

		rec := e.login(t, "returnUrl=/orders?id=1", nil)
		require.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/orders?id=1", rec.Header().Get("Location"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Contains(t, rec.Header().Values("Set-Cookie")[0], "Max-Age=0; HttpOnly; Secure; SameSite=Lax")

		s, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
		require.NoError(t, err)
		assert.Equal(t, "alice", s.Subject)
		assert.Equal(t, "s1", s.SID)
		assert.NotEmpty(t, s.IDToken)
		assert.NotEmpty(t, s.AccessToken)
		assert.NotEmpty(t, s.RefreshToken)
		assert.Equal(t, "Bearer", s.TokenType)
		assert.Positive(t, s.Expiry)
		assert.NotEmpty(t, s.LogoutCSRFToken)
	}
}

func TestCallbackDefaultReturnURL(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	rec := e.login(t, "", nil)
	assert.Equal(t, "/", rec.Header().Get("Location"))
}

func TestCallbackReplacesSession(t *testing.T) {
	ms := &mapStore{records: make(map[string]store.Record)}
	e := newTestEnv(t, oidctest.Options{}, WithStore(ms))

	first := requestCookies(t, e.login(t, "", nil).Header())
	require.Len(t, ms.records, 1)
	second := e.login(t, "", first)
	require.Equal(t, http.StatusFound, second.Code)
	assert.Len(t, ms.records, 1)

	_, _, err := e.fe.readSession(t.Context(), first)
	assert.ErrorIs(t, err, ErrNoSession)
	_, _, err = e.fe.readSession(t.Context(), requestCookies(t, second.Header()))
	assert.NoError(t, err)
}

func TestSilentLogin(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{LoggedOut: true})
	rec, callback := e.startLogin(t, "prompt=none&returnUrl=/home")
	authorize, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "none", authorize.Query().Get("prompt"))

	res := e.serve(callback, requestCookies(t, rec.Header()))
	assert.Equal(t, http.StatusFound, res.Code)
	assert.Equal(t, "/home", res.Header().Get("Location"))
	lines := res.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "__Host-bff-login-")
}

func TestLoginInvalid(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Metadata: map[string]any{"prompt_values_supported": []string{"none", "login"}}})
	for _, query := range []string{
		"returnUrl=https://evil.example.com",
		"returnUrl=//evil.example.com",
		"returnUrl=/%5Cevil.example.com",
		"returnUrl=/a%5Cb",
		"returnUrl=evil",
		"returnUrl=/a%01b",
		"prompt=consent",
		"prompt=none%20login",
		"prompt=%20",
	} {
		t.Run(query, func(t *testing.T) {
			rec := e.serve("/bff/login?"+query, nil)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Empty(t, rec.Header().Values("Set-Cookie"))
		})
	}
}

func TestCallbackInvalid(t *testing.T) {
	t.Run("no login cookie", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{})
		_, callback := e.startLogin(t, "")
		assert.Equal(t, http.StatusBadRequest, e.serve(callback, nil).Code)
	})

	t.Run("other login cookie", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{})
		rec, _ := e.startLogin(t, "")
		_, callback := e.startLogin(t, "")
		assert.Equal(t, http.StatusBadRequest, e.serve(callback, requestCookies(t, rec.Header())).Code)
	})

	t.Run("expired login", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{})
		rec, callback := e.startLogin(t, "")
		e.fe.now = func() time.Time { return time.Now().Add(loginTimeout + time.Minute) }
		res := e.serve(callback, requestCookies(t, rec.Header()))
		assert.Equal(t, http.StatusBadRequest, res.Code)
		assert.Contains(t, res.Header().Get("Set-Cookie"), "Max-Age=0")
	})

	cases := []struct {
		name string
		opts oidctest.Options
	}{
		{name: "iss mismatch", opts: oidctest.Options{
			ISS:      "https://evil.example.com",
			Metadata: map[string]any{"authorization_response_iss_parameter_supported": true},
		}},
		{name: "nonce mismatch", opts: oidctest.Options{Claims: map[string]any{"nonce": "other"}}},
		{name: "audience mismatch", opts: oidctest.Options{Claims: map[string]any{"aud": "other"}}},
		{name: "expired id token", opts: oidctest.Options{Claims: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}}},
		{name: "azp mismatch", opts: oidctest.Options{Claims: map[string]any{"azp": "other"}}},
		{name: "several audiences and azp mismatch", opts: oidctest.Options{Claims: map[string]any{"aud": []string{"app", "other"}, "azp": "other"}}},
		{name: "missing sub", opts: oidctest.Options{Claims: map[string]any{"sub": nil}}},
		{name: "missing iat", opts: oidctest.Options{Claims: map[string]any{"iat": nil}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, tc.opts)
			res := e.login(t, "", nil)
			assert.Equal(t, http.StatusBadRequest, res.Code)
			lines := res.Header().Values("Set-Cookie")
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0], "__Host-bff-login-")
		})
	}

	t.Run("missing iss", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{})
		e.fe.provider.issParameter = true
		assert.Equal(t, http.StatusBadRequest, e.login(t, "", nil).Code)
	})

	t.Run("code replay", func(t *testing.T) {
		e := newTestEnv(t, oidctest.Options{})
		rec, callback := e.startLogin(t, "")
		cookies := requestCookies(t, rec.Header())
		require.Equal(t, http.StatusFound, e.serve(callback, cookies).Code)
		assert.Equal(t, http.StatusBadRequest, e.serve(callback, cookies).Code)
	})
}

func TestCallbackUserInfo(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{UserInfo: map[string]any{"email": "alice@example.com"}}, WithUserInfo(true))
	rec := e.login(t, "", nil)
	require.Equal(t, http.StatusFound, rec.Code)
	s, _, err := e.fe.readSession(t.Context(), requestCookies(t, rec.Header()))
	require.NoError(t, err)
	var info map[string]any
	require.NoError(t, json.Unmarshal(s.UserInfo, &info))
	assert.Equal(t, "alice@example.com", info["email"])

	e.idp.Update(func(o *oidctest.Options) { o.UserInfo = map[string]any{"sub": "mallory"} })
	assert.Equal(t, http.StatusBadRequest, e.login(t, "", nil).Code)
}

func FuzzLocalURL(f *testing.F) {
	for _, seed := range []string{"/", "/orders?id=1", "//evil.example.com", "/\\evil.example.com", "https://evil.example.com", "/a\tb"} {
		f.Add(seed)
	}
	base, err := url.Parse("https://app.example.com/a/b")
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, u string) {
		if !localURL(u) {
			return
		}
		ref, err := url.Parse(u)
		require.NoError(t, err)
		resolved := base.ResolveReference(ref)
		assert.Equal(t, "https", resolved.Scheme)
		assert.Equal(t, "app.example.com", resolved.Host)
		assert.False(t, strings.ContainsAny(u, "\\\t\r\n"))
	})
}

func TestCallbackReloginWithStaleChunks(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{Claims: map[string]any{"pad": strings.Repeat("a", 2*maxChunkSize)}})
	old := e.loggedIn(t)
	require.Greater(t, len(old), 1)

	e.idp.Update(func(o *oidctest.Options) { o.Claims = nil })
	rec := e.login(t, "", nil)
	require.Equal(t, http.StatusFound, rec.Code)
	fresh := requestCookies(t, rec.Header())
	require.Len(t, sessionCookieLines(rec.Header()), 1)

	jar := append(fresh, old[1:]...)
	s, st, err := e.fe.readSession(t.Context(), jar)
	require.NoError(t, err)
	assert.Equal(t, "alice", s.Subject)
	assert.Equal(t, len(old), st.chunks)
}

func TestCallbackDeletesSessionsOfSameSID(t *testing.T) {
	cases := []struct {
		name    string
		sid     string
		records int
	}{
		{name: "same sid", sid: "s1", records: 1},
		{name: "no sid", sid: "", records: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := &mapStore{records: make(map[string]store.Record)}
			e := newTestEnv(t, oidctest.Options{SID: tc.sid}, WithStore(ms))
			e.loggedIn(t)
			require.Equal(t, http.StatusFound, e.login(t, "", nil).Code)

			assert.Len(t, ms.records, tc.records)
			assert.Empty(t, e.idp.Revoked())
		})
	}
}

func TestCallbackSigningAlgorithms(t *testing.T) {
	metadata := map[string]any{"id_token_signing_alg_values_supported": []string{"RS256", "PS256"}}
	for alg, code := range map[string]int{"RS256": http.StatusFound, "PS256": http.StatusBadRequest} {
		t.Run(alg, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{Metadata: metadata}, WithSigningAlgorithms(alg))
			assert.Equal(t, code, e.login(t, "", nil).Code)
		})
	}
}

func TestCallbackDecoyKeys(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{DecoyKeys: true})
	assert.Equal(t, http.StatusFound, e.login(t, "", nil).Code)
}

func TestCallbackSeveralAudiences(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{name: "with azp", claims: map[string]any{"aud": []string{"app", "other"}, "azp": "app"}},
		{name: "without azp", claims: map[string]any{"aud": []string{"app", "other"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, oidctest.Options{Claims: tc.claims})
			assert.Equal(t, http.StatusFound, e.login(t, "", nil).Code)
		})
	}
}

func TestLoginPendingLimit(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	start := time.Now()
	var cookies []*http.Cookie
	var callbacks []string
	for i := range maxPendingLogins + 1 {
		e.fe.now = func() time.Time { return start.Add(time.Duration(i) * time.Second) }
		rec := e.serve("/bff/login", cookies)
		require.Equal(t, http.StatusFound, rec.Code)
		cookies = applySetCookies(t, cookies, rec.Header())
		hc := e.idp.Client()
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := hc.Get(rec.Header().Get("Location"))
		require.NoError(t, err)
		_ = resp.Body.Close()
		callback, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		callbacks = append(callbacks, callback.RequestURI())
	}
	assert.Len(t, cookies, maxPendingLogins)

	assert.Equal(t, http.StatusBadRequest, e.serve(callbacks[0], cookies).Code)
	assert.Equal(t, http.StatusFound, e.serve(callbacks[len(callbacks)-1], cookies).Code)
}

func applySetCookies(t *testing.T, cookies []*http.Cookie, h http.Header) []*http.Cookie {
	t.Helper()
	jar := make(map[string]string)
	var order []string
	for _, c := range cookies {
		jar[c.Name] = c.Value
		order = append(order, c.Name)
	}
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		if _, ok := jar[c.Name]; !ok {
			order = append(order, c.Name)
		}
		if c.MaxAge < 0 {
			delete(jar, c.Name)
			continue
		}
		jar[c.Name] = c.Value
	}
	var out []*http.Cookie
	for _, name := range order {
		if v, ok := jar[name]; ok {
			out = append(out, &http.Cookie{Name: name, Value: v})
			delete(jar, name)
		}
	}
	return out
}

func TestLoginResources(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{}, WithResources(billing, orders))
	rec, _ := e.startLogin(t, "")
	authorize, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, []string{billing, orders}, authorize.Query()["resource"])
}

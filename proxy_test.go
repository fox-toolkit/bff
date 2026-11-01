// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fox-toolkit/fox"
	"github.com/fox-toolkit/rp/internal/oidctest"
	"github.com/fox-toolkit/rp/store/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var navigate = http.Header{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}}

type proxyEnv struct {
	idp        *oidctest.Server
	p          *Proxy
	router     *fox.Router
	mu         sync.Mutex
	last       http.Header
	identified bool
}

func newProxyEnv(t testing.TB, opts oidctest.Options, proxyOpts ...ProxyOption) *proxyEnv {
	t.Helper()
	if opts.Subject == "" {
		opts.Subject = "alice"
	}
	idp := oidctest.NewServer(opts)
	t.Cleanup(idp.Close)
	p, err := NewProxy(proxyClient(t, idp), newGCMAEAD(t), proxyOpts...)
	require.NoError(t, err)

	e := &proxyEnv{idp: idp, p: p, router: fox.MustRouter()}
	e.router.MustAdd(fox.MethodGet, "/oauth2/callback", p.CallbackHandler())
	e.router.MustAdd(fox.MethodAny, "/oauth2/logout", p.LogoutHandler())
	e.mount(t, "/app/*{any}")
	return e
}

func proxyClient(t testing.TB, idp *oidctest.Server) Client {
	t.Helper()
	provider, err := NewProvider(t.Context(), idp.URL, WithHTTPClient(idp.Client()))
	require.NoError(t, err)
	return Client{
		Provider:              provider,
		ClientID:              "app",
		ClientSecret:          oidctest.ClientSecret,
		RedirectURL:           appOrigin + "/oauth2/callback",
		PostLogoutRedirectURL: appOrigin + "/",
		Scopes:                []string{"openid"},
	}
}

func (e *proxyEnv) mount(t testing.TB, pattern string, opts ...fox.RouteOption) {
	t.Helper()
	h := func(c *fox.Context) {
		_, identified := UserClaims(c.Request().Context())
		e.mu.Lock()
		e.last = c.Request().Header.Clone()
		e.identified = identified
		e.mu.Unlock()
		c.Writer().WriteHeader(http.StatusOK)
	}
	_, err := e.router.Add(fox.MethodAny, pattern, h, append(opts, fox.WithMiddleware(e.p.Authenticate()))...)
	require.NoError(t, err)
}

func (e *proxyEnv) do(method, target string, cookies []*http.Cookie, header http.Header) *httptest.ResponseRecorder {
	e.mu.Lock()
	e.last, e.identified = nil, false
	e.mu.Unlock()
	if !strings.HasPrefix(target, "https://") {
		target = appOrigin + target
	}
	req := httptest.NewRequest(method, target, nil)
	maps.Copy(req.Header, header)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *proxyEnv) upstream() http.Header {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

func (e *proxyEnv) login(t testing.TB, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := e.do(http.MethodGet, target, nil, navigate)
	require.Equal(t, http.StatusFound, rec.Code)
	hc := e.idp.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Get(rec.Header().Get("Location"))
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return e.do(http.MethodGet, callback.RequestURI(), requestCookies(t, rec.Header()), nil)
}

func (e *proxyEnv) loggedIn(t testing.TB) []*http.Cookie {
	t.Helper()
	rec := e.login(t, "/app/")
	require.Equal(t, http.StatusFound, rec.Code)
	return requestCookies(t, rec.Header())
}

func TestProxyLogin(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	rec := e.do(http.MethodGet, "/app/orders?id=1", nil, navigate)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), e.idp.URL))
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "__Host-Http-Proxy-Login-"))
	assert.Contains(t, lines[0], "SameSite=Lax")

	rec = e.login(t, "/app/orders?id=1")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/app/orders?id=1", rec.Header().Get("Location"))
	var session []string
	for _, line := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(line, "__Host-Http-Proxy.") {
			session = append(session, line)
		}
	}
	require.Len(t, session, 1)
	assert.Contains(t, session[0], "HttpOnly; Secure; SameSite=Lax")

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/orders", requestCookies(t, rec.Header()), nil).Code)
}

func TestProxyLoginReturnURL(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	rec := e.login(t, "/app/"+strings.Repeat("a", maxReturnURL))
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/", rec.Header().Get("Location"))
}

func TestProxyLoginReturnURLOtherHost(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	e.mount(t, "/*{any}")
	rec := e.login(t, "//evil.example.com/")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "/", rec.Header().Get("Location"))
}

func TestProxyRefreshedCookie(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{"groups": []any{"dev"}}})
	e.mount(t, "/admin", Require(Group("admin")))
	e.mount(t, "/public", AllowAnonymous(), Require(Group("admin")))
	cookies := e.loggedIn(t)
	e.p.rp.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	for _, tc := range []struct {
		method, target string
		header         http.Header
		want           int
	}{
		{method: http.MethodPost, target: "/app/", header: http.Header{"Sec-Fetch-Site": {"cross-site"}}, want: http.StatusForbidden},
		{method: http.MethodGet, target: "/admin", want: http.StatusForbidden},
		{method: http.MethodGet, target: "/public", want: http.StatusOK},
	} {
		rec := e.do(tc.method, tc.target, cookies, tc.header)
		assert.Equal(t, tc.want, rec.Code)
		assert.True(t, hasLine(rec.Header().Values("Set-Cookie"), "__Host-Http-Proxy.0="))
	}
}

func TestProxyCallbackProviderError(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	rec := e.do(http.MethodGet, "/app/", nil, navigate)
	require.Equal(t, http.StatusFound, rec.Code)
	authorize, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	q := url.Values{"state": {authorize.Query().Get("state")}, "error": {"access_denied"}, "iss": {e.p.rp.provider.issuer}}
	rec = e.do(http.MethodGet, "/oauth2/callback?"+q.Encode(), requestCookies(t, rec.Header()), nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, hasLine(rec.Header().Values("Set-Cookie"), "__Host-Http-Proxy.0="))
}

func TestProxyUnauthorized(t *testing.T) {
	cases := []struct {
		name   string
		method string
		header http.Header
	}{
		{name: "no fetch metadata", method: http.MethodGet},
		{name: "fetch", method: http.MethodGet, header: http.Header{"Sec-Fetch-Mode": {"cors"}}},
		{name: "form post", method: http.MethodPost, header: navigate},
		{name: "iframe", method: http.MethodGet, header: http.Header{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"iframe"}}},
	}
	e := newProxyEnv(t, oidctest.Options{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.do(tc.method, "/app/", nil, tc.header)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Empty(t, rec.Header().Values("Set-Cookie"))
		})
	}
}

func TestProxyInvalidSessionCleared(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	cookies := []*http.Cookie{{Name: "__Host-Http-Proxy.0", Value: "1.x"}}
	for _, header := range []http.Header{nil, navigate} {
		rec := e.do(http.MethodGet, "/app/", cookies, header)
		assert.True(t, hasLine(rec.Header().Values("Set-Cookie"), "__Host-Http-Proxy.0=; Path=/; Max-Age=0"))
	}
}

func TestProxyUnauthorizedHandler(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{}, WithUnauthorizedHandler(func(c *fox.Context) {
		c.Writer().WriteHeader(http.StatusTeapot)
	}))
	assert.Equal(t, http.StatusTeapot, e.do(http.MethodGet, "/app/", nil, nil).Code)
	assert.Equal(t, http.StatusFound, e.do(http.MethodGet, "/app/", nil, navigate).Code)
}

func TestProxyCrossOrigin(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	e.mount(t, "/public", AllowAnonymous())
	cookies := e.loggedIn(t)
	crossSite := http.Header{"Sec-Fetch-Site": {"cross-site"}}
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodPost, "/app/", cookies, crossSite).Code)
	assert.Equal(t, http.StatusOK, e.do(http.MethodPost, "/app/", cookies, http.Header{"Sec-Fetch-Site": {"same-origin"}}).Code)
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, crossSite).Code)
	assert.Equal(t, http.StatusOK, e.do(http.MethodPost, "/public", nil, crossSite).Code)
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodPost, "/public", cookies, crossSite).Code)
}

func TestProxyIdentityHeaders(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{
		"email":   "alice@example.com",
		"groups":  []any{"dev", "ops"},
		"address": map[string]any{"country": "CH"},
		"roles":   []any{"a", 1},
		"age":     42,
		"ratio":   4.2,
		"admin":   true,
		"bio":     "a\nb",
	}},
		WithIdentityHeader("X-Auth-Request-Email", "email"),
		WithIdentityHeader("X-Auth-Request-Groups", "groups"),
		WithIdentityHeader("X-Auth-Request-Address", "address"),
		WithIdentityHeader("X-Auth-Request-Roles", "roles"),
		WithIdentityHeader("X-Auth-Request-Name", "name"),
		WithIdentityHeader("X-Auth-Request-Age", "age"),
		WithIdentityHeader("X-Auth-Request-Ratio", "ratio"),
		WithIdentityHeader("X-Auth-Request-Admin", "admin"),
		WithIdentityHeader("X-Auth-Request-Bio", "bio"),
	)
	e.mount(t, "/public", AllowAnonymous())
	cookies := e.loggedIn(t)
	forged := http.Header{
		"X-Auth-Request-Email":   {"admin@example.com"},
		"X_auth_request_email":   {"admin@example.com"},
		"X-Auth_request-Groups":  {"admin"},
		"X-Auth-Request-Address": {"forged"},
		"X-Auth-Request-Name":    {"Admin"},
		"X-Other":                {"kept"},
	}

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, forged).Code)
	assert.Equal(t, http.Header{
		"X-Auth-Request-Email":  {"alice@example.com"},
		"X-Auth-Request-Groups": {"dev,ops"},
		"X-Auth-Request-Age":    {"42"},
		"X-Auth-Request-Ratio":  {"4.2"},
		"X-Auth-Request-Admin":  {"true"},
		"X-Other":               {"kept"},
	}, withoutCookie(e.upstream()))

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/public", nil, forged).Code)
	assert.Equal(t, http.Header{"X-Other": {"kept"}}, withoutCookie(e.upstream()))
}

func withoutCookie(h http.Header) http.Header {
	h = h.Clone()
	delete(h, "Cookie")
	return h
}

func TestProxyAccessRule(t *testing.T) {
	t.Run("denied at login", func(t *testing.T) {
		e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{"email": "alice@example.com", "email_verified": false}},
			WithAccessRule(EmailDomain("example.com")))
		rec := e.login(t, "/app/")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		for _, line := range rec.Header().Values("Set-Cookie") {
			assert.False(t, strings.HasPrefix(line, "__Host-Http-Proxy."))
		}
		assert.Empty(t, e.idp.Revoked())
	})
	t.Run("granted", func(t *testing.T) {
		e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{"email": "alice@example.com", "email_verified": true}},
			WithAccessRule(EmailDomain("example.com")))
		cookies := e.loggedIn(t)
		assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, nil).Code)
	})
}

func TestProxyRequire(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{"groups": []any{"dev"}}}, WithIdentityHeader("X-Sub", "sub"))
	e.mount(t, "/admin", Require(Group("admin")))
	e.mount(t, "/dev", Require(Group("dev")))
	e.mount(t, "/public", AllowAnonymous(), Require(Group("admin")))
	e.mount(t, "/team", AllowAnonymous(), Require(Group("dev")))
	cookies := e.loggedIn(t)
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodGet, "/admin", cookies, nil).Code)
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodGet, "/admin", cookies, nil).Code)
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/dev", cookies, nil).Code)

	crossSite := http.Header{"Sec-Fetch-Site": {"cross-site"}, "X-Sub": {"admin"}}
	assert.Equal(t, http.StatusOK, e.do(http.MethodPost, "/public", cookies, crossSite).Code)
	assert.False(t, e.identified)
	assert.Empty(t, e.upstream().Values("X-Sub"))
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/team", cookies, nil).Code)
	assert.True(t, e.identified)
	assert.Equal(t, "alice", e.upstream().Get("X-Sub"))
	assert.Panics(t, func() { Require(Group("admin"), nil) })
}

func TestRules(t *testing.T) {
	verified := map[string]any{"email": "Alice@Example.com", "email_verified": true, "groups": []any{"dev", 1}, "tenant": "acme"}
	unverified := map[string]any{"email": "alice@example.com", "email_verified": "true"}
	cases := []struct {
		name   string
		rule   Rule
		claims map[string]any
		want   bool
	}{
		{name: "email domain", rule: EmailDomain("other.com", "example.com"), claims: verified, want: true},
		{name: "email subdomain", rule: EmailDomain("example.com"), claims: map[string]any{"email": "a@sub.example.com", "email_verified": true}},
		{name: "email domain unverified", rule: EmailDomain("example.com"), claims: unverified},
		{name: "email domain without at", rule: EmailDomain("example.com"), claims: map[string]any{"email": "example.com", "email_verified": true}},
		{name: "email", rule: Email("alice@example.com"), claims: verified, want: true},
		{name: "email other", rule: Email("bob@example.com"), claims: verified},
		{name: "email unverified", rule: Email("alice@example.com"), claims: unverified},
		{name: "email kelvin sign", rule: Email("kim@example.com"), claims: map[string]any{"email": "\u212aim@example.com", "email_verified": true}},
		{name: "email domain long s in rule", rule: EmailDomain("\u017fub.example.com"), claims: map[string]any{"email": "a@sub.example.com", "email_verified": true}},
		{name: "group", rule: Group("ops", "dev"), claims: verified, want: true},
		{name: "group other", rule: Group("ops"), claims: verified},
		{name: "group missing", rule: Group("dev"), claims: unverified},
		{name: "claim string", rule: Claim("tenant", "acme"), claims: verified, want: true},
		{name: "claim other", rule: Claim("tenant", "globex"), claims: verified},
		{name: "claim number", rule: Claim("groups", "1"), claims: verified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.rule(tc.claims))
		})
	}
}

func TestProxyLogout(t *testing.T) {
	cases := []struct {
		name   string
		method string
		header http.Header
		want   int
	}{
		{name: "same origin get", method: http.MethodGet, header: http.Header{"Sec-Fetch-Site": {"same-origin"}}, want: http.StatusSeeOther},
		{name: "typed url", method: http.MethodGet, header: http.Header{"Sec-Fetch-Site": {"none"}}, want: http.StatusSeeOther},
		{name: "same origin post", method: http.MethodPost, header: http.Header{"Origin": {appOrigin}}, want: http.StatusSeeOther},
		{name: "no fetch metadata", method: http.MethodGet, want: http.StatusSeeOther},
		{name: "cross site get", method: http.MethodGet, header: http.Header{"Sec-Fetch-Site": {"cross-site"}}, want: http.StatusForbidden},
		{name: "same site get", method: http.MethodGet, header: http.Header{"Sec-Fetch-Site": {"same-site"}}, want: http.StatusForbidden},
		{name: "other origin", method: http.MethodPost, header: http.Header{"Origin": {"https://evil.example.com"}}, want: http.StatusForbidden},
	}
	e := newProxyEnv(t, oidctest.Options{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.do(tc.method, "/oauth2/logout", e.loggedIn(t), tc.header)
			assert.Equal(t, tc.want, rec.Code)
			cleared := hasLine(rec.Header().Values("Set-Cookie"), "__Host-Http-Proxy.0=; Path=/; Max-Age=0")
			assert.Equal(t, tc.want == http.StatusSeeOther, cleared)
		})
	}
}

func hasLine(lines []string, prefix string) bool {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func TestOwnCookiesSharedHost(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{})
	cookies := append(e.loggedIn(t), &http.Cookie{Name: "__Host-Http-BFF.0", Value: "x"}, &http.Cookie{Name: "__Http-Proxy.0", Value: "x"},
		&http.Cookie{Name: "app", Value: "1"})
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, nil).Code)
	assert.Equal(t, "app=1", e.upstream().Get("Cookie"))

	h := http.Header{"Set-Cookie": {"__Host-Http-Proxy.0=x; Path=/", "__Host-Http-BFF-Login-a.0=x; Path=/", "__Http-Proxy-Login-a.0=x; Path=/", "app=1"}}
	removeOwnSetCookies(h)
	assert.Equal(t, []string{"app=1"}, h.Values("Set-Cookie"))
}

func TestNewProxyOptions(t *testing.T) {
	cases := []struct {
		name string
		opt  ProxyOption
	}{
		{name: "invalid header name", opt: WithIdentityHeader("X Email", "email")},
		{name: "empty claim", opt: WithIdentityHeader("X-Email", "")},
		{name: "nil rule", opt: WithAccessRule(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, tc.opt.applyProxy(defaultConfig()), ErrInvalidConfig)
		})
	}
	t.Run("duplicate header", func(t *testing.T) {
		cfg := defaultConfig()
		require.NoError(t, WithIdentityHeader("X-Email", "email").applyProxy(cfg))
		assert.ErrorIs(t, WithIdentityHeader("x_email", "mail").applyProxy(cfg), ErrInvalidConfig)
	})
	t.Run("back-channel without store", func(t *testing.T) {
		e := newProxyEnv(t, oidctest.Options{})
		assert.Panics(t, func() { e.p.BackchannelHandler() })
	})
}

func TestProxySharedSession(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{}, WithCookieDomain("Example.com"))
	rec := e.do(http.MethodGet, "https://app1.example.com/app/orders?id=1", nil, navigate)
	require.Equal(t, http.StatusFound, rec.Code)
	lines := rec.Header().Values("Set-Cookie")
	require.Len(t, lines, 1)
	assert.True(t, strings.HasPrefix(lines[0], "__Http-Proxy-Login-"))
	assert.Contains(t, lines[0], "Domain=example.com; Max-Age=900; HttpOnly; Secure; SameSite=Lax")

	rec = e.login(t, "https://app1.example.com/app/orders?id=1")
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "https://app1.example.com/app/orders?id=1", rec.Header().Get("Location"))
	assert.True(t, hasLine(rec.Header().Values("Set-Cookie"), "__Http-Proxy.0="))
	assert.Contains(t, strings.Join(rec.Header().Values("Set-Cookie"), "\n"), "Domain=example.com; HttpOnly; Secure; SameSite=Lax")
	cookies := requestCookies(t, rec.Header())

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "https://app2.example.com/app/", cookies, nil).Code)
	assert.True(t, e.identified)
	crossOrigin := http.Header{"Origin": {"https://app2.example.com"}}
	assert.Equal(t, http.StatusForbidden, e.do(http.MethodPost, "https://app1.example.com/app/", cookies, crossOrigin).Code)

	rec = e.do(http.MethodGet, "https://notexample.com/app/", nil, navigate)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Header().Values("Set-Cookie"))

	rec = e.do(http.MethodGet, "/oauth2/logout", cookies, nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.True(t, hasLine(rec.Header().Values("Set-Cookie"), "__Http-Proxy.0=; Path=/; Domain=example.com; Max-Age=0"))
}

func TestWithCookieDomain(t *testing.T) {
	for _, domain := range []string{"", "co.uk", "github.io", "10.0.0.1", ".example.com", "example.com.", "exa mple.com", "exa_mple.com"} {
		assert.ErrorIs(t, WithCookieDomain(domain).applyProxy(defaultConfig()), ErrInvalidConfig, domain)
	}
	cfg := defaultConfig()
	require.NoError(t, WithCookieDomain("Apps.Example.com").applyProxy(cfg))
	assert.Equal(t, "apps.example.com", cfg.cookieDomain)

	idp := oidctest.NewServer(oidctest.Options{})
	t.Cleanup(idp.Close)
	_, err := NewProxy(proxyClient(t, idp), newGCMAEAD(t), WithCookieDomain("other.com"))
	assert.ErrorIs(t, err, ErrInvalidConfig)
	_, err = NewProxy(proxyClient(t, idp), newGCMAEAD(t), WithCookieDomain("app.example.com"))
	assert.NoError(t, err)
}

func TestProxyLogoutSpeculative(t *testing.T) {
	e := newProxyEnv(t, oidctest.Options{}, WithStore(memory.NewStore()))
	cookies := e.loggedIn(t)
	rec := e.do(http.MethodGet, "/oauth2/logout", cookies, http.Header{"Sec-Purpose": {"prefetch"}, "Sec-Fetch-Site": {"same-origin"}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, nil).Code)
}

func TestProxyIdentityHeadersConnection(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) }}

	e := newProxyEnv(t, oidctest.Options{Claims: map[string]any{"groups": []any{"dev"}}}, WithIdentityHeader("X-Auth-Request-Groups", "groups"))
	_, err = e.router.Add(fox.MethodAny, "/rp/*{any}", fox.WrapH(proxy), fox.WithMiddleware(e.p.Authenticate()))
	require.NoError(t, err)
	cookies := e.loggedIn(t)

	for _, connection := range []string{"X-Auth-Request-Groups", "keep-alive, x_auth_request_groups", "X-Other"} {
		require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/rp/x", cookies, http.Header{"Connection": {connection}, "X-Other": {"1"}}).Code)
		assert.Equal(t, "dev", got.Get("X-Auth-Request-Groups"), connection)
	}
	assert.Empty(t, got.Get("X-Other"))

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, http.Header{"Connection": {"keep-alive, X-Auth-Request-Groups"}}).Code)
	assert.Equal(t, "keep-alive", e.upstream().Get("Connection"))
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/app/", cookies, http.Header{"Connection": {"X-Auth-Request-Groups"}}).Code)
	assert.Empty(t, e.upstream().Values("Connection"))
}

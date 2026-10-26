// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPProof(t *testing.T) {
	key, raw, err := newDPoPKey()
	require.NoError(t, err)
	parsed, err := parseDPoPKey(raw)
	require.NoError(t, err)
	assert.Equal(t, key.jkt, parsed.jkt)

	r := httptest.NewRequest(http.MethodPost, "https://api.example.com/orders?id=1", nil)
	proof, err := parsed.proof(r, "access-token", "n1", time.Now())
	require.NoError(t, err)
	r.Header.Set("DPoP", proof)
	jkt, err := oidctest.VerifyDPoPProof(r, "access-token", "n1")
	require.NoError(t, err)
	assert.Equal(t, key.jkt, jkt)

	_, err = parseDPoPKey([]byte("invalid"))
	assert.Error(t, err)
}

func TestNonceCacheBound(t *testing.T) {
	c := newNonceCache()
	for i := range maxNonceOrigins + 10 {
		c.set("https://api"+strconv.Itoa(i)+".example.com", "n")
	}
	assert.Len(t, c.nonces, maxNonceOrigins)
	c.set("https://api0.example.com", "n2")
	assert.Equal(t, "n2", c.get("https://api0.example.com"))
}

func TestLoginDPoP(t *testing.T) {
	cases := []struct {
		name string
		opts oidctest.Options
		fe   []Option
	}{
		{name: "front channel"},
		{name: "pushed authorization", opts: oidctest.Options{PAR: true}},
		{name: "userinfo", fe: []Option{WithUserInfo()}},
		{name: "nonce", opts: oidctest.Options{DPoPNonce: "n1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t, tc.opts, append(tc.fe, WithDPoP())...)
			rec, callback := e.startLogin(t, "")
			authorize, err := url.Parse(rec.Header().Get("Location"))
			require.NoError(t, err)
			if !tc.opts.PAR {
				assert.NotEmpty(t, authorize.Query().Get("dpop_jkt"))
			}

			res := e.serve(callback, requestCookies(t, rec.Header()))
			require.Equal(t, http.StatusFound, res.Code)
			s, _, err := e.fe.readSession(t.Context(), requestCookies(t, res.Header()))
			require.NoError(t, err)
			assert.Equal(t, "DPoP", s.TokenType)
			key, err := parseDPoPKey(s.DPoPKey)
			require.NoError(t, err)
			if !tc.opts.PAR {
				assert.Equal(t, authorize.Query().Get("dpop_jkt"), key.jkt)
			}
		})
	}
}

func TestLoginDPoPNotBound(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{IgnoreDPoP: true}, WithDPoP())
	assert.Equal(t, http.StatusBadGateway, e.login(t, "", nil).Code)
}

func TestLoginDPoPWithoutKey(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{})
	rec, callback := e.startLogin(t, "")
	e.fe.cfg.dpop = true
	assert.Equal(t, http.StatusBadRequest, e.serve(callback, requestCookies(t, rec.Header())).Code)
}

func TestRefreshDPoP(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: 30 * time.Second, DPoPNonce: "n1"}, WithDPoP())
	got := e.mount(t, "/api")
	cookies := e.loggedIn(t)
	before, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)

	e.skipAhead(20 * time.Second)
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
	refreshed := (*got)[0].state.session
	assert.NotEqual(t, before.AccessToken, refreshed.AccessToken)
	assert.Equal(t, "DPoP", refreshed.TokenType)
	assert.Equal(t, before.DPoPKey, refreshed.DPoPKey)

	e.idp.Update(func(o *oidctest.Options) { o.IgnoreDPoP = true })
	e.skipAhead(2 * time.Minute)
	assert.Equal(t, http.StatusBadGateway, e.do(http.MethodGet, "/api", cookies, nil).Code)
}

type dpopAPI struct {
	*httptest.Server
	nonce    atomic.Pointer[string]
	requests atomic.Int32
	jkt      atomic.Pointer[string]
}

func newDPoPAPI(t *testing.T) *dpopAPI {
	t.Helper()
	api := &dpopAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.requests.Add(1)
		nonce := *api.nonce.Load()
		w.Header().Set("DPoP-Nonce", nonce)
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
		jkt, err := oidctest.VerifyDPoPProof(r, token, nonce)
		if !ok || err != nil {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api.jkt.Store(&jkt)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	api.setNonce("n1")
	return api
}

func (a *dpopAPI) setNonce(n string) {
	a.nonce.Store(&n)
}

func TestTransportDPoP(t *testing.T) {
	api := newDPoPAPI(t)
	target, err := url.Parse(api.URL)
	require.NoError(t, err)
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour}, WithDPoP())
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(target) }, Transport: Transport(nil)}
	_, err = e.router.Add(fox.MethodAny, "/api/*{any}", fox.WrapH(proxy), fox.WithMiddleware(e.fe.Middleware()))
	require.NoError(t, err)
	cookies := e.loggedIn(t)
	s, _, err := e.fe.readSession(t.Context(), cookies)
	require.NoError(t, err)
	key, err := parseDPoPKey(s.DPoPKey)
	require.NoError(t, err)

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, appOrigin+"/api/orders", strings.NewReader("{}"))
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api/orders", cookies, nil).Code)
	assert.Equal(t, int32(2), api.requests.Load())
	assert.Equal(t, key.jkt, *api.jkt.Load())

	require.Equal(t, http.StatusOK, post())
	assert.Equal(t, int32(3), api.requests.Load())

	api.setNonce("n2")
	assert.Equal(t, http.StatusUnauthorized, post())
	assert.Equal(t, int32(4), api.requests.Load())
	assert.Equal(t, http.StatusOK, post())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSendDPoPProviderError(t *testing.T) {
	key, _, err := newDPoPKey()
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		error string
		calls int
	}{
		{name: "use_dpop_nonce", error: "use_dpop_nonce", calls: 2},
		{name: "invalid_grant", error: "invalid_grant", calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []string
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				bodies = append(bodies, string(body))
				if len(bodies) == 2 {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
				}
				h := http.Header{"Dpop-Nonce": {"n1"}}
				return &http.Response{StatusCode: http.StatusBadRequest, Header: h, Body: io.NopCloser(strings.NewReader(`{"error":"` + tc.error + `"}`))}, nil
			})
			req, err := http.NewRequest(http.MethodPost, "https://idp.example.com/token", strings.NewReader("grant_type=refresh_token"))
			require.NoError(t, err)

			resp, err := sendDPoP(base, newNonceCache(), key, req, "", time.Now())
			require.NoError(t, err)
			assert.Len(t, bodies, tc.calls)
			for _, b := range bodies {
				assert.Equal(t, "grant_type=refresh_token", b)
			}
			if tc.calls == 1 {
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{"error":"invalid_grant"}`, string(body))
			}
		})
	}
}

func TestMiddlewareDPoPMismatch(t *testing.T) {
	for _, dpop := range []bool{false, true} {
		t.Run(strconv.FormatBool(dpop), func(t *testing.T) {
			var opts []Option
			if dpop {
				opts = append(opts, WithDPoP())
			}
			e := newTestEnv(t, oidctest.Options{}, opts...)
			e.mount(t, "/api")
			cookies := e.loggedIn(t)
			s, _, err := e.fe.readSession(t.Context(), cookies)
			require.NoError(t, err)

			e.fe.cfg.dpop = !dpop
			rec := e.do(http.MethodGet, "/api", cookies, nil)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			lines := sessionCookieLines(rec.Header())
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0], "Max-Age=0")
			assert.Equal(t, []string{s.RefreshToken}, e.idp.Revoked())
		})
	}
}

func TestTransportDPoPHostHeader(t *testing.T) {
	api := newDPoPAPI(t)
	target, err := url.Parse(api.URL)
	require.NoError(t, err)
	e := newTestEnv(t, oidctest.Options{AccessTokenTTL: time.Hour}, WithDPoP())
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = Transport(nil)
	_, err = e.router.Add(fox.MethodAny, "/api/*{any}", fox.WrapH(proxy), fox.WithMiddleware(e.fe.Middleware()))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api/orders", e.loggedIn(t), nil).Code)
}

func TestDPoPTransportSchemeCase(t *testing.T) {
	key, _, err := newDPoPKey()
	require.NoError(t, err)
	var got string
	var verifyErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, verifyErr = oidctest.VerifyDPoPProof(r, "access-token", "")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "dpop access-token")
	rt := &dpopTransport{base: http.DefaultTransport, key: key, nonces: newNonceCache(), now: time.Now}
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, "DPoP access-token", got)
	assert.NoError(t, verifyErr)
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store/memory"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndToEnd(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		name := "stateless"
		if stateful {
			name = "stateful"
		}
		t.Run(name, func(t *testing.T) {
			idp := oidctest.NewServer(oidctest.Options{
				Subject:             "alice",
				SID:                 "s1",
				AccessTokenTTL:      30 * time.Second,
				RotateRefreshTokens: true,
			})
			defer idp.Close()

			var (
				mu     sync.Mutex
				tokens []string
			)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				tokens = append(tokens, r.Header.Get("Authorization"))
				mu.Unlock()
				_, _ = io.WriteString(w, "orders")
			}))
			defer api.Close()
			apiURL, err := url.Parse(api.URL)
			require.NoError(t, err)

			f := fox.MustRouter()
			app := httptest.NewUnstartedServer(f)
			app.StartTLS()
			defer app.Close()

			p, err := NewProvider(t.Context(), idp.URL, WithHTTPClient(idp.Client()))
			require.NoError(t, err)
			var opts []Option
			if stateful {
				opts = append(opts, WithStore(memory.NewStore()))
			}
			fe, err := NewFrontend(Client{
				Provider:              p,
				ClientID:              "app",
				ClientSecret:          oidctest.ClientSecret,
				RedirectURL:           app.URL + "/bff/callback",
				PostLogoutRedirectURL: app.URL + "/",
				Scopes:                []string{"openid"},
			}, newGCMAEAD(t), opts...)
			require.NoError(t, err)

			proxy := &httputil.ReverseProxy{
				Rewrite:   func(pr *httputil.ProxyRequest) { pr.SetURL(apiURL) },
				Transport: Transport(nil),
			}
			page := func(c *fox.Context) { _ = c.String(http.StatusOK, "page") }
			type route struct {
				methods []string
				pattern string
				handler fox.HandlerFunc
				opts    []fox.RouteOption
			}
			require.NoError(t, f.Updates(func(txn *fox.Txn) error {
				routes := []route{
					{methods: fox.MethodGet, pattern: "/bff/login", handler: fe.LoginHandler()},
					{methods: fox.MethodGet, pattern: "/bff/callback", handler: fe.CallbackHandler()},
					{methods: []string{http.MethodGet, http.MethodPost}, pattern: "/bff/logout", handler: fe.LogoutHandler()},
					{methods: fox.MethodGet, pattern: "/bff/user", handler: fe.UserHandler()},
					{methods: fox.MethodAny, pattern: "/api/*{any}", handler: fox.WrapH(proxy), opts: []fox.RouteOption{fox.WithMiddleware(fe.Middleware())}},
					{methods: fox.MethodGet, pattern: "/", handler: page},
					{methods: fox.MethodGet, pattern: "/home", handler: page},
				}
				if stateful {
					routes = append(routes, route{methods: fox.MethodPost, pattern: "/bff/backchannel", handler: fe.BackchannelHandler()})
				}
				for _, r := range routes {
					if _, err := txn.Add(r.methods, r.pattern, r.handler, r.opts...); err != nil {
						return err
					}
				}
				return nil
			}))

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			browser := app.Client()
			browser.Jar = jar

			get := func(path string) *http.Response {
				t.Helper()
				resp, err := browser.Get(app.URL + path)
				require.NoError(t, err)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp
			}
			user := func() (int, string) {
				t.Helper()
				resp, err := browser.Get(app.URL + "/bff/user")
				require.NoError(t, err)
				defer resp.Body.Close()
				var body struct {
					Claims          map[string]any `json:"claims"`
					LogoutCSRFToken string         `json:"logoutCsrfToken"`
				}
				if resp.StatusCode == http.StatusOK {
					require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
					assert.Equal(t, "alice", body.Claims["sub"])
				}
				return resp.StatusCode, body.LogoutCSRFToken
			}

			code, _ := user()
			require.Equal(t, http.StatusUnauthorized, code)

			resp := get("/bff/login?returnUrl=/home")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "/home", resp.Request.URL.Path)

			code, logoutToken := user()
			require.Equal(t, http.StatusOK, code)
			appURL, err := url.Parse(app.URL)
			require.NoError(t, err)
			before, _, err := fe.readSession(t.Context(), jar.Cookies(appURL))
			require.NoError(t, err)
			fe.now = func() time.Time { return time.Now().Add(20 * time.Second) }

			for range 3 {
				require.Equal(t, http.StatusOK, get("/api/orders").StatusCode)
			}
			require.Len(t, tokens, 3)
			for _, token := range tokens {
				assert.True(t, strings.HasPrefix(token, "Bearer "))
			}
			assert.NotEqual(t, "Bearer "+before.AccessToken, tokens[0])
			assert.Equal(t, tokens[0], tokens[2])

			resp, err = browser.PostForm(app.URL+"/bff/logout", url.Values{"csrf_token": {logoutToken}})
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, app.URL+"/", resp.Request.URL.String())
			require.Len(t, idp.EndSessions(), 1)
			assert.NotEmpty(t, idp.EndSessions()[0].IDTokenHint)
			assert.NotEmpty(t, idp.Revoked())
			code, _ = user()
			assert.Equal(t, http.StatusUnauthorized, code)
			assert.Equal(t, http.StatusUnauthorized, get("/api/orders").StatusCode)

			if !stateful {
				return
			}
			require.Equal(t, http.StatusOK, get("/bff/login").StatusCode)
			code, _ = user()
			require.Equal(t, http.StatusOK, code)

			resp, err = app.Client().PostForm(app.URL+"/bff/backchannel", url.Values{
				"logout_token": {idp.LogoutToken("app", "alice", "")},
			})
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			code, _ = user()
			assert.Equal(t, http.StatusUnauthorized, code)
		})
	}
}

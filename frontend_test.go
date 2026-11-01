// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopAEAD struct{}

func (nopAEAD) Encrypt(plaintext, _ []byte) ([]byte, error)  { return plaintext, nil }
func (nopAEAD) Decrypt(ciphertext, _ []byte) ([]byte, error) { return ciphertext, nil }

func newTestProvider(t testing.TB, metadata map[string]any) *Provider {
	t.Helper()
	srv := oidctest.NewServer(oidctest.Options{Metadata: metadata})
	t.Cleanup(srv.Close)
	p, err := NewProvider(t.Context(), srv.URL, WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	return p
}

func TestNewProvider(t *testing.T) {
	t.Run("discovery metadata", func(t *testing.T) {
		p := newTestProvider(t, map[string]any{
			"end_session_endpoint":                           "https://idp.example.com/logout",
			"revocation_endpoint":                            "https://idp.example.com/revoke",
			"prompt_values_supported":                        []string{"none", "login"},
			"authorization_response_iss_parameter_supported": true,
			"pushed_authorization_request_endpoint":          "https://idp.example.com/par",
			"require_pushed_authorization_requests":          true,
		})
		assert.Equal(t, "https://idp.example.com/logout", p.endSessionEndpoint)
		assert.Equal(t, "https://idp.example.com/revoke", p.revocationEndpoint)
		assert.Equal(t, "https://idp.example.com/par", p.parEndpoint)
		assert.True(t, p.requirePAR)
		assert.Equal(t, []string{"none", "login"}, p.promptValues)
		assert.True(t, p.issParameter)
	})

	t.Run("endpoint options", func(t *testing.T) {
		srv := oidctest.NewServer(oidctest.Options{Metadata: map[string]any{"revocation_endpoint": "http://idp.example.com/revoke"}})
		defer srv.Close()
		p, err := NewProvider(t.Context(), srv.URL, WithHTTPClient(srv.Client()),
			WithEndSessionEndpoint("https://idp.example.com/logout"), WithRevocationEndpoint("https://idp.example.com/revoke"))
		require.NoError(t, err)
		assert.Equal(t, "https://idp.example.com/logout", p.endSessionEndpoint)
		assert.Equal(t, "https://idp.example.com/revoke", p.revocationEndpoint)
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		srv := oidctest.NewServer(oidctest.Options{Metadata: map[string]any{"issuer": "https://other.example.com"}})
		defer srv.Close()
		_, err := NewProvider(t.Context(), srv.URL, WithHTTPClient(srv.Client()))
		assert.Error(t, err)
	})

	t.Run("pushed authorization required without endpoint", func(t *testing.T) {
		srv := oidctest.NewServer(oidctest.Options{Metadata: map[string]any{"require_pushed_authorization_requests": true}})
		defer srv.Close()
		_, err := NewProvider(t.Context(), srv.URL, WithHTTPClient(srv.Client()))
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})

	t.Run("invalid config", func(t *testing.T) {
		cases := []struct {
			name   string
			issuer string
			opts   []ProviderOption
		}{
			{name: "http issuer", issuer: "http://idp.example.com"},
			{name: "relative issuer", issuer: "/realms/acme"},
			{name: "issuer with fragment", issuer: "https://idp.example.com#x"},
			{name: "nil http client", issuer: "https://idp.example.com", opts: []ProviderOption{WithHTTPClient(nil)}},
			{name: "empty end session endpoint", issuer: "https://idp.example.com", opts: []ProviderOption{WithEndSessionEndpoint("")}},
			{name: "http revocation endpoint", issuer: "https://idp.example.com", opts: []ProviderOption{WithRevocationEndpoint("http://idp.example.com/revoke")}},
		}
		for _, endpoint := range []string{"token_endpoint", "jwks_uri", "end_session_endpoint", "revocation_endpoint",
			"pushed_authorization_request_endpoint"} {
			t.Run("http "+endpoint, func(t *testing.T) {
				srv := oidctest.NewServer(oidctest.Options{Metadata: map[string]any{endpoint: "http://idp.example.com/x"}})
				defer srv.Close()
				_, err := NewProvider(t.Context(), srv.URL, WithHTTPClient(srv.Client()))
				assert.ErrorIs(t, err, ErrInvalidConfig)
			})
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewProvider(t.Context(), tc.issuer, tc.opts...)
				assert.ErrorIs(t, err, ErrInvalidConfig)
			})
		}
	})
}

func TestNewFrontend(t *testing.T) {
	p := newTestProvider(t, nil)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	valid := func() Client {
		return Client{
			Provider:              p,
			ClientID:              "app",
			ClientSecret:          "secret",
			RedirectURL:           "https://app.example.com/bff/callback",
			PostLogoutRedirectURL: "https://app.example.com/",
			Scopes:                []string{"openid", "profile"},
		}
	}

	t.Run("valid", func(t *testing.T) {
		c := valid()
		fe, err := NewFrontend(c, nopAEAD{}, WithIdleTimeout(time.Minute), WithCSRFHeader("x-csrf", "1"))
		require.NoError(t, err)
		c.Scopes[1] = "email"
		assert.Equal(t, []string{"openid", "profile"}, fe.rp.oauth2.Scopes)
		assert.Equal(t, "X-Csrf", fe.rp.cfg.csrfHeader)
	})

	t.Run("same site trusted origins", func(t *testing.T) {
		for redirect, origin := range map[string]string{
			"https://BFF.EXAMPLE.COM/bff/callback":    "https://app.example.com",
			"https://bff.BÜCHER.example/bff/callback": "https://app.xn--bcher-kva.example",
			"https://[2001:DB8::1]/bff/callback":      "https://[2001:db8::1]",
			"http://localhost:8080/bff/callback":      "http://localhost:5173",
			"http://[::1]:8080/bff/callback":          "http://[::1]:5173",
			"https://127.0.0.1:8443/bff/callback":     "https://127.0.0.1:5173",
		} {
			c := valid()
			c.RedirectURL = redirect
			_, err := NewFrontend(c, nopAEAD{}, WithTrustedOrigins(origin))
			assert.NoError(t, err)
		}
	})

	t.Run("loopback http redirect", func(t *testing.T) {
		c := valid()
		c.RedirectURL = "http://localhost:8080/bff/callback"
		_, err := NewFrontend(c, nopAEAD{})
		assert.NoError(t, err)
	})

	cases := []struct {
		name    string
		client  func(c *Client)
		opts    []FrontendOption
		nilAEAD bool
	}{
		{name: "nil provider", client: func(c *Client) { c.Provider = nil }},
		{name: "empty client id", client: func(c *Client) { c.ClientID = "" }},
		{name: "empty client secret", client: func(c *Client) { c.ClientSecret = "" }},
		{name: "secret and key", client: func(c *Client) { c.ClientKey = p256 }},
		{name: "key id without key", client: func(c *Client) { c.ClientKeyID = "k1" }},
		{name: "p384 key", client: func(c *Client) { c.ClientSecret, c.ClientKey = "", p384 }},
		{name: "small rsa key", client: func(c *Client) { c.ClientSecret, c.ClientKey = "", rsa1024 }},
		{name: "http redirect url", client: func(c *Client) { c.RedirectURL = "http://app.example.com/bff/callback" }},
		{name: "relative redirect url", client: func(c *Client) { c.RedirectURL = "/bff/callback" }},
		{name: "invalid post logout url", client: func(c *Client) { c.PostLogoutRedirectURL = "/" }},
		{name: "missing openid scope", client: func(c *Client) { c.Scopes = []string{"profile"} }},
		{name: "empty scope", client: func(c *Client) { c.Scopes = []string{"openid", ""} }},
		{name: "scope with space", client: func(c *Client) { c.Scopes = []string{"openid", "a b"} }},
		{name: "nil aead", client: func(*Client) {}, nilAEAD: true},
		{name: "idle timeout", client: func(*Client) {}, opts: []FrontendOption{WithIdleTimeout(0)}},
		{name: "absolute timeout", client: func(*Client) {}, opts: []FrontendOption{WithAbsoluteTimeout(-time.Second)}},
		{name: "idle exceeds absolute", client: func(*Client) {}, opts: []FrontendOption{WithIdleTimeout(2 * time.Hour), WithAbsoluteTimeout(time.Hour)}},
		{name: "csrf header name", client: func(*Client) {}, opts: []FrontendOption{WithCSRFHeader("x csrf", "1")}},
		{name: "csrf header value", client: func(*Client) {}, opts: []FrontendOption{WithCSRFHeader("x-csrf", "")}},
		{name: "nil unauthorized handler", client: func(*Client) {}, opts: []FrontendOption{WithUnauthorizedHandler(nil)}},
		{name: "nil log handler", client: func(*Client) {}, opts: []FrontendOption{WithLogHandler(nil)}},
		{name: "trusted origin with path", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://spa.example.com/")}},
		{name: "trusted origin without scheme", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("spa.example.com")}},
		{name: "http trusted origin", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("http://spa.example.com")}},
		{name: "uppercase trusted origin", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://SPA.example.com")}},
		{name: "trusted origin with userinfo", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://user@spa.example.com")}},
		{name: "trusted origin with default port", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://spa.example.com:443")}},
		{name: "cross-site trusted origin", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://app.example.org")}},
		{name: "trusted origin on a public suffix", client: func(c *Client) { c.RedirectURL = "https://bff.vercel.app/bff/callback" }, opts: []FrontendOption{WithTrustedOrigins("https://app.vercel.app")}},
		{name: "trusted origin with another scheme", client: func(c *Client) { c.RedirectURL = "https://localhost:8443/bff/callback" }, opts: []FrontendOption{WithTrustedOrigins("http://localhost:5173")}},
		{name: "trusted origin on another loopback host", client: func(c *Client) { c.RedirectURL = "http://localhost:8080/bff/callback" }, opts: []FrontendOption{WithTrustedOrigins("http://127.0.0.1:5173")}},
		{name: "trusted origin on another ip", client: func(c *Client) { c.RedirectURL = "https://10.0.0.1/bff/callback" }, opts: []FrontendOption{WithTrustedOrigins("https://10.1.0.1")}},
		{name: "trusted origin with empty port", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://spa.example.com:")}},
		{name: "loopback trusted origin with default port", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("http://localhost:80")}},
		{name: "unicode trusted origin", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://bücher.example")}},
		{name: "wildcard trusted origin", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://*.example.com")}},
		{name: "trusted origin with quote", client: func(*Client) {}, opts: []FrontendOption{WithTrustedOrigins("https://spa.example.com'")}},
		{name: "dpop algorithm", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{"dpop_signing_alg_values_supported": []string{"RS256"}})
		}, opts: []FrontendOption{WithDPoP(true)}},
		{name: "unsupported signing algorithm", client: func(*Client) {}, opts: []FrontendOption{WithSigningAlgorithms("HS256")}},
		{name: "no common signing algorithm", client: func(*Client) {}, opts: []FrontendOption{WithSigningAlgorithms("ES256")}},
		{name: "provider with unsupported signing algorithms", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{"id_token_signing_alg_values_supported": []string{"HS256"}})
		}, opts: []FrontendOption{WithSigningAlgorithms("ES256")}},
		{name: "provider with only unsupported signing algorithms", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{"id_token_signing_alg_values_supported": []string{"ES256K"}})
		}},
		{name: "pushed authorization mode", client: func(*Client) {}, opts: []FrontendOption{WithPushedAuthorization(3)}},
		{name: "pushed authorization without endpoint", client: func(*Client) {}, opts: []FrontendOption{WithPushedAuthorization(PushedAuthorizationRequired)}},
		{name: "pushed authorization disabled but required", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{
				"pushed_authorization_request_endpoint": "https://idp.example.com/par",
				"require_pushed_authorization_requests": true,
			})
		}, opts: []FrontendOption{WithPushedAuthorization(PushedAuthorizationDisabled)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.client(&c)
			var aead AEAD = nopAEAD{}
			if tc.nilAEAD {
				aead = nil
			}
			_, err := NewFrontend(c, aead, tc.opts...)
			assert.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestNewFrontendRequestObject(t *testing.T) {
	keys := generateKeys(t)
	par := "https://idp.example.com/par"
	cases := []struct {
		name     string
		key      crypto.Signer
		metadata map[string]any
		opts     []FrontendOption
		alg      string
		authAlg  string
	}{
		{name: "ec", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []FrontendOption{WithRequestObject(true)}, alg: "ES256", authAlg: "ES256"},
		{name: "algorithm chosen apart from the assertion", key: keys["rsa"], metadata: map[string]any{
			"pushed_authorization_request_endpoint":            par,
			"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
			"request_object_signing_alg_values_supported":      []string{"PS256"},
		}, opts: []FrontendOption{WithRequestObject(true)}, alg: "PS256", authAlg: "RS256"},
		{name: "unsupported algorithm", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint":       par,
			"request_object_signing_alg_values_supported": []string{"PS256"},
		}, opts: []FrontendOption{WithRequestObject(true)}},
		{name: "without client key", metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []FrontendOption{WithRequestObject(true)}},
		{name: "without pushed authorization endpoint", key: keys["ec"], opts: []FrontendOption{WithRequestObject(true)}},
		{name: "pushed authorization disabled", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []FrontendOption{WithRequestObject(true), WithPushedAuthorization(PushedAuthorizationDisabled)}},
		{name: "required by the provider", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
			"require_signed_request_object":         true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]any{"token_endpoint_auth_methods_supported": bothMethods}
			maps.Copy(metadata, tc.metadata)
			c := Client{
				Provider:    newTestProvider(t, metadata),
				ClientID:    "app",
				RedirectURL: "https://app.example.com/bff/callback",
				Scopes:      []string{"openid"},
			}
			if tc.key != nil {
				c.ClientKey = tc.key
			} else {
				c.ClientSecret = oidctest.ClientSecret
			}
			fe, err := NewFrontend(c, nopAEAD{}, tc.opts...)
			if tc.alg == "" {
				assert.ErrorIs(t, err, ErrInvalidConfig)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.alg, fe.rp.requestObjectAlg)
			assert.Equal(t, tc.authAlg, fe.rp.auth.alg)
		})
	}
}

func TestWithResources(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{},
		WithResources(billing, "https://api.example.com/app/?tenant=1"),
		WithResources(),
		WithResources(orders, billing),
		WithSigningAlgorithms("RS256"),
		WithSigningAlgorithms("PS256", "RS256"),
	)
	assert.Equal(t, []string{billing, "https://api.example.com/app/?tenant=1", orders}, e.fe.rp.cfg.resources)
	assert.Equal(t, []string{"RS256", "PS256"}, e.fe.rp.cfg.signingAlgs)

	for _, resource := range []string{"/api", "https://api.example.com/#x", "https://api.example.com/#", "https://[::1", ""} {
		assert.ErrorIs(t, WithResources(resource).applyFrontend(defaultConfig()), ErrInvalidConfig, resource)
	}
}

func TestTrustedOrigins(t *testing.T) {
	e := newTestEnv(t, oidctest.Options{},
		WithTrustedOrigins("https://spa.example.com", "https://admin.rp.example.com"),
		WithTrustedOrigins("https://spa.example.com"),
	)
	e.mount(t, "/api")
	e.mountLogout(t)
	assert.Equal(t, []string{"https://spa.example.com", "https://admin.rp.example.com"}, e.fe.rp.cfg.trustedOrigins)

	t.Run("requests", func(t *testing.T) {
		cookies := e.loggedIn(t)
		cases := []struct {
			name   string
			site   string
			origin string
			code   int
		}{
			{name: "trusted", site: "same-site", origin: "https://spa.example.com", code: http.StatusOK},
			{name: "other subdomain", site: "same-site", origin: "https://evil.example.com", code: http.StatusForbidden},
			{name: "other scheme", site: "cross-site", origin: "http://spa.example.com", code: http.StatusForbidden},
			{name: "old browser", origin: "https://spa.example.com", code: http.StatusOK},
			{name: "old browser from other subdomain", origin: "https://evil.example.com", code: http.StatusForbidden},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				header := http.Header{"Origin": {tc.origin}}
				if tc.site != "" {
					header.Set("Sec-Fetch-Site", tc.site)
				}
				assert.Equal(t, tc.code, e.do(http.MethodPost, "/api", cookies, header).Code)
			})
		}
	})

	t.Run("logout", func(t *testing.T) {
		cookies := e.loggedIn(t)
		s, _, err := e.fe.rp.readSession(t.Context(), cookies)
		require.NoError(t, err)
		header := http.Header{"Sec-Fetch-Site": {"same-site"}, "Origin": {"https://spa.example.com"}}
		rec := e.doForm(http.MethodPost, "/bff/logout", cookies, header, url.Values{"csrf_token": {s.LogoutCSRFToken}})
		assert.Equal(t, http.StatusSeeOther, rec.Code)
	})

	t.Run("return url", func(t *testing.T) {
		rec := e.login(t, "returnUrl="+url.QueryEscape("https://spa.example.com/orders?id=1"), nil)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "https://spa.example.com/orders?id=1", rec.Header().Get("Location"))

		for _, u := range []string{
			"https://evil.example.com/",
			"https://spa.example.com.evil.com/",
			"https://user@spa.example.com/",
			"http://spa.example.com/",
			"https://spa.example.com\\@evil.com",
			"//spa.example.com/",
			"https://spa.example.com/a\tb",
			"https://SPA.example.com/",
			"https://spa.example.com:443/",
			"https://adm%C4%B0n.example.com/",
			"https://admİn.example.com/",
		} {
			t.Run(u, func(t *testing.T) {
				assert.Equal(t, http.StatusBadRequest, e.serve("/bff/login?returnUrl="+url.QueryEscape(u), nil).Code)
			})
		}
	})
}

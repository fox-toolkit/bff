// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopAEAD struct{}

func (nopAEAD) Encrypt(plaintext, _ []byte) ([]byte, error)  { return plaintext, nil }
func (nopAEAD) Decrypt(ciphertext, _ []byte) ([]byte, error) { return ciphertext, nil }

func newTestProvider(t *testing.T, metadata map[string]any) *Provider {
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
		assert.Equal(t, []string{"openid", "profile"}, fe.oauth2.Scopes)
		assert.Equal(t, "X-Csrf", fe.cfg.csrfHeader)
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
		opts    []Option
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
		{name: "idle timeout", client: func(*Client) {}, opts: []Option{WithIdleTimeout(0)}},
		{name: "absolute timeout", client: func(*Client) {}, opts: []Option{WithAbsoluteTimeout(-time.Second)}},
		{name: "idle exceeds absolute", client: func(*Client) {}, opts: []Option{WithIdleTimeout(2 * time.Hour), WithAbsoluteTimeout(time.Hour)}},
		{name: "csrf header name", client: func(*Client) {}, opts: []Option{WithCSRFHeader("x csrf", "1")}},
		{name: "csrf header value", client: func(*Client) {}, opts: []Option{WithCSRFHeader("x-csrf", "")}},
		{name: "nil unauthorized handler", client: func(*Client) {}, opts: []Option{WithUnauthorizedHandler(nil)}},
		{name: "nil log handler", client: func(*Client) {}, opts: []Option{WithLogHandler(nil)}},
		{name: "dpop algorithm", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{"dpop_signing_alg_values_supported": []string{"RS256"}})
		}, opts: []Option{WithDPoP(true)}},
		{name: "unsupported signing algorithm", client: func(*Client) {}, opts: []Option{WithSigningAlgorithms("HS256")}},
		{name: "no common signing algorithm", client: func(*Client) {}, opts: []Option{WithSigningAlgorithms("ES256")}},
		{name: "pushed authorization mode", client: func(*Client) {}, opts: []Option{WithPushedAuthorization(3)}},
		{name: "pushed authorization without endpoint", client: func(*Client) {}, opts: []Option{WithPushedAuthorization(PushedAuthorizationRequired)}},
		{name: "pushed authorization disabled but required", client: func(c *Client) {
			c.Provider = newTestProvider(t, map[string]any{
				"pushed_authorization_request_endpoint": "https://idp.example.com/par",
				"require_pushed_authorization_requests": true,
			})
		}, opts: []Option{WithPushedAuthorization(PushedAuthorizationDisabled)}},
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
		opts     []Option
		alg      string
		authAlg  string
	}{
		{name: "ec", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []Option{WithRequestObject(true)}, alg: "ES256", authAlg: "ES256"},
		{name: "algorithm chosen apart from the assertion", key: keys["rsa"], metadata: map[string]any{
			"pushed_authorization_request_endpoint":            par,
			"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
			"request_object_signing_alg_values_supported":      []string{"PS256"},
		}, opts: []Option{WithRequestObject(true)}, alg: "PS256", authAlg: "RS256"},
		{name: "unsupported algorithm", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint":       par,
			"request_object_signing_alg_values_supported": []string{"PS256"},
		}, opts: []Option{WithRequestObject(true)}},
		{name: "without client key", metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []Option{WithRequestObject(true)}},
		{name: "without pushed authorization endpoint", key: keys["ec"], opts: []Option{WithRequestObject(true)}},
		{name: "pushed authorization disabled", key: keys["ec"], metadata: map[string]any{
			"pushed_authorization_request_endpoint": par,
		}, opts: []Option{WithRequestObject(true), WithPushedAuthorization(PushedAuthorizationDisabled)}},
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
			assert.Equal(t, tc.alg, fe.requestObjectAlg)
			assert.Equal(t, tc.authAlg, fe.auth.alg)
		})
	}
}

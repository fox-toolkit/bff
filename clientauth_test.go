// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var bothMethods = []string{"client_secret_basic", "private_key_jwt"}

func generateKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return map[string]crypto.Signer{"ec": ec, "rsa": rsaKey, "ed25519": ed}
}

func TestNewClientAuth(t *testing.T) {
	keys := generateKeys(t)
	cases := []struct {
		name     string
		key      crypto.Signer
		metadata map[string]any
		alg      string
		invalid  bool
	}{
		{name: "secret by default"},
		{name: "secret not supported", metadata: map[string]any{"token_endpoint_auth_methods_supported": []string{"private_key_jwt"}}, invalid: true},
		{name: "key by default", key: keys["ec"], invalid: true},
		{name: "ec", key: keys["ec"], metadata: map[string]any{"token_endpoint_auth_methods_supported": bothMethods}, alg: "ES256"},
		{name: "rsa", key: keys["rsa"], metadata: map[string]any{"token_endpoint_auth_methods_supported": bothMethods}, alg: "PS256"},
		{name: "rsa without pss", key: keys["rsa"], metadata: map[string]any{
			"token_endpoint_auth_methods_supported":            bothMethods,
			"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		}, alg: "RS256"},
		{name: "ed25519", key: keys["ed25519"], metadata: map[string]any{"token_endpoint_auth_methods_supported": bothMethods}, alg: "EdDSA"},
		{name: "unsupported algorithm", key: keys["ec"], metadata: map[string]any{
			"token_endpoint_auth_methods_supported":            bothMethods,
			"token_endpoint_auth_signing_alg_values_supported": []string{"PS256"},
		}, invalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Client{ClientID: "app", ClientSecret: oidctest.ClientSecret}
			if tc.key != nil {
				c.ClientSecret, c.ClientKey = "", tc.key
			}
			auth, err := newClientAuth(c, newTestProvider(t, tc.metadata))
			if tc.invalid {
				assert.ErrorIs(t, err, ErrInvalidConfig)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.alg, auth.alg)
		})
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	for name, key := range generateKeys(t) {
		t.Run(name, func(t *testing.T) {
			opts := oidctest.Options{
				PAR:            true,
				AccessTokenTTL: 30 * time.Second,
				ClientKey:      key.Public(),
				Metadata:       map[string]any{"token_endpoint_auth_methods_supported": bothMethods},
			}
			e := newTestEnvWithClient(t, opts, func(c *Client) {
				c.ClientSecret, c.ClientKey, c.ClientKeyID = "", key, "k1"
			})
			got := e.mount(t, "/api")
			cookies := e.loggedIn(t)
			e.skipAhead(20 * time.Second)
			require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/api", cookies, nil).Code)
			require.NoError(t, e.fe.revoke(t.Context(), (*got)[0].state.session.RefreshToken))

			var paths []string
			for _, a := range e.idp.Assertions() {
				paths = append(paths, a.Path)
				assert.Equal(t, e.fe.auth.alg, a.Alg)
				assert.Equal(t, "k1", a.KeyID)
			}
			assert.Equal(t, []string{"/par", "/token", "/token", "/revoke"}, paths)
		})
	}
}

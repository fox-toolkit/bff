// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testKeySet struct {
	set      *keySet
	keys     atomic.Pointer[[]jose.JSONWebKey]
	status   atomic.Int32
	requests atomic.Int32
	now      time.Time
}

func newTestKeySet(t *testing.T) *testKeySet {
	t.Helper()
	ks := &testKeySet{now: time.Now()}
	ks.publish()
	ks.status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks.requests.Add(1)
		w.WriteHeader(int(ks.status.Load()))
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": *ks.keys.Load()})
	}))
	t.Cleanup(srv.Close)
	ks.set = newKeySet(srv.Client(), srv.URL)
	ks.set.now = func() time.Time { return ks.now }
	return ks
}

func (ks *testKeySet) publish(keys ...jose.JSONWebKey) {
	ks.keys.Store(&keys)
}

func newSigningKey(t *testing.T, kid string) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid}
}

func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, nil)
	require.NoError(t, err)
	jws, err := signer.Sign([]byte(`{"sub":"alice"}`))
	require.NoError(t, err)
	token, err := jws.CompactSerialize()
	require.NoError(t, err)
	return token
}

func TestKeySetVerify(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	other, _ := newSigningKey(t, "k1")
	ks.publish(pub1)

	payload, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":"alice"}`, string(payload))
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, ""))
	assert.NoError(t, err)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, other, "k1"))
	assert.ErrorIs(t, err, errNoVerifyingKey)
	assert.Equal(t, int32(1), ks.requests.Load())
}

func TestKeySetRefetch(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	k2, pub2 := newSigningKey(t, "k2")
	ks.publish(pub1)
	_, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	require.NoError(t, err)

	ks.publish(pub1, pub2)
	for range 20 {
		_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k2, "k2"))
		assert.ErrorIs(t, err, errNoVerifyingKey)
	}
	assert.Equal(t, int32(1), ks.requests.Load())

	ks.now = ks.now.Add(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k2, "k2"))
	require.NoError(t, err)
	assert.Equal(t, int32(2), ks.requests.Load())
}

func TestKeySetMaxAge(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	ks.publish(pub1)
	token := signTestJWT(t, k1, "k1")
	_, err := ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)

	ks.publish()
	ks.now = ks.now.Add(maxKeysAge - time.Second)
	_, err = ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)

	ks.now = ks.now.Add(time.Second)
	_, err = ks.set.VerifySignature(t.Context(), token)
	assert.ErrorIs(t, err, errNoVerifyingKey)
	assert.Equal(t, int32(2), ks.requests.Load())
}

func TestKeySetFetchError(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	ks.publish(pub1)
	token := signTestJWT(t, k1, "k1")
	_, err := ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)

	ks.status.Store(http.StatusInternalServerError)
	ks.now = ks.now.Add(maxKeysAge)
	_, err = ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)

	ks.status.Store(http.StatusOK)
	ks.publish()
	ks.now = ks.now.Add(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), token)
	assert.ErrorIs(t, err, errNoVerifyingKey)
	assert.Equal(t, int32(3), ks.requests.Load())
}

func TestParseKeySet(t *testing.T) {
	keys, err := parseKeySet([]byte(`{"keys":[
		{"kty":"unknown","kid":"kty"},
		{"kty":"EC","kid":"curve","crv":"P-9999","x":"AQ","y":"AQ"},
		{"kty":"oct","kid":"oct","k":"c2VjcmV0"},
		{"kty":"RSA","kid":"rsa","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}
	]}`))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "rsa", keys[0].KeyID)

	_, err = parseKeySet([]byte(`{"keys":`))
	assert.Error(t, err)
}

func TestKeySetCanceledFetch(t *testing.T) {
	k1, pub1 := newSigningKey(t, "k1")
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		started <- struct{}{}
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JSONWebKey{pub1}})
	}))
	t.Cleanup(srv.Close)
	set := newKeySet(srv.Client(), srv.URL)
	token := signTestJWT(t, k1, "k1")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() {
		_, err := set.VerifySignature(ctx, token)
		done <- err
	}()
	<-started
	cancel()
	assert.Error(t, <-done)
	close(release)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := set.VerifySignature(t.Context(), token)
		assert.NoError(c, err)
	}, time.Second, 10*time.Millisecond)
}

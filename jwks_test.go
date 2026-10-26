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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testKeySet struct {
	set          *keySet
	keys         atomic.Pointer[[]jose.JSONWebKey]
	cacheControl atomic.Pointer[string]
	release      chan struct{}
	unblock      func()
	status       atomic.Int32
	requests     atomic.Int32
	now          atomic.Int64
	hang         atomic.Bool
}

func newTestKeySet(t *testing.T) *testKeySet {
	t.Helper()
	ks := &testKeySet{release: make(chan struct{})}
	ks.unblock = sync.OnceFunc(func() { close(ks.release) })
	ks.now.Store(time.Now().UnixNano())
	ks.publish()
	ks.status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.requests.Add(1)
		cc := r.Header.Get("Cache-Control")
		ks.cacheControl.Store(&cc)
		if ks.hang.Load() {
			<-ks.release
		}
		w.WriteHeader(int(ks.status.Load()))
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": *ks.keys.Load()})
	}))
	t.Cleanup(func() {
		ks.unblock()
		srv.Close()
	})
	ks.set = newKeySet(srv.Client(), srv.URL)
	ks.set.now = func() time.Time { return time.Unix(0, ks.now.Load()) }
	return ks
}

func (ks *testKeySet) publish(keys ...jose.JSONWebKey) {
	keys = append([]jose.JSONWebKey{}, keys...)
	ks.keys.Store(&keys)
}

func (ks *testKeySet) skipAhead(d time.Duration) {
	ks.now.Add(int64(d))
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
	assert.Equal(t, "no-cache", *ks.cacheControl.Load())
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

	ks.skipAhead(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k2, "k2"))
	require.NoError(t, err)
	assert.Equal(t, int32(2), ks.requests.Load())
}

func TestKeySetRefetchFromProvider(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	k2, pub2 := newSigningKey(t, "k2")
	ks.publish(pub1)
	_, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	require.NoError(t, err)

	ks.publish(pub2)
	_, err = providerKeySet{ks.set}.VerifySignature(t.Context(), signTestJWT(t, k2, "k2"))
	require.NoError(t, err)
	assert.Equal(t, int32(2), ks.requests.Load())
}

func TestKeySetRotationWithoutKeyID(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "")
	k2, pub2 := newSigningKey(t, "")
	ks.publish(pub1)
	_, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, ""))
	require.NoError(t, err)

	ks.publish(pub2)
	ks.skipAhead(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k2, ""))
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
	ks.skipAhead(maxKeysAge - time.Second)
	_, err = ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, int32(1), ks.requests.Load())

	ks.skipAhead(time.Second)
	_, err = ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := ks.set.VerifySignature(t.Context(), token)
		assert.ErrorIs(c, err, errNoVerifyingKey)
	}, time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(2), ks.requests.Load())
}

func TestKeySetStaleKeysDoNotWait(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	ks.publish(pub1)
	token := signTestJWT(t, k1, "k1")
	_, err := ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)

	ks.hang.Store(true)
	ks.skipAhead(maxKeysAge)
	start := time.Now()
	_, err = ks.set.VerifySignature(t.Context(), token)
	require.NoError(t, err)
	assert.Less(t, time.Since(start), time.Second)
	assert.Eventually(t, func() bool { return ks.requests.Load() == 2 }, time.Second, 10*time.Millisecond)
}

func TestKeySetFetchError(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	k2, _ := newSigningKey(t, "k2")
	ks.publish(pub1)
	_, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	require.NoError(t, err)

	ks.status.Store(http.StatusInternalServerError)
	ks.skipAhead(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k2, "k2"))
	require.ErrorIs(t, err, errNoVerifyingKey)
	assert.ErrorContains(t, err, "unexpected status 500")
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	assert.NoError(t, err)
}

func TestKeySetKeyAlgorithm(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	pub1.Algorithm = string(jose.ES384)
	ks.publish(pub1)
	_, err := ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	assert.ErrorIs(t, err, errNoVerifyingKey)

	pub1.Algorithm = string(jose.ES256)
	ks.publish(pub1)
	ks.skipAhead(minKeysRefetch)
	_, err = ks.set.VerifySignature(t.Context(), signTestJWT(t, k1, "k1"))
	assert.NoError(t, err)
}

func TestKeySetCanceledFetch(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	ks.publish(pub1)
	ks.hang.Store(true)
	token := signTestJWT(t, k1, "k1")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() {
		_, err := ks.set.VerifySignature(ctx, token)
		done <- err
	}()
	assert.Eventually(t, func() bool { return ks.requests.Load() == 1 }, time.Second, 10*time.Millisecond)
	cancel()
	assert.ErrorIs(t, <-done, context.Canceled)
	ks.unblock()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := ks.set.VerifySignature(t.Context(), token)
		assert.NoError(c, err)
	}, time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(1), ks.requests.Load())
}

func TestKeySetSingleRequest(t *testing.T) {
	ks := newTestKeySet(t)
	k1, pub1 := newSigningKey(t, "k1")
	ks.publish(pub1)
	ks.hang.Store(true)
	token := signTestJWT(t, k1, "k1")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ks.set.VerifySignature(ctx, token)
	require.ErrorIs(t, err, context.Canceled)
	assert.Eventually(t, func() bool { return ks.requests.Load() == 1 }, time.Second, 10*time.Millisecond)
	for range 10 {
		_, err := ks.set.VerifySignature(ctx, token)
		require.ErrorIs(t, err, context.Canceled)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() {
			var err error
			if i%2 == 0 {
				_, err = providerKeySet{ks.set}.VerifySignature(t.Context(), token)
			} else {
				_, err = ks.set.VerifySignature(t.Context(), token)
			}
			errs <- err
		})
	}
	ks.unblock()
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int32(1), ks.requests.Load())
}

func TestParseKeySet(t *testing.T) {
	keys, err := parseKeySet([]byte(`{"keys":[
		{"kty":"unknown","kid":"kty"},
		{"kty":"EC","kid":"curve","crv":"P-9999","x":"AQ","y":"AQ"},
		{"kty":"oct","kid":"oct","k":"c2VjcmV0"},
		{"kty":"RSA","kid":"oaep","alg":"RSA-OAEP","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"},
		{"kty":"RSA","kid":"rsa","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}
	]}`))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "rsa", keys[0].KeyID)

	_, err = parseKeySet([]byte(`{}`))
	require.ErrorIs(t, err, errNoKeys)
	_, err = parseKeySet([]byte(`{"keys":`))
	assert.Error(t, err)
}

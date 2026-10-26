// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	minKeysRefetch = 30 * time.Second
	maxKeysAge     = 10 * time.Minute
	maxKeySetSize  = 1 << 20
)

var jwsAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

var errNoVerifyingKey = errors.New("no provider key verifies the signature")

// keySet is the JSON Web Key Set of a provider. It implements [oidc.KeySet].
type keySet struct {
	fetched   time.Time
	requested time.Time
	client    *http.Client
	now       func() time.Time
	inflight  *keyFetch
	url       string
	keys      []jose.JSONWebKey
	mu        sync.Mutex
}

// keyFetch is a request of the key set. It is not canceled with the request that started it, so its keys are kept for
// the next ones.
type keyFetch struct {
	done chan struct{}
	err  error
	keys []jose.JSONWebKey
}

func newKeySet(client *http.Client, url string) *keySet {
	return &keySet{client: client, url: url, now: time.Now}
}

// VerifySignature verifies the signature of the JWT with the provider key of its key ID, or any provider key when it
// has none, and returns its payload. The claims and the algorithm are verified by the [oidc.IDTokenVerifier].
func (k *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, jwsAlgs)
	if err != nil {
		return nil, err
	}
	kid := jws.Signatures[0].Header.KeyID

	keys, fetchErr := k.keysFor(ctx, kid)
	for _, key := range keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(&key); err == nil {
			return payload, nil
		}
	}
	if fetchErr != nil {
		return nil, fmt.Errorf("%w: %w", errNoVerifyingKey, fetchErr)
	}
	return nil, errNoVerifyingKey
}

// keysFor returns the keys to verify a signature with the key ID. It requests the key set again when it has no key with
// this ID or is older than maxKeysAge, at most once every minKeysRefetch.
func (k *keySet) keysFor(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	now := k.now()
	keys := k.keys
	if hasKey(keys, kid) && now.Sub(k.fetched) < maxKeysAge {
		k.mu.Unlock()
		return keys, nil
	}
	f := k.inflight
	if f == nil {
		if now.Sub(k.requested) < minKeysRefetch {
			k.mu.Unlock()
			return keys, nil
		}
		f = &keyFetch{done: make(chan struct{})}
		k.inflight, k.requested = f, now
		go k.fetch(context.WithoutCancel(ctx), f, now)
	}
	k.mu.Unlock()

	select {
	case <-ctx.Done():
		return keys, ctx.Err()
	case <-f.done:
		if f.err != nil {
			return keys, f.err
		}
		return f.keys, nil
	}
}

func hasKey(keys []jose.JSONWebKey, kid string) bool {
	for _, key := range keys {
		if kid == "" || key.KeyID == kid {
			return true
		}
	}
	return false
}

func (k *keySet) fetch(ctx context.Context, f *keyFetch, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, minKeysRefetch)
	defer cancel()
	f.keys, f.err = k.requestKeys(ctx)

	k.mu.Lock()
	if f.err == nil {
		k.keys, k.fetched = f.keys, now
	}
	k.inflight = nil
	k.mu.Unlock()
	close(f.done)
}

func (k *keySet) requestKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetSize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key set: unexpected status %d", resp.StatusCode)
	}
	return parseKeySet(body)
}

// parseKeySet returns the public keys of the key set. It ignores the keys that cannot be used, such as a key of an
// unknown type or curve, as RFC 7517 5 recommends.
func parseKeySet(data []byte) ([]jose.JSONWebKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	keys := make([]jose.JSONWebKey, 0, len(set.Keys))
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil || !key.Valid() || !key.IsPublic() {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

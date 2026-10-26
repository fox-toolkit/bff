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
	"slices"
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

var (
	errNoVerifyingKey = errors.New("no provider key verifies the signature")
	errNoKeys         = errors.New("key set without keys member")
)

// keySet is the JSON Web Key Set of a provider. It works like the RemoteKeySet of go-oidc, with three differences:
//
//  1. A token that does not come from the provider requests the keys at most once every minKeysRefetch.
//  2. The keys older than maxKeysAge are requested again in the background.
//  3. A key that cannot be used is ignored, where go-oidc rejects the key set.
type keySet struct {
	fetched   time.Time
	requested time.Time
	client    *http.Client
	now       func() time.Time
	inflight  *inflight
	url       string
	keys      []jose.JSONWebKey
	mu        sync.Mutex
}

type inflight struct {
	done chan struct{}
	err  error
	keys []jose.JSONWebKey
}

func newKeySet(client *http.Client, url string) *keySet {
	return &keySet{client: client, url: url, now: time.Now}
}

// VerifySignature implements [oidc.KeySet] for the tokens that do not come from the provider, such as the logout
// tokens. The claims and the algorithm are verified by the [oidc.IDTokenVerifier].
func (k *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	return k.verify(ctx, jwt, false)
}

// providerKeySet implements [oidc.KeySet] for the tokens received from the provider, such as the ID tokens of the token
// endpoint.
type providerKeySet struct {
	*keySet
}

func (p providerKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	return p.verify(ctx, jwt, true)
}

func (k *keySet) verify(ctx context.Context, jwt string, fromProvider bool) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, jwsAlgs)
	if err != nil {
		return nil, err
	}

	keys, stale := k.cachedKeys()
	if payload, ok := verifyWith(jws, keys); ok {
		if stale {
			k.refresh(ctx, false)
		}
		return payload, nil
	}

	f := k.refresh(ctx, fromProvider)
	if f == nil {
		return nil, errNoVerifyingKey
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
	}
	if f.err != nil {
		return nil, fmt.Errorf("%w: %w", errNoVerifyingKey, f.err)
	}
	if payload, ok := verifyWith(jws, f.keys); ok {
		return payload, nil
	}
	return nil, errNoVerifyingKey
}

// verifyWith verifies the signature with the keys that match its key ID and algorithm (RFC 8725 3.1).
func verifyWith(jws *jose.JSONWebSignature, keys []jose.JSONWebKey) ([]byte, bool) {
	header := jws.Signatures[0].Header
	for _, key := range keys {
		if header.KeyID != "" && key.KeyID != header.KeyID || key.Algorithm != "" && key.Algorithm != header.Algorithm {
			continue
		}
		if payload, err := jws.Verify(&key); err == nil {
			return payload, true
		}
	}
	return nil, false
}

func (k *keySet) cachedKeys() ([]jose.JSONWebKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.keys, k.now().Sub(k.fetched) >= maxKeysAge
}

// refresh returns the request of the keys in flight, or starts one. Without force, it returns nil when the last request
// started less than minKeysRefetch ago.
func (k *keySet) refresh(ctx context.Context, force bool) *inflight {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.inflight != nil {
		return k.inflight
	}
	now := k.now()
	if !force && now.Sub(k.requested) < minKeysRefetch {
		return nil
	}
	f := &inflight{done: make(chan struct{})}
	k.inflight, k.requested = f, now
	go k.update(context.WithoutCancel(ctx), f, now)
	return f
}

// update requests the keys. The previous keys are kept when the request fails.
func (k *keySet) update(ctx context.Context, f *inflight, now time.Time) {
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
	req.Header.Set("Cache-Control", "no-cache")
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
// unknown type, curve or algorithm, as RFC 7517 5 recommends.
func parseKeySet(data []byte) ([]jose.JSONWebKey, error) {
	var set struct {
		Keys *[]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		return nil, errNoKeys
	}
	keys := make([]jose.JSONWebKey, 0, len(*set.Keys))
	for _, raw := range *set.Keys {
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil || !key.Valid() || !key.IsPublic() ||
			key.Algorithm != "" && !slices.Contains(jwsAlgs, jose.SignatureAlgorithm(key.Algorithm)) {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

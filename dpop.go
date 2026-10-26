// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	dpopAlg           = "ES256"
	maxNonceOrigins   = 1024
	maxNonceErrorSize = 4096
)

// dpopKey is the key a session proves the possession of, as defined by RFC 9449.
type dpopKey struct {
	private *ecdsa.PrivateKey
	// header is the encoded JOSE header of the proofs, which contains the public key.
	header string
	// jkt is the JWK thumbprint of the public key (RFC 7638).
	jkt string
}

// newDPoPKey generates a key and returns it with its raw encoding.
func newDPoPKey() (*dpopKey, []byte, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	raw, err := private.Bytes()
	if err != nil {
		return nil, nil, err
	}
	key, err := newDPoPKeyFrom(private)
	return key, raw, err
}

func parseDPoPKey(raw []byte) (*dpopKey, error) {
	private, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, err
	}
	return newDPoPKeyFrom(private)
}

func newDPoPKeyFrom(private *ecdsa.PrivateKey) (*dpopKey, error) {
	point, err := private.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:])
	// RFC 7638 3.2: the required members in lexicographic order, without whitespace.
	jwk := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(jwk))
	header := `{"typ":"dpop+jwt","alg":"` + dpopAlg + `","jwk":` + jwk + `}`
	return &dpopKey{
		private: private,
		header:  base64.RawURLEncoding.EncodeToString([]byte(header)),
		jkt:     base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	IAT   int64  `json:"iat"`
}

// proof returns a DPoP proof for the request, bound to the access token when it is not empty.
func (k *dpopKey) proof(r *http.Request, accessToken, nonce string, now time.Time) (string, error) {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	claims := dpopClaims{
		JTI:   randomString(),
		HTM:   r.Method,
		HTU:   targetOrigin(r) + path,
		IAT:   now.Unix(),
		Nonce: nonce,
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims.ATH = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	input := k.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r1, s1, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", err
	}
	// RFC 7518 3.4: the signature is R and S as two 32 bytes big-endian integers.
	var sig [64]byte
	r1.FillBytes(sig[:32])
	s1.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig[:]), nil
}

type nonceCache struct {
	nonces map[string]string
	mu     sync.Mutex
}

func newNonceCache() *nonceCache {
	return &nonceCache{nonces: make(map[string]string)}
}

func (c *nonceCache) get(origin string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nonces[origin]
}

func (c *nonceCache) set(origin, nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.nonces[origin]; !ok && len(c.nonces) >= maxNonceOrigins {
		for k := range c.nonces {
			delete(c.nonces, k)
			break
		}
	}
	c.nonces[origin] = nonce
}

// sendDPoP sends r with a DPoP proof of the key, and with the access token when it is not empty. When the server
// requires a new nonce, the request is sent again once with this nonce, if its body can be sent again.
func sendDPoP(base http.RoundTripper, nonces *nonceCache, key *dpopKey, r *http.Request, accessToken string, now time.Time) (*http.Response, error) {
	origin := targetOrigin(r)
	nonce := nonces.get(origin)
	resp, err := sendProof(base, key, r, accessToken, nonce, now)
	if err != nil {
		return nil, err
	}
	fresh := resp.Header.Get("DPoP-Nonce")
	if fresh == "" || fresh == nonce {
		return resp, nil
	}
	nonces.set(origin, fresh)
	if !replayable(r) || !requiresNonce(resp) {
		return resp, nil
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNonceErrorSize))
	_ = resp.Body.Close()
	retry := r.Clone(r.Context())
	if r.GetBody != nil {
		if retry.Body, err = r.GetBody(); err != nil {
			return nil, err
		}
	}
	resp, err = sendProof(base, key, retry, accessToken, fresh, now)
	if err != nil {
		return nil, err
	}
	if n := resp.Header.Get("DPoP-Nonce"); n != "" && n != fresh {
		nonces.set(origin, n)
	}
	return resp, nil
}

// targetOrigin returns the scheme and authority of the target URI as the server sees it, with the Host header when it
// is set (RFC 9110 7.1).
func targetOrigin(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return r.URL.Scheme + "://" + host
}

func replayable(r *http.Request) bool {
	return r.Body == nil || r.Body == http.NoBody || r.GetBody != nil
}

func sendProof(base http.RoundTripper, key *dpopKey, r *http.Request, accessToken, nonce string, now time.Time) (*http.Response, error) {
	proof, err := key.proof(r, accessToken, nonce, now)
	if err != nil {
		return nil, err
	}
	// A RoundTripper must not modify the request it is given.
	r = r.Clone(r.Context())
	r.Header.Set("DPoP", proof)
	if accessToken != "" {
		r.Header.Set("Authorization", "DPoP "+accessToken)
	}
	return base.RoundTrip(r)
}

// requiresNonce reports whether the response is a use_dpop_nonce error of a resource server (RFC 9449 9) or of an
// authorization server (RFC 9449 8). The body of an authorization server error is kept readable.
func requiresNonce(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		for _, v := range resp.Header.Values("WWW-Authenticate") {
			if strings.Contains(v, "use_dpop_nonce") {
				return true
			}
		}
	case http.StatusBadRequest:
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxNonceErrorSize))
		resp.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), Closer: resp.Body}
		var e struct {
			Error string `json:"error"`
		}
		return err == nil && json.Unmarshal(data, &e) == nil && e.Error == "use_dpop_nonce"
	}
	return false
}

type readCloser struct {
	io.Reader
	io.Closer
}

// dpopTransport sends the requests to the provider with a DPoP proof of the key, bound to the access token of a
// request authorized with the DPoP scheme, such as a UserInfo request.
type dpopTransport struct {
	base   http.RoundTripper
	key    *dpopKey
	nonces *nonceCache
	now    func() time.Time
}

func (t *dpopTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var accessToken string
	// RFC 9110 11.1: the authentication scheme is case insensitive.
	if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "DPoP") {
		accessToken = token
	}
	return sendDPoP(t.base, t.nonces, t.key, r, accessToken, t.now())
}

var errNotDPoPBound = errors.New("access token is not bound to the dpop key")

// RFC 6749 5.1: the token type is case insensitive.
func isDPoP(tokenType string) bool {
	return strings.EqualFold(tokenType, "DPoP")
}

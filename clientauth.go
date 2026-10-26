// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	clientSecretBasic = "client_secret_basic"
	privateKeyJWT     = "private_key_jwt"
	assertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	assertionLifetime = time.Minute
)

// clientAuth authenticates the requests of the client to the provider, with client_secret_basic (RFC 6749 2.3.1) or
// private_key_jwt (OpenID Connect Core 9, RFC 7523).
type clientAuth struct {
	key      crypto.Signer
	id       string
	secret   string
	keyID    string
	alg      string
	audience string
}

func newClientAuth(c Client, p *Provider) (clientAuth, error) {
	auth := clientAuth{id: c.ClientID, secret: c.ClientSecret, key: c.ClientKey, keyID: c.ClientKeyID, audience: p.issuer}
	method := clientSecretBasic
	if auth.key != nil {
		method = privateKeyJWT
	}
	// RFC 8414 2: the default authentication method is client_secret_basic.
	methods := p.authMethods
	if len(methods) == 0 {
		methods = []string{clientSecretBasic}
	}
	if !slices.Contains(methods, method) {
		return clientAuth{}, fmt.Errorf("%w: provider does not support %s", ErrInvalidConfig, method)
	}
	if auth.key == nil {
		return auth, nil
	}

	algs := clientKeyAlgs(auth.key.Public())
	auth.alg = algs[0]
	if len(p.authAlgs) > 0 {
		i := slices.IndexFunc(algs, func(alg string) bool { return slices.Contains(p.authAlgs, alg) })
		if i < 0 {
			return clientAuth{}, fmt.Errorf("%w: provider does not support the algorithm of the client key", ErrInvalidConfig)
		}
		auth.alg = algs[i]
	}
	return auth, nil
}

// clientKeyAlgs returns the algorithms of a client key, in order of preference.
func clientKeyAlgs(pub crypto.PublicKey) []string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return []string{"ES256"}
		}
	case *rsa.PublicKey:
		// FAPI 2.0 Security Profile 5.4.1: RSA keys have at least 2048 bits.
		if k.N.BitLen() >= 2048 {
			return []string{"PS256", "RS256"}
		}
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	}
	return nil
}

// newRequest returns a POST request of the form to the endpoint, authenticated as the client.
func (a *clientAuth) newRequest(ctx context.Context, endpoint string, form url.Values, now func() time.Time) (*http.Request, error) {
	if a.key == nil {
		req, err := newFormRequest(ctx, endpoint, form.Encode())
		if err != nil {
			return nil, err
		}
		// RFC 6749 2.3.1: the client credentials are form-encoded before being used for basic authentication.
		req.SetBasicAuth(url.QueryEscape(a.id), url.QueryEscape(a.secret))
		return req, nil
	}

	body, err := a.assertionForm(form, now())
	if err != nil {
		return nil, err
	}
	req, err := newFormRequest(ctx, endpoint, body)
	if err != nil {
		return nil, err
	}
	// OpenID Connect Core 9: an assertion is used only once, so a request sent again, such as after a DPoP nonce
	// error, carries a new one.
	req.GetBody = func() (io.ReadCloser, error) {
		retry, err := a.assertionForm(form, now())
		if err != nil {
			return nil, err
		}
		if len(retry) != len(body) {
			return nil, errAssertionSize
		}
		return io.NopCloser(strings.NewReader(retry)), nil
	}
	return req, nil
}

var errAssertionSize = errors.New("client assertion size changed")

// assertionForm returns the encoded form with a new client assertion.
func (a *clientAuth) assertionForm(form url.Values, now time.Time) (string, error) {
	assertion, err := a.assertion(now)
	if err != nil {
		return "", err
	}
	form = cloneValues(form)
	form.Set("client_id", a.id)
	form.Set("client_assertion_type", assertionType)
	form.Set("client_assertion", assertion)
	return form.Encode(), nil
}

func newFormRequest(ctx context.Context, endpoint, body string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// assertion returns a client authentication JWT. The audience is the issuer, as required by the FAPI 2.0 Security
// Profile and draft-ietf-oauth-rfc7523bis.
func (a *clientAuth) assertion(now time.Time) (string, error) {
	header, err := json.Marshal(struct {
		Alg   string `json:"alg"`
		Typ   string `json:"typ"`
		KeyID string `json:"kid,omitempty"`
	}{Alg: a.alg, Typ: "client-authentication+jwt", KeyID: a.keyID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		JTI      string `json:"jti"`
		IAT      int64  `json:"iat"`
		EXP      int64  `json:"exp"`
	}{
		Issuer:   a.id,
		Subject:  a.id,
		Audience: a.audience,
		JTI:      randomString(),
		IAT:      now.Unix(),
		EXP:      now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}

	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := signJWS(a.key, a.alg, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

var errInvalidSignature = errors.New("invalid ecdsa signature")

// signJWS returns the JWS signature of the input (RFC 7518 3).
func signJWS(key crypto.Signer, alg string, input []byte) ([]byte, error) {
	if alg == "EdDSA" {
		return key.Sign(rand.Reader, input, crypto.Hash(0))
	}
	digest := sha256.Sum256(input)
	switch alg {
	case "ES256":
		der, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		// RFC 7518 3.4: the signature is R and S as two 32 bytes big-endian integers.
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 || rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
			return nil, errInvalidSignature
		}
		sig := make([]byte, 64)
		rs.R.FillBytes(sig[:32])
		rs.S.FillBytes(sig[32:])
		return sig, nil
	case "PS256":
		// RFC 7518 3.5: the salt has the size of the hash.
		return key.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	default:
		return key.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}

func cloneValues(v url.Values) url.Values {
	c := make(url.Values, len(v)+3)
	for k, vv := range v {
		c[k] = slices.Clone(vv)
	}
	return c
}

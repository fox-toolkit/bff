// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package conformance

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/fox-toolkit/fox"
	"github.com/fox-toolkit/rp"
	"github.com/fox-toolkit/rp/store/memory"
	rpredis "github.com/fox-toolkit/rp/store/redis"
	goredis "github.com/redis/go-redis/v9"
)

const resource = "https://api.example.com/"

var insecure = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

type bffConfig struct {
	plan     plan
	setup    setup
	module   string
	issuer   string
	baseURL  string
	clientID string
	secret   string
	scopes   []string
	key      *ecdsa.PrivateKey
	redis    *goredis.Client
	log      io.Writer
}

// newBFF returns the BFF for the issuer of a module. It reads the provider metadata, like a real deployment at
// startup, so it fails for a module that serves invalid metadata.
func newBFF(cfg bffConfig) (http.Handler, error) {
	logger := slog.NewTextHandler(cfg.log, &slog.HandlerOptions{Level: slog.LevelDebug})
	provider, err := rp.NewProvider(context.Background(), cfg.issuer,
		rp.WithHTTPClient(&http.Client{Timeout: 10 * time.Second, Transport: insecure}))
	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}

	client := rp.Client{
		Provider:              provider,
		ClientID:              cfg.clientID,
		ClientSecret:          cfg.secret,
		RedirectURL:           cfg.baseURL + "/bff/callback",
		PostLogoutRedirectURL: cfg.baseURL + "/",
		Scopes:                cfg.scopes,
	}
	if cfg.key != nil {
		client.ClientKey = cfg.key
		client.ClientKeyID = keyID(cfg.key)
	}
	opts := append(cfg.plan.options(cfg.module), rp.WithLogHandler(logger))
	switch cfg.setup.store {
	case "memory":
		opts = append(opts, rp.WithStore(memory.NewStore()))
	case "redis":
		s, err := rpredis.NewStore(cfg.redis, rpredis.WithKeyPrefix("bff-conformance:"+cfg.issuer+":"))
		if err != nil {
			return nil, fmt.Errorf("redis: %w", err)
		}
		opts = append(opts, rp.WithStore(s))
	}
	if cfg.setup.resource {
		opts = append(opts, rp.WithResources(resource))
	}
	fe, err := rp.NewFrontend(client, newAEAD(), opts...)
	if err != nil {
		return nil, fmt.Errorf("frontend: %w", err)
	}

	// /api/{path} is proxied to {issuer}{path}, such as the FAPI accounts resource or the userinfo endpoint.
	target, err := url.Parse(cfg.issuer)
	if err != nil {
		return nil, err
	}
	transport := rp.Transport(insecure)
	apiOpts := []fox.RouteOption{fox.WithMiddleware(fe.Authenticate())}
	if cfg.setup.resource {
		transport = rp.ResourceTransport(insecure, resource)
		apiOpts = append(apiOpts, rp.ForResource(resource))
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.URL.Path = path.Join(target.Path, strings.TrimPrefix(r.In.URL.Path, "/api/"))
			r.Out.URL.RawPath = ""
		},
		Transport: transport,
	}

	f := fox.MustRouter(fox.WithMiddleware(fox.Logger(logger)))
	f.MustAdd(fox.MethodGet, "/bff/login", fe.LoginHandler())
	f.MustAdd(fox.MethodGet, "/bff/callback", fe.CallbackHandler())
	f.MustAdd([]string{http.MethodGet, http.MethodPost}, "/bff/logout", fe.LogoutHandler())
	f.MustAdd(fox.MethodGet, "/bff/user", fe.UserHandler())
	if cfg.setup.store != "stateless" {
		f.MustAdd(fox.MethodPost, "/bff/backchannel", fe.BackchannelHandler())
	}
	f.MustAdd(fox.MethodAny, "/api/*{any}", fox.WrapH(proxy), apiOpts...)
	f.MustAdd(fox.MethodGet, "/", func(c *fox.Context) { _ = c.String(http.StatusOK, "bff\n") })
	return f, nil
}

type aead struct{ cipher.AEAD }

func newAEAD() aead {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(err)
	}
	return aead{gcm}
}

func (a aead) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.Seal(nil, nil, plaintext, associatedData), nil
}

func (a aead) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.Open(nil, nil, ciphertext, associatedData)
}

func publicJWK(key *ecdsa.PrivateKey) map[string]string {
	point, err := key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(point[33:]),
		"kid": keyID(key),
		"alg": "ES256",
		"use": "sig",
	}
}

func keyID(key *ecdsa.PrivateKey) string {
	point, err := key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(point)
	return hex.EncodeToString(sum[:8])
}

type browser struct {
	client  *http.Client
	baseURL string
	flow    io.Writer
}

func newBrowser(baseURL string, flow io.Writer) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &browser{
		client:  &http.Client{Timeout: 30 * time.Second, Transport: insecure, Jar: localhostJar{jar}},
		baseURL: baseURL,
		flow:    flow,
	}
}

func (b *browser) login() {
	resp, err := b.client.Get(b.baseURL + "/bff/login?returnUrl=/")
	b.record("login", resp, err)
}

func (b *browser) get(p string) {
	req, err := http.NewRequest(http.MethodGet, b.baseURL+p, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.client.Do(req)
	b.record("GET "+p, resp, err)
}

func (b *browser) logout() {
	req, err := http.NewRequest(http.MethodGet, b.baseURL+"/bff/user", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	var user struct {
		LogoutCSRFToken string `json:"logoutCsrfToken"`
	}
	if resp, err := b.client.Do(req); err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&user)
		_ = resp.Body.Close()
	}
	req, err = http.NewRequest(http.MethodPost, b.baseURL+"/bff/logout",
		strings.NewReader(url.Values{"csrf_token": {user.LogoutCSRFToken}}.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := b.client.Do(req)
	b.record("logout", resp, err)
}

func (b *browser) record(step string, resp *http.Response, err error) {
	if err != nil {
		_, _ = fmt.Fprintf(b.flow, "%s: %v\n", step, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
	_, _ = fmt.Fprintf(b.flow, "%s: %d %s\n%s\n", step, resp.StatusCode, resp.Request.URL, body)
}

// localhostJar sends the Secure cookies to http://localhost, like the browsers do.
type localhostJar struct{ http.CookieJar }

func (j localhostJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.CookieJar.SetCookies(secureLocalhost(u), cookies)
}

func (j localhostJar) Cookies(u *url.URL) []*http.Cookie {
	return j.CookieJar.Cookies(secureLocalhost(u))
}

func secureLocalhost(u *url.URL) *url.URL {
	if u.Scheme != "http" || u.Hostname() != "localhost" {
		return u
	}
	s := *u
	s.Scheme = "https"
	return &s
}

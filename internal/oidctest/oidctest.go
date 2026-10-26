// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

// Package oidctest provides an OpenID Connect provider for tests. It logs in every authorization request as the
// configured user, unless the user is logged out and the request asks for prompt=none.
package oidctest

import (
	"cmp"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	ClientSecret = "secret"
	keyID        = "test"
)

var signingKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// Options configures a [Server]. Every field can be changed while the server runs, with [Server.Update].
type Options struct {
	// Metadata is added to the discovery document. A nil value removes a field.
	Metadata map[string]any
	// Claims are added to the ID tokens.
	Claims map[string]any
	// UserInfo is added to the UserInfo response.
	UserInfo map[string]any
	// ISS is the iss parameter of the authorization response, sent when the discovery document advertises it. The
	// default is the issuer.
	ISS     string
	Subject string
	SID     string
	// AccessTokenTTL is the lifetime of the access tokens. The default is 5 minutes.
	AccessTokenTTL time.Duration
	// RotateRefreshTokens issues a new refresh token on every refresh. Reusing a refresh token then revokes every
	// token issued from it.
	RotateRefreshTokens bool
	LoggedOut           bool
	// Plain serves the provider over HTTP, for browser tests. It is read once by [NewServer].
	Plain bool
}

// EndSession is a request to the end session endpoint.
type EndSession struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	ClientID              string
}

// Server is an OpenID Connect provider served over TLS.
type Server struct {
	*httptest.Server
	codes       map[string]grant
	refresh     map[string]*grant
	access      map[string]grant
	revoked     []string
	endSessions []EndSession
	opts        Options
	mu          sync.Mutex
}

type grant struct {
	family      *bool // set to true when the family is revoked
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
	subject     string
	sid         string
	used        bool
}

// NewServer starts a [Server].
func NewServer(opts Options) *Server {
	s := &Server{
		opts:    opts,
		codes:   make(map[string]grant),
		refresh: make(map[string]*grant),
		access:  make(map[string]grant),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /userinfo", s.userInfo)
	mux.HandleFunc("POST /revoke", s.revoke)
	mux.HandleFunc("GET /end_session", s.endSession)
	if opts.Plain {
		s.Server = httptest.NewServer(mux)
	} else {
		s.Server = httptest.NewTLSServer(mux)
	}
	return s
}

// Update changes the options of a running server.
func (s *Server) Update(fn func(o *Options)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.opts)
}

// Revoked returns the tokens revoked through the revocation endpoint.
func (s *Server) Revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revoked...)
}

// EndSessions returns the requests received by the end session endpoint.
func (s *Server) EndSessions() []EndSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]EndSession(nil), s.endSessions...)
}

// Sign returns a JWT with the given claims and typ header, signed by the provider key.
func (s *Server) Sign(typ string, claims map[string]any) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signingKey(), KeyID: keyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		panic(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return token
}

// LogoutToken returns a valid back-channel logout token for the client. An empty sub or sid is omitted.
func (s *Server) LogoutToken(clientID, sub, sid string) string {
	now := time.Now()
	claims := map[string]any{
		"iss":    s.URL,
		"aud":    clientID,
		"iat":    now.Unix(),
		"exp":    now.Add(2 * time.Minute).Unix(),
		"jti":    randomString(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}
	return s.Sign("logout+jwt", claims)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"jwks_uri":                              s.URL + "/jwks",
		"userinfo_endpoint":                     s.URL + "/userinfo",
		"revocation_endpoint":                   s.URL + "/revoke",
		"end_session_endpoint":                  s.URL + "/end_session",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	s.mu.Lock()
	maps.Copy(doc, s.opts.Metadata)
	s.mu.Unlock()
	maps.DeleteFunc(doc, func(_ string, v any) bool { return v == nil })
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &signingKey().PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || !redirectURI.IsAbs() {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("code_challenge") == "" ||
		q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	params := url.Values{"state": {q.Get("state")}}
	if supported, _ := s.opts.Metadata["authorization_response_iss_parameter_supported"].(bool); supported {
		params.Set("iss", cmp.Or(s.opts.ISS, s.URL))
	}
	if s.opts.LoggedOut && q.Get("prompt") == "none" {
		params.Set("error", "login_required")
	} else {
		code := randomString()
		s.codes[code] = grant{
			clientID:    q.Get("client_id"),
			redirectURI: q.Get("redirect_uri"),
			nonce:       q.Get("nonce"),
			challenge:   q.Get("code_challenge"),
			subject:     s.opts.Subject,
			sid:         s.opts.SID,
		}
		params.Set("code", code)
	}
	redirectURI.RawQuery = params.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound) //nolint:gosec // test provider, any client redirect URI is accepted
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	clientID, ok := s.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var g grant
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		g, ok = s.codes[code]
		delete(s.codes, code)
		if !ok || g.clientID != clientID || g.redirectURI != r.PostForm.Get("redirect_uri") ||
			!verifyChallenge(r.PostForm.Get("code_verifier"), g.challenge) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		g.family = new(false)
	case "refresh_token":
		prev, ok := s.refresh[r.PostForm.Get("refresh_token")]
		if !ok || prev.clientID != clientID || *prev.family || prev.used {
			if ok && prev.used {
				*prev.family = true
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		if s.opts.RotateRefreshTokens {
			prev.used = true
		}
		g = *prev
		g.nonce = ""
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}

	now := time.Now()
	ttl := s.opts.AccessTokenTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	accessToken := randomString()
	s.access[accessToken] = g

	refreshToken := r.PostForm.Get("refresh_token")
	if refreshToken == "" || s.opts.RotateRefreshTokens {
		refreshToken = randomString()
		g.used = false
		s.refresh[refreshToken] = &g
	}

	claims := map[string]any{
		"iss": s.URL,
		"aud": clientID,
		"sub": g.subject,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	if g.sid != "" {
		claims["sid"] = g.sid
	}
	maps.Copy(claims, s.opts.Claims)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refreshToken,
		"id_token":      s.Sign("JWT", claims),
	})
}

func (s *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, found := s.access[token]
	if !ok || !found {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	info := map[string]any{"sub": g.subject}
	maps.Copy(info, s.opts.UserInfo)
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	token := r.PostForm.Get("token")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, token)
	if g, ok := s.refresh[token]; ok {
		*g.family = true
	}
	delete(s.access, token)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.endSessions = append(s.endSessions, EndSession{
		IDTokenHint:           q.Get("id_token_hint"),
		PostLogoutRedirectURI: q.Get("post_logout_redirect_uri"),
		ClientID:              q.Get("client_id"),
	})
	s.opts.LoggedOut = true
	s.mu.Unlock()

	if uri := q.Get("post_logout_redirect_uri"); uri != "" {
		http.Redirect(w, r, uri, http.StatusFound) //nolint:gosec // test provider, any post logout URI is accepted
		return
	}
	w.WriteHeader(http.StatusOK)
}

// authenticate checks client_secret_basic or client_secret_post and returns the client ID.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	if err := r.ParseForm(); err != nil {
		return "", false
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return id, id != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(ClientSecret)) == 1
}

func verifyChallenge(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return verifier != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

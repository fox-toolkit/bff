// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

// Package oidctest provides an OpenID Connect provider for tests. It logs in every authorization request as the
// configured user, unless the user is logged out and the request asks for prompt=none.
package oidctest

import (
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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
	// ClientKey is the public key that verifies the private_key_jwt assertions and the request objects of the clients.
	ClientKey crypto.PublicKey
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
	// DPoPNonce is the nonce the token endpoint requires in the DPoP proofs, when it is not empty.
	DPoPNonce string
	// AccessTokenTTL is the lifetime of the access tokens. The default is 5 minutes.
	AccessTokenTTL time.Duration
	// RotateRefreshTokens issues a new refresh token on every refresh. Reusing a refresh token then revokes every
	// token issued from it.
	RotateRefreshTokens bool
	LoggedOut           bool
	// PAR advertises the pushed authorization request endpoint.
	PAR bool
	// IgnoreDPoP issues bearer access tokens to the requests with a DPoP proof.
	IgnoreDPoP bool
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
	pushed      map[string]url.Values
	refresh     map[string]*grant
	access      map[string]grant
	jtis        map[string]bool
	revoked     []string
	endSessions []EndSession
	assertions  []Assertion
	requests    []RequestObject
	opts        Options
	mu          sync.Mutex
}

type grant struct {
	family      *bool // set to true when the family is revoked
	clientID    string
	dpopJKT     string
	jkt         string
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
		pushed:  make(map[string]url.Values),
		jtis:    make(map[string]bool),
		refresh: make(map[string]*grant),
		access:  make(map[string]grant),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /par", s.par)
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

// Assertion is a private_key_jwt assertion accepted by the provider.
type Assertion struct {
	Path  string
	Alg   string
	KeyID string
}

// Assertions returns the private_key_jwt assertions accepted by the provider.
func (s *Server) Assertions() []Assertion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Assertion(nil), s.assertions...)
}

// RequestObject is a request object accepted by the pushed authorization request endpoint.
type RequestObject struct {
	Claims map[string]any
	Alg    string
	KeyID  string
}

// RequestObjects returns the request objects accepted by the provider.
func (s *Server) RequestObjects() []RequestObject {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RequestObject(nil), s.requests...)
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
	if s.opts.PAR {
		doc["pushed_authorization_request_endpoint"] = s.URL + "/par"
	}
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

func (s *Server) par(w http.ResponseWriter, r *http.Request) {
	clientID, ok := s.authenticate(r)
	if !ok || r.PostForm.Get("client_id") != clientID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	params := r.PostForm
	if r.PostForm.Has("request") {
		var err error
		if params, err = s.verifyRequestObject(r.PostForm, clientID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request_object", "error_description": err.Error()})
			return
		}
	} else if s.metadataBool("require_signed_request_object") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "request object required"})
		return
	}
	requestURI := "urn:ietf:params:oauth:request_uri:" + randomString()
	s.mu.Lock()
	s.pushed[requestURI] = params
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": requestURI, "expires_in": 60})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if requestURI := q.Get("request_uri"); requestURI != "" {
		s.mu.Lock()
		pushed, ok := s.pushed[requestURI]
		delete(s.pushed, requestURI)
		s.mu.Unlock()
		if !ok || pushed.Get("client_id") != q.Get("client_id") {
			http.Error(w, "invalid request_uri", http.StatusBadRequest)
			return
		}
		q = pushed
	} else if s.metadataBool("require_pushed_authorization_requests") || s.metadataBool("require_signed_request_object") {
		http.Error(w, "pushed authorization request required", http.StatusBadRequest)
		return
	}
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
			dpopJKT:     q.Get("dpop_jkt"),
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
	var jkt string
	if r.Header.Get("DPoP") != "" && !s.opts.IgnoreDPoP {
		var err error
		jkt, err = VerifyDPoPProof(r, "", s.opts.DPoPNonce)
		if errors.Is(err, ErrDPoPNonce) {
			w.Header().Set("DPoP-Nonce", s.opts.DPoPNonce)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_dpop_proof"})
			return
		}
	}

	var g grant
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code := r.PostForm.Get("code")
		g, ok = s.codes[code]
		delete(s.codes, code)
		if !ok || g.clientID != clientID || g.redirectURI != r.PostForm.Get("redirect_uri") ||
			!verifyChallenge(r.PostForm.Get("code_verifier"), g.challenge) || g.dpopJKT != "" && !s.opts.IgnoreDPoP && g.dpopJKT != jkt {
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

	g.jkt = jkt
	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
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
		"token_type":    tokenType,
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refreshToken,
		"id_token":      s.Sign("JWT", claims),
	})
}

func (s *Server) userInfo(w http.ResponseWriter, r *http.Request) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	s.mu.Lock()
	defer s.mu.Unlock()
	g, found := s.access[token]
	if found && g.jkt != "" {
		jkt, err := VerifyDPoPProof(r, token, "")
		ok = ok && scheme == "DPoP" && err == nil && jkt == g.jkt
	} else {
		ok = ok && strings.EqualFold(scheme, "Bearer")
	}
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

func (s *Server) metadataBool(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, _ := s.opts.Metadata[name].(bool)
	return v
}

// supportedAlg reports whether the alg is in the metadata list, or the list is not set. It must be called with the
// lock held.
func (s *Server) supportedAlg(name, alg string) bool {
	algs, ok := s.opts.Metadata[name].([]string)
	return !ok || slices.Contains(algs, alg)
}

// verifyRequestObject verifies a pushed request object as required by RFC 9126 3 and the FAPI 2.0 Message Signing
// profile, and returns its authorization parameters.
func (s *Server) verifyRequestObject(form url.Values, clientID string) (url.Values, error) {
	for k := range form {
		switch k {
		case "request", "client_id", "client_assertion_type", "client_assertion":
		default:
			return nil, errors.New("parameter outside the request object: " + k)
		}
	}
	algs := []jose.SignatureAlgorithm{jose.ES256, jose.PS256, jose.RS256, jose.EdDSA}
	jws, err := jose.ParseSigned(form.Get("request"), algs)
	if err != nil {
		return nil, err
	}
	header := jws.Signatures[0].Protected
	s.mu.Lock()
	defer s.mu.Unlock()
	if header.ExtraHeaders[jose.HeaderType] != "oauth-authz-req+jwt" || s.opts.ClientKey == nil ||
		!s.supportedAlg("request_object_signing_alg_values_supported", header.Algorithm) {
		return nil, errors.New("invalid header")
	}
	payload, err := jws.Verify(s.opts.ClientKey)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	nbf, _ := claims["nbf"].(float64)
	exp, _ := claims["exp"].(float64)
	now := float64(time.Now().Unix())
	switch {
	case claims["aud"] != s.URL, claims["client_id"] != clientID:
		return nil, errors.New("invalid aud or client_id")
	case nbf == 0 || nbf > now || now-nbf > 3600 || exp <= now || exp-nbf > 3600:
		return nil, errors.New("invalid nbf or exp")
	case claims["request"] != nil || claims["request_uri"] != nil:
		return nil, errors.New("nested request")
	}
	params := make(url.Values)
	for k, v := range claims {
		switch k {
		case "iss", "aud", "nbf", "exp", "iat", "jti":
			continue
		}
		str, ok := v.(string)
		if !ok {
			return nil, errors.New("non string parameter: " + k)
		}
		params.Set(k, str)
	}
	s.requests = append(s.requests, RequestObject{Claims: claims, Alg: header.Algorithm, KeyID: header.KeyID})
	return params, nil
}

// authenticate checks client_secret_basic or client_secret_post and returns the client ID.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	if err := r.ParseForm(); err != nil {
		return "", false
	}
	if r.PostForm.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return s.verifyAssertion(r)
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

// verifyAssertion verifies a private_key_jwt assertion with the audience required by draft-ietf-oauth-rfc7523bis and
// returns the client ID.
func (s *Server) verifyAssertion(r *http.Request) (string, bool) {
	algs := []jose.SignatureAlgorithm{jose.ES256, jose.PS256, jose.RS256, jose.EdDSA}
	jws, err := jose.ParseSigned(r.PostForm.Get("client_assertion"), algs)
	if err != nil {
		return "", false
	}
	header := jws.Signatures[0].Protected
	s.mu.Lock()
	defer s.mu.Unlock()
	if header.ExtraHeaders[jose.HeaderType] != "client-authentication+jwt" || s.opts.ClientKey == nil ||
		!s.supportedAlg("token_endpoint_auth_signing_alg_values_supported", header.Algorithm) {
		return "", false
	}
	payload, err := jws.Verify(s.opts.ClientKey)
	if err != nil {
		return "", false
	}
	var claims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience any    `json:"aud"`
		JTI      string `json:"jti"`
		EXP      int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Issuer == "" || claims.Subject != claims.Issuer || claims.Audience != s.URL || claims.JTI == "" ||
		s.jtis[claims.JTI] || time.Now().After(time.Unix(claims.EXP, 0)) {
		return "", false
	}
	if id := r.PostForm.Get("client_id"); id != "" && id != claims.Issuer {
		return "", false
	}
	s.jtis[claims.JTI] = true
	s.assertions = append(s.assertions, Assertion{Path: r.URL.Path, Alg: header.Algorithm, KeyID: header.KeyID})
	return claims.Issuer, true
}

func verifyChallenge(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return verifier != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// ErrDPoPNonce is returned by [VerifyDPoPProof] when the proof does not have the required nonce.
var ErrDPoPNonce = errors.New("dpop nonce required")

// VerifyDPoPProof verifies the DPoP proof of a request received by a server, as defined by RFC 9449 4.3, and returns
// the JWK thumbprint of its key. The proof must be bound to the access token and have the nonce when they are not empty.
func VerifyDPoPProof(r *http.Request, accessToken, nonce string) (string, error) {
	jws, err := jose.ParseSigned(r.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", err
	}
	header := jws.Signatures[0].Protected
	jwk := header.JSONWebKey
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" || jwk == nil || !jwk.IsPublic() {
		return "", errors.New("invalid proof header")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", err
	}
	var claims struct {
		JTI   string `json:"jti"`
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		ATH   string `json:"ath"`
		Nonce string `json:"nonce"`
		IAT   int64  `json:"iat"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	sum := sha256.Sum256([]byte(accessToken))
	switch {
	case claims.JTI == "", claims.HTM != r.Method, claims.HTU != scheme+"://"+r.Host+r.URL.EscapedPath():
		return "", errors.New("invalid proof claims")
	case time.Since(time.Unix(claims.IAT, 0)).Abs() > time.Minute:
		return "", errors.New("proof expired")
	case accessToken != "" && claims.ATH != base64.RawURLEncoding.EncodeToString(sum[:]):
		return "", errors.New("proof not bound to the access token")
	case nonce != "" && claims.Nonce != nonce:
		return "", ErrDPoPNonce
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
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

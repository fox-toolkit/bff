// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"cmp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/fox"
	"golang.org/x/oauth2"
)

const (
	loginTimeout = 15 * time.Minute
	// maxPendingLogins bounds the login cookies of a browser, which abandoned or forced logins would pile up.
	maxPendingLogins = 3
	// maxReturnURL bounds the return URL in the login cookie. A page of another site can choose it, and escaped JSON
	// characters such as & take 6 bytes.
	maxReturnURL = 1024
	// maxACRValues bounds the acr_values in the login cookie, once encoded as JSON.
	maxACRValues       = 256
	maxPARResponseSize = 1 << 16
	// authTimeSkew tolerates the clock difference between the provider and the client when checking auth_time.
	authTimeSkew = time.Minute
)

// standardPrompts are accepted when the provider does not advertise its prompt values.
var standardPrompts = []string{"none", "login", "consent", "select_account"}

type loginState struct {
	// MaxAge is a pointer, so max_age=0 is still checked.
	MaxAge    *int64 `json:"m,omitempty"`
	Verifier  string `json:"v"`
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
	ACRValues string `json:"a,omitempty"`
	DPoPKey   []byte `json:"k,omitempty"`
	// Created is in nanoseconds, so logins started in the same second are ordered.
	Created int64 `json:"t"`
}

// LoginHandler returns a handler that starts the authorization code flow with the provider. The browser must open it
// with a top-level navigation, because the flow redirects the browser to the provider. After login, the browser is
// redirected to the URL in the returnUrl query parameter, or to "/" if it is absent. The return URL must be a local URL
// or a URL of a trusted origin (see [WithTrustedOrigins]), of at most 1024 bytes once encoded as JSON. The optional
// prompt, max_age and acr_values query parameters are passed to the provider, such as prompt=none for a silent login.
//
// When Pushed Authorization Requests (PAR, RFC 9126) are used, each login sends a request to the pushed authorization
// request endpoint of the provider, so the route should be rate limited. If this request fails, the handler responds
// with 502 Bad Gateway.
func (fe *Frontend) LoginHandler() fox.HandlerFunc {
	rp := fe.rp
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")

		q := r.URL.Query()
		returnURL := q.Get("returnUrl")
		if returnURL == "" {
			returnURL = "/"
		} else if encoded, _ := json.Marshal(returnURL); len(encoded)-2 > maxReturnURL ||
			!localURL(returnURL) && !rp.trustedURL(returnURL) {
			rp.logRejected(r, "invalid return url", nil)
			badRequest(w)
			return
		}
		prompt := q.Get("prompt")
		if prompt != "" && !rp.validPrompt(prompt) {
			rp.logRejected(r, "invalid prompt", nil)
			badRequest(w)
			return
		}
		var maxAge *int64
		if v := q.Get("max_age"); v != "" {
			// ParseUint rejects a sign, and 32 bits keep the duration in range.
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				rp.logRejected(r, "invalid max_age", nil)
				badRequest(w)
				return
			}
			maxAge = new(int64(n))
		}
		acrValues := q.Get("acr_values")
		if acrValues != "" && !rp.validACRValues(acrValues) {
			rp.logRejected(r, "invalid acr_values", nil)
			badRequest(w)
			return
		}
		rp.startLogin(w, r, loginState{ReturnURL: returnURL, MaxAge: maxAge, ACRValues: acrValues}, prompt)
	}
}

// startLogin redirects to the provider to start the authorization code flow, with the return URL, max_age and
// acr_values of ls.
func (rp *relyingParty) startLogin(w http.ResponseWriter, r *http.Request, ls loginState, prompt string) {
	state := randomString()
	ls.Verifier = oauth2.GenerateVerifier()
	ls.Nonce = randomString()
	ls.Created = rp.now().UnixNano()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {rp.oauth2.ClientID},
		"redirect_uri":          {rp.oauth2.RedirectURL},
		"scope":                 {strings.Join(rp.oauth2.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {ls.Nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(ls.Verifier)},
		"code_challenge_method": {"S256"},
	}
	if prompt != "" {
		params.Set("prompt", prompt)
	}
	if ls.MaxAge != nil {
		params.Set("max_age", strconv.FormatInt(*ls.MaxAge, 10))
	}
	if ls.ACRValues != "" {
		params.Set("acr_values", ls.ACRValues)
	}
	if len(rp.cfg.resources) > 0 {
		// RFC 8707 2.1: the resources apply to the full grant, so their access tokens are requested with the
		// refresh token.
		params["resource"] = slices.Clone(rp.cfg.resources)
	}
	if rp.cfg.dpop {
		key, raw, err := newDPoPKey()
		if err != nil {
			rp.logFailed(r, "dpop key", err)
			internalError(w)
			return
		}
		ls.DPoPKey = raw
		// RFC 9449 10: the authorization code is bound to the key.
		params.Set("dpop_jkt", key.jkt)
	}
	if rp.parEndpoint != "" {
		requestURI, err := rp.pushAuthorizationRequest(r.Context(), params)
		if err != nil {
			rp.logFailed(r, "pushed authorization request", err)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		params = url.Values{"client_id": {rp.oauth2.ClientID}, "request_uri": {requestURI}}
	}

	rp.trimPendingLogins(w.Header(), r.Cookies())
	data, err := json.Marshal(ls)
	if err == nil {
		err = rp.loginCookie(state).write(w.Header(), rp.aead, data, int(loginTimeout.Seconds()), 0)
	}
	if err != nil {
		rp.logFailed(r, "login cookie", err)
		internalError(w)
		return
	}

	authURL := rp.oauth2.Endpoint.AuthURL
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, authURL+sep+params.Encode(), http.StatusFound)
}

// pushAuthorizationRequest pushes the authorization request to the provider, as defined by RFC 9126, and returns its
// request URI.
func (rp *relyingParty) pushAuthorizationRequest(ctx context.Context, params url.Values) (string, error) {
	if rp.requestObjectAlg != "" {
		// RFC 9126 3: the form only has the request object and the parameters of the client authentication.
		request, err := rp.auth.requestObject(params, rp.requestObjectAlg, rp.now())
		if err != nil {
			return "", err
		}
		params = url.Values{"request": {request}}
	}
	req, err := rp.auth.newRequest(ctx, rp.parEndpoint, params, rp.now)
	if err != nil {
		return "", err
	}
	resp, err := rp.provider.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPARResponseSize))
	if err != nil {
		return "", err
	}
	// RFC 9126 2.2 defines 201 Created, some providers respond with 200 OK.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		return "", fmt.Errorf("unexpected status %d: %s %s", resp.StatusCode, e.Error, e.Description)
	}
	var res struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	if res.RequestURI == "" {
		return "", errors.New("no request uri")
	}
	return res.RequestURI, nil
}

// trimPendingLogins deletes the login cookies of the oldest pending logins, keeping room for a new one.
func (rp *relyingParty) trimPendingLogins(h http.Header, cookies []*http.Cookie) {
	type pending struct {
		spec    cookieSpec
		created int64
		chunks  int
	}
	var logins []pending
	seen := make(map[string]bool)
	for _, c := range cookies {
		name, ok := strings.CutPrefix(c.Name, rp.loginCookie("").name)
		if !ok {
			continue
		}
		id, _, _ := strings.Cut(name, ".")
		if seen[id] {
			continue
		}
		seen[id] = true
		spec := rp.loginCookie(id)
		data, chunks, err := spec.read(cookies, rp.aead)
		var ls loginState
		if err != nil || json.Unmarshal(data, &ls) != nil {
			spec.clear(h, max(chunks, 1))
			continue
		}
		logins = append(logins, pending{spec: spec, created: ls.Created, chunks: chunks})
	}
	if len(logins) < maxPendingLogins {
		return
	}
	slices.SortFunc(logins, func(a, b pending) int { return cmp.Compare(b.created, a.created) })
	for _, l := range logins[maxPendingLogins-1:] {
		l.spec.clear(h, l.chunks)
	}
}

// CallbackHandler returns the handler of the redirect URL. It completes the login, creates a new session and redirects
// to the return URL. If the provider returns an error, such as login_required for prompt=none, it redirects to the
// return URL without a new session.
func (fe *Frontend) CallbackHandler() fox.HandlerFunc {
	return fe.rp.callbackHandler(nil, false)
}

// callbackHandler returns the handler of the redirect URL. When allow is not nil and returns false for the new session,
// the login is refused with 403 Forbidden. An error of the provider is answered with 403 Forbidden when forbidError is
// true, and with a redirect to the return URL otherwise.
func (rp *relyingParty) callbackHandler(allow func(*session) bool, forbidError bool) fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		h := w.Header()
		h.Set("Cache-Control", "no-store")

		q := r.URL.Query()
		state := q.Get("state")
		if state == "" {
			rp.logRejected(r, "invalid callback", errors.New("no state"))
			badRequest(w)
			return
		}
		cookies := r.Cookies()
		spec := rp.loginCookie(state)
		data, chunks, err := spec.read(cookies, rp.aead)
		spec.clear(h, chunks)
		if err != nil {
			rp.logRejected(r, "invalid callback", fmt.Errorf("login cookie: %w", err))
			badRequest(w)
			return
		}
		var ls loginState
		if err = json.Unmarshal(data, &ls); err != nil || rp.now().After(time.Unix(0, ls.Created).Add(loginTimeout)) {
			rp.logRejected(r, "invalid callback", errors.New("login expired"))
			badRequest(w)
			return
		}

		// RFC 9207: the response must come from the provider the login was started with.
		if iss := q.Get("iss"); (iss != "" || rp.provider.issParameter) && iss != rp.provider.issuer {
			rp.logRejected(r, "invalid callback", fmt.Errorf("iss mismatch: %q", iss))
			badRequest(w)
			return
		}
		if e := q.Get("error"); e != "" {
			rp.logger.InfoContext(r.Context(), "provider returned an error", "path", r.URL.Path, "error", e)
			if forbidError {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
			return
		}

		s, err := rp.exchange(r, q.Get("code"), ls)
		if err != nil {
			if _, ok := errors.AsType[*tokenError](err); ok || errors.Is(err, errInvalidLogin) {
				rp.logRejected(r, "invalid callback", err)
				badRequest(w)
			} else {
				rp.logFailed(r, "provider unavailable", err)
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			}
			return
		}
		if allow != nil && !allow(s) {
			// Do not revoke the refresh token. Some providers, such as Keycloak, would also revoke the tokens of the other
			// sessions with the same sid.
			rp.logRejected(r, "access denied", errAccessDenied)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// Replace any previous session of the client. The session cookie is usually not sent on the cross-site redirect
		// from the provider, so the previous sessions of the same provider session are also found by their sid.
		// Do not revoke their refresh tokens. Some providers, such as Keycloak, would also revoke the tokens just received.
		_, prev, err := rp.readSession(r.Context(), cookies)
		if err == nil && prev.id != "" {
			_ = rp.cfg.store.Delete(r.Context(), prev.id)
		}
		if rp.cfg.store != nil && s.SID != "" {
			if _, err := rp.cfg.store.DeleteBy(r.Context(), rp.partition, s.Subject, s.SID); err != nil {
				rp.logFailed(r, "session store", err)
				internalError(w)
				return
			}
		}
		if len(rp.cfg.resources) > 0 && s.RefreshToken == "" {
			rp.logger.WarnContext(r.Context(), "resources declared but no refresh token", "path", r.URL.Path)
		}
		if err := rp.writeSession(r.Context(), h, s, sessionState{chunks: prev.chunks}); err != nil {
			rp.logFailed(r, "session store", err)
			internalError(w)
			return
		}
		http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
	}
}

var errInvalidLogin = errors.New("invalid login")

func (rp *relyingParty) exchange(r *http.Request, code string, ls loginState) (*session, error) {
	var key *dpopKey
	if rp.cfg.dpop {
		var err error
		if key, err = parseDPoPKey(ls.DPoPKey); err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
		}
	}
	client := rp.providerClient(key)
	ctx := oidc.ClientContext(r.Context(), client)
	token, err := rp.requestToken(ctx, client, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.oauth2.RedirectURL},
		"code_verifier": {ls.Verifier},
	})
	if err != nil {
		return nil, err
	}
	if key != nil && !isDPoP(token.TokenType) {
		return nil, errNotDPoPBound
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%w: no id token", errInvalidLogin)
	}
	idToken, err := rp.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ls.Nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", errInvalidLogin)
	}
	if err := ls.checkAuthentication(idToken); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
	}

	now := rp.now()
	s := newSession(now)
	s.Subject = idToken.Subject
	s.SID = claims.SID
	s.IDToken = rawIDToken
	s.DPoPKey = ls.DPoPKey
	s.setToken(token, now)

	if rp.cfg.userInfo {
		info, err := rp.provider.oidc.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, err
		}
		// OpenID Connect Core 5.3.2: the sub of the UserInfo response must match the ID token.
		if info.Subject != idToken.Subject {
			return nil, fmt.Errorf("%w: userinfo subject mismatch", errInvalidLogin)
		}
		if err := info.Claims(&s.UserInfo); err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
		}
	}
	return s, nil
}

// verifyIDToken verifies the ID token with go-oidc, then the claims that go-oidc does not check. OpenID Connect Core 2
// requires sub and iat, and OpenID Connect Core 3.1.3.7 steps 3 and 4 define the checks of aud and azp.
func (rp *relyingParty) verifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, error) {
	idToken, err := rp.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if idToken.Subject == "" {
		return nil, errors.New("sub required")
	}
	if idToken.IssuedAt.IsZero() {
		return nil, errors.New("iat required")
	}
	var claims struct {
		AZP string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	if err := rp.checkAudience(idToken.Audience, claims.AZP); err != nil {
		return nil, err
	}
	return idToken, nil
}

// checkAuthentication checks the auth_time and acr of the ID token against the max_age and acr_values of the login, as
// OpenID Connect Core 3.1.3.7 steps 12 and 13 recommend. An acr outside the requested values is rejected, as RFC 9470 5
// expects of a step-up. The provider authenticates after the login started, so auth_time is compared to its start.
func (ls loginState) checkAuthentication(idToken *oidc.IDToken) error {
	if ls.MaxAge == nil && ls.ACRValues == "" {
		return nil
	}
	var claims struct {
		ACR      string  `json:"acr"`
		AuthTime float64 `json:"auth_time"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}
	if ls.MaxAge != nil {
		if claims.AuthTime == 0 {
			return errors.New("auth_time required")
		}
		oldest := time.Unix(0, ls.Created).Add(-time.Duration(*ls.MaxAge)*time.Second - authTimeSkew)
		if time.Unix(int64(claims.AuthTime), 0).Before(oldest) {
			return errors.New("auth_time too old")
		}
	}
	if ls.ACRValues != "" && !slices.Contains(strings.Fields(ls.ACRValues), claims.ACR) {
		return fmt.Errorf("acr mismatch: %q", claims.ACR)
	}
	return nil
}

// checkAudience checks the audiences and the authorized party of a token. Additional audiences are trusted only when
// azp is the client ID.
func (rp *relyingParty) checkAudience(aud []string, azp string) error {
	if len(aud) > 1 && azp == "" {
		return errors.New("untrusted audience")
	}
	if azp != "" && azp != rp.oauth2.ClientID {
		return errors.New("azp mismatch")
	}
	return nil
}

// validPrompt reports whether prompt is a space-separated list of values supported by the provider, none being
// exclusive of the others.
func (rp *relyingParty) validPrompt(prompt string) bool {
	supported := rp.provider.promptValues
	if len(supported) == 0 {
		supported = standardPrompts
	}
	values := strings.Fields(prompt)
	if len(values) == 0 || len(values) > 1 && slices.Contains(values, "none") {
		return false
	}
	for _, v := range values {
		if !slices.Contains(supported, v) {
			return false
		}
	}
	return true
}

// validACRValues reports whether acr is a non-empty, bounded list of values supported by the provider. Any value is
// accepted when the provider does not advertise them.
func (rp *relyingParty) validACRValues(acr string) bool {
	values := strings.Fields(acr)
	if encoded, _ := json.Marshal(acr); len(values) == 0 || len(encoded)-2 > maxACRValues {
		return false
	}
	if len(rp.provider.acrValues) == 0 {
		return true
	}
	for _, v := range values {
		if !slices.Contains(rp.provider.acrValues, v) {
			return false
		}
	}
	return true
}

// localURL reports whether u is a path on the same origin, which a browser cannot read as another host.
func localURL(u string) bool {
	if len(u) == 0 || u[0] != '/' || len(u) > 1 && (u[1] == '/' || u[1] == '\\') {
		return false
	}
	for i := range len(u) {
		if u[i] < 0x20 || u[i] == 0x7f || u[i] == '\\' {
			return false
		}
	}
	parsed, err := url.Parse(u)
	return err == nil && parsed.Scheme == "" && parsed.Host == ""
}

// trustedURL reports whether u is an absolute URL of a trusted origin.
func (rp *relyingParty) trustedURL(u string) bool {
	parsed, err := url.Parse(u)
	return err == nil && parsed.User == nil && slices.Contains(rp.cfg.trustedOrigins, parsed.Scheme+"://"+parsed.Host)
}

func badRequest(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

func internalError(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

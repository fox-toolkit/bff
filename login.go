// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/fox"
	"golang.org/x/oauth2"
)

const (
	loginTimeout = 15 * time.Minute
	// maxPendingLogins bounds the login cookies of a browser, which abandoned or forced logins would pile up.
	maxPendingLogins   = 3
	maxPARResponseSize = 1 << 16
)

// standardPrompts are accepted when the provider does not advertise its prompt values.
var standardPrompts = []string{"none", "login", "consent", "select_account"}

type loginState struct {
	Verifier  string `json:"v"`
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
	DPoPKey   []byte `json:"k,omitempty"`
	// Created is in nanoseconds, so logins started in the same second are ordered.
	Created int64 `json:"t"`
}

// LoginHandler returns a handler that starts the authorization code flow with the provider. The browser must initiate
// the login flow by navigating to it. After login, the browser is redirected to the local URL in the returnUrl query
// parameter, or to "/" if it is absent. The optional prompt query parameter is passed to the provider, such as
// prompt=none for a silent login.
//
// A login started from another origin redirects to the return URL without starting the flow, unless
// [WithCrossOriginLogin] is enabled.
//
// When Pushed Authorization Requests (PAR, RFC 9126) are used, each login sends a request to the pushed authorization
// request endpoint of the provider, so the route should be rate limited. If this request fails, the handler responds
// with 502 Bad Gateway.
func (fe *Frontend) LoginHandler() fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")

		q := r.URL.Query()
		returnURL := q.Get("returnUrl")
		if returnURL == "" {
			returnURL = "/"
		} else if !localURL(returnURL) {
			fe.logRejected(r, "invalid return url", nil)
			badRequest(w)
			return
		}
		prompt := q.Get("prompt")
		if prompt != "" && !fe.validPrompt(prompt) {
			fe.logRejected(r, "invalid prompt", nil)
			badRequest(w)
			return
		}
		if !fe.cfg.crossOriginLogin && crossOrigin(r) {
			fe.logger.InfoContext(r.Context(), "login from another origin", "path", r.URL.Path)
			http.Redirect(w, r, returnURL, http.StatusFound) //nolint:gosec // checked by localURL
			return
		}

		state := randomString()
		ls := loginState{
			Verifier:  oauth2.GenerateVerifier(),
			Nonce:     randomString(),
			ReturnURL: returnURL,
			Created:   fe.now().UnixNano(),
		}
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {fe.oauth2.ClientID},
			"redirect_uri":          {fe.oauth2.RedirectURL},
			"scope":                 {strings.Join(fe.oauth2.Scopes, " ")},
			"state":                 {state},
			"nonce":                 {ls.Nonce},
			"code_challenge":        {oauth2.S256ChallengeFromVerifier(ls.Verifier)},
			"code_challenge_method": {"S256"},
		}
		if prompt != "" {
			params.Set("prompt", prompt)
		}
		if len(fe.cfg.resources) > 0 {
			// RFC 8707 2.1: the resources apply to the full grant, so their access tokens are requested with the
			// refresh token.
			params["resource"] = slices.Clone(fe.cfg.resources)
		}
		if fe.cfg.dpop {
			key, raw, err := newDPoPKey()
			if err != nil {
				fe.logFailed(r, "dpop key", err)
				internalError(w)
				return
			}
			ls.DPoPKey = raw
			// RFC 9449 10: the authorization code is bound to the key.
			params.Set("dpop_jkt", key.jkt)
		}
		if fe.parEndpoint != "" {
			requestURI, err := fe.pushAuthorizationRequest(r.Context(), params)
			if err != nil {
				fe.logFailed(r, "pushed authorization request", err)
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
				return
			}
			params = url.Values{"client_id": {fe.oauth2.ClientID}, "request_uri": {requestURI}}
		}

		fe.trimPendingLogins(w.Header(), r.Cookies())
		data, err := json.Marshal(ls)
		if err == nil {
			err = loginCookie(state).write(w.Header(), fe.aead, data, int(loginTimeout.Seconds()), 0)
		}
		if err != nil {
			fe.logFailed(r, "login cookie", err)
			internalError(w)
			return
		}

		authURL := fe.oauth2.Endpoint.AuthURL
		sep := "?"
		if strings.Contains(authURL, "?") {
			sep = "&"
		}
		http.Redirect(w, r, authURL+sep+params.Encode(), http.StatusFound)
	}
}

// pushAuthorizationRequest pushes the authorization request to the provider, as defined by RFC 9126, and returns its
// request URI.
func (fe *Frontend) pushAuthorizationRequest(ctx context.Context, params url.Values) (string, error) {
	if fe.requestObjectAlg != "" {
		// RFC 9126 3: the form only has the request object and the parameters of the client authentication.
		request, err := fe.auth.requestObject(params, fe.requestObjectAlg, fe.now())
		if err != nil {
			return "", err
		}
		params = url.Values{"request": {request}}
	}
	req, err := fe.auth.newRequest(ctx, fe.parEndpoint, params, fe.now)
	if err != nil {
		return "", err
	}
	resp, err := fe.provider.client.Do(req)
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

// crossOrigin reports whether the browser sent the request from another origin, as http.CrossOriginProtection does. A
// request without Sec-Fetch-Site is accepted.
func crossOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site != "" && site != "same-origin" && site != "none"
}

// trimPendingLogins deletes the login cookies of the oldest pending logins, keeping room for a new one.
func (fe *Frontend) trimPendingLogins(h http.Header, cookies []*http.Cookie) {
	type pending struct {
		spec    cookieSpec
		created int64
		chunks  int
	}
	var logins []pending
	seen := make(map[string]bool)
	for _, c := range cookies {
		name, ok := strings.CutPrefix(c.Name, loginCookie("").name)
		if !ok {
			continue
		}
		id, _, _ := strings.Cut(name, ".")
		if seen[id] {
			continue
		}
		seen[id] = true
		spec := loginCookie(id)
		data, chunks, err := spec.read(cookies, fe.aead)
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
// return URL without session.
func (fe *Frontend) CallbackHandler() fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		h := w.Header()
		h.Set("Cache-Control", "no-store")

		q := r.URL.Query()
		state := q.Get("state")
		if state == "" {
			fe.logRejected(r, "invalid callback", errors.New("no state"))
			badRequest(w)
			return
		}
		cookies := r.Cookies()
		spec := loginCookie(state)
		data, chunks, err := spec.read(cookies, fe.aead)
		spec.clear(h, chunks)
		if err != nil {
			fe.logRejected(r, "invalid callback", fmt.Errorf("login cookie: %w", err))
			badRequest(w)
			return
		}
		var ls loginState
		if err = json.Unmarshal(data, &ls); err != nil || fe.now().After(time.Unix(0, ls.Created).Add(loginTimeout)) {
			fe.logRejected(r, "invalid callback", errors.New("login expired"))
			badRequest(w)
			return
		}

		// RFC 9207: the response must come from the provider the login was started with.
		if iss := q.Get("iss"); (iss != "" || fe.provider.issParameter) && iss != fe.provider.issuer {
			fe.logRejected(r, "invalid callback", fmt.Errorf("iss mismatch: %q", iss))
			badRequest(w)
			return
		}
		if e := q.Get("error"); e != "" {
			fe.logger.InfoContext(r.Context(), "provider returned an error", "path", r.URL.Path, "error", e)
			http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
			return
		}

		s, err := fe.exchange(r, q.Get("code"), ls)
		if err != nil {
			if _, ok := errors.AsType[*tokenError](err); ok || errors.Is(err, errInvalidLogin) {
				fe.logRejected(r, "invalid callback", err)
				badRequest(w)
			} else {
				fe.logFailed(r, "provider unavailable", err)
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			}
			return
		}

		// Replace any previous session of the client. The session cookie is usually not sent on the cross-site redirect
		// from the provider, so the previous sessions of the same provider session are also found by their sid.
		_, prev, err := fe.readSession(r.Context(), cookies)
		if err == nil && prev.id != "" {
			_ = fe.cfg.store.Delete(r.Context(), prev.id)
		}
		if fe.cfg.store != nil && s.SID != "" {
			if err := fe.deleteSessionsBy(r.Context(), s.Subject, s.SID); err != nil {
				fe.logFailed(r, "session store", err)
				internalError(w)
				return
			}
		}
		if len(fe.cfg.resources) > 0 && s.RefreshToken == "" {
			fe.logger.WarnContext(r.Context(), "resources declared but no refresh token", "path", r.URL.Path)
		}
		if err := fe.writeSession(r.Context(), h, s, sessionState{chunks: prev.chunks}); err != nil {
			fe.logFailed(r, "session store", err)
			internalError(w)
			return
		}
		http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
	}
}

var errInvalidLogin = errors.New("invalid login")

func (fe *Frontend) exchange(r *http.Request, code string, ls loginState) (*session, error) {
	var key *dpopKey
	if fe.cfg.dpop {
		var err error
		if key, err = parseDPoPKey(ls.DPoPKey); err != nil {
			return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
		}
	}
	client := fe.providerClient(key)
	ctx := oidc.ClientContext(r.Context(), client)
	token, err := fe.requestToken(ctx, client, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {fe.oauth2.RedirectURL},
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
	idToken, err := fe.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ls.Nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", errInvalidLogin)
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidLogin, err)
	}

	now := fe.now()
	s := newSession(now)
	s.Subject = idToken.Subject
	s.SID = claims.SID
	s.IDToken = rawIDToken
	s.DPoPKey = ls.DPoPKey
	s.setToken(token, now)

	if fe.cfg.userInfo {
		info, err := fe.provider.oidc.UserInfo(ctx, oauth2.StaticTokenSource(token))
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
// requires sub and iat, and OpenID Connect Core 3.1.3.7 steps 4 and 5 define the checks of azp.
func (fe *Frontend) verifyIDToken(ctx context.Context, raw string) (*oidc.IDToken, error) {
	idToken, err := fe.verifier.Verify(ctx, raw)
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
	if claims.AZP == "" && len(idToken.Audience) > 1 {
		return nil, errors.New("azp required with several audiences")
	}
	if claims.AZP != "" && claims.AZP != fe.oauth2.ClientID {
		return nil, errors.New("azp mismatch")
	}
	return idToken, nil
}

// validPrompt reports whether prompt is a space-separated list of values supported by the provider, none being
// exclusive of the others.
func (fe *Frontend) validPrompt(prompt string) bool {
	supported := fe.provider.promptValues
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

func badRequest(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

func internalError(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

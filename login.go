// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/fox"
	"golang.org/x/oauth2"
)

const loginTimeout = 15 * time.Minute

// standardPrompts are accepted when the provider does not advertise its prompt values.
var standardPrompts = []string{"none", "login", "consent", "select_account"}

type loginState struct {
	Verifier  string `json:"v"`
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
	Created   int64  `json:"t"`
}

// LoginHandler returns a handler that starts the authorization code flow with the provider. The optional returnUrl
// query parameter is a local URL to redirect to after login, "/" by default. The optional prompt query parameter is
// passed to the provider, such as prompt=none for a silent login.
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
			badRequest(w)
			return
		}
		prompt := q.Get("prompt")
		if prompt != "" && !fe.validPrompt(prompt) {
			badRequest(w)
			return
		}

		state := randomString()
		ls := loginState{
			Verifier:  oauth2.GenerateVerifier(),
			Nonce:     randomString(),
			ReturnURL: returnURL,
			Created:   fe.now().Unix(),
		}
		data, err := json.Marshal(ls)
		if err == nil {
			err = loginCookie(state).write(w.Header(), fe.aead, data, int(loginTimeout.Seconds()), 0)
		}
		if err != nil {
			internalError(w)
			return
		}

		opts := []oauth2.AuthCodeOption{oidc.Nonce(ls.Nonce), oauth2.S256ChallengeOption(ls.Verifier)}
		if prompt != "" {
			opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
		}
		http.Redirect(w, r, fe.oauth2.AuthCodeURL(state, opts...), http.StatusFound)
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
			badRequest(w)
			return
		}
		cookies := r.Cookies()
		spec := loginCookie(state)
		data, chunks, err := spec.read(cookies, fe.aead)
		spec.clear(h, chunks)
		if err != nil {
			badRequest(w)
			return
		}
		var ls loginState
		if err = json.Unmarshal(data, &ls); err != nil || fe.now().After(time.Unix(ls.Created, 0).Add(loginTimeout)) {
			badRequest(w)
			return
		}

		// RFC 9207: the response must come from the provider the login was started with.
		if iss := q.Get("iss"); (iss != "" || fe.provider.issParameter) && iss != fe.provider.issuer {
			badRequest(w)
			return
		}
		if q.Get("error") != "" {
			http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
			return
		}

		s, err := fe.exchange(r, q.Get("code"), ls)
		if err != nil {
			if _, ok := errors.AsType[*oauth2.RetrieveError](err); ok || errors.Is(err, errInvalidLogin) {
				badRequest(w)
			} else {
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			}
			return
		}

		// Replace any previous session of the client.
		_, prev, err := fe.readSession(r.Context(), cookies)
		if err == nil && prev.id != "" {
			_ = fe.cfg.store.Delete(r.Context(), prev.id)
		}
		if err := fe.writeSession(r.Context(), h, s, sessionState{chunks: prev.chunks}); err != nil {
			internalError(w)
			return
		}
		http.Redirect(w, r, ls.ReturnURL, http.StatusFound)
	}
}

var errInvalidLogin = errors.New("invalid login")

func (fe *Frontend) exchange(r *http.Request, code string, ls loginState) (*session, error) {
	ctx := oidc.ClientContext(r.Context(), fe.provider.client)
	token, err := fe.oauth2.Exchange(ctx, code, oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		return nil, err
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errInvalidLogin
	}
	idToken, err := fe.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errInvalidLogin
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(ls.Nonce)) != 1 {
		return nil, errInvalidLogin
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errInvalidLogin
	}

	s := newSession(fe.now())
	s.Subject = idToken.Subject
	s.SID = claims.SID
	s.IDToken = rawIDToken
	s.AccessToken = token.AccessToken
	s.TokenType = token.TokenType
	s.RefreshToken = token.RefreshToken
	if !token.Expiry.IsZero() {
		s.Expiry = token.Expiry.Unix()
	}

	if fe.cfg.userInfo {
		info, err := fe.provider.oidc.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, err
		}
		// OpenID Connect Core 5.3.2: the sub of the UserInfo response must match the ID token.
		if info.Subject != idToken.Subject {
			return nil, errInvalidLogin
		}
		if err := info.Claims(&s.UserInfo); err != nil {
			return nil, errInvalidLogin
		}
	}
	return s, nil
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

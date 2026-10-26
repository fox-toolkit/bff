// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fox-toolkit/fox"
)

var protocolClaims = []string{"iss", "aud", "azp", "exp", "iat", "nbf", "jti", "nonce", "at_hash", "c_hash", "sid"}

type userResponse struct {
	Claims          map[string]any `json:"claims"`
	LogoutCSRFToken string         `json:"logoutCsrfToken"`
	ExpiresIn       int64          `json:"expiresIn"`
}

// UserHandler returns a handler that responds with a JSON object describing the session of the user, such as
//
//	{
//	  "claims": {"sub": "248289761001", "name": "Jane Doe", "email": "janedoe@example.com"},
//	  "logoutCsrfToken": "pNmKN2uL7x0Hbf3Sx9VTq2nqZ2bJ1ws6Zx1cA5tDqKE",
//	  "expiresIn": 1800
//	}
//
// The logoutCsrfToken member is the CSRF token expected by [Frontend.LogoutHandler], and expiresIn is the number of
// seconds before the session ends.
func (fe *Frontend) UserHandler() fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")
		if err := fe.checkCSRF(r); err != nil {
			fe.logRejected(r, "cross-site request", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		s, err := fe.currentSession(r, w.Header())
		if err != nil {
			fe.sessionError(w, r, err)
			return
		}
		if s == nil {
			fe.cfg.unauthorized(c)
			return
		}

		claims, err := s.claims()
		if err != nil {
			internalError(w)
			return
		}
		body, err := json.Marshal(userResponse{
			Claims:          claims,
			LogoutCSRFToken: s.LogoutCSRFToken,
			ExpiresIn:       int64(s.expires(fe.cfg).Sub(fe.now()) / time.Second),
		})
		if err != nil {
			internalError(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// claims returns the user claims of the ID token, merged with the UserInfo claims, without the protocol claims. The
// ID token was verified at login and is kept encrypted in the session, so its signature is not checked again.
func (s *session) claims() (map[string]any, error) {
	parts := strings.Split(s.IDToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed id token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	for _, name := range protocolClaims {
		delete(claims, name)
	}
	if len(s.UserInfo) > 0 {
		if err := json.Unmarshal(s.UserInfo, &claims); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fox-toolkit/fox"
)

const (
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	// maxBackchannelBody bounds the form body of a back-channel logout request, which only contains the logout token.
	maxBackchannelBody = 16 << 10
)

var errInvalidLogoutToken = errors.New("invalid logout token")

// BackchannelHandler returns a handler that ends the sessions designated by a logout token, as defined by OpenID
// Connect Back-Channel Logout. The provider must call it with a POST request. It panics if the frontend has no store.
func (fe *Frontend) BackchannelHandler() fox.HandlerFunc {
	if fe.cfg.store == nil {
		panic("bff: back-channel logout requires a store")
	}
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		// Back-Channel Logout 2.8: the response must not be cached.
		w.Header().Set("Cache-Control", "no-store")

		r.Body = http.MaxBytesReader(w, r.Body, maxBackchannelBody)
		if err := r.ParseForm(); err != nil {
			fe.logRejected(r, "invalid back-channel logout", err)
			badRequest(w)
			return
		}
		subject, sid, err := fe.verifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
		if err != nil {
			fe.logRejected(r, "invalid back-channel logout", err)
			badRequest(w)
			return
		}

		if err := fe.deleteSessionsBy(r.Context(), subject, sid); err != nil {
			fe.logFailed(r, "session store", err)
			internalError(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// verifyLogoutToken validates the logout token as defined by Back-Channel Logout 2.6 and returns its subject and
// provider session ID, one of which may be empty.
func (fe *Frontend) verifyLogoutToken(ctx context.Context, raw string) (string, string, error) {
	if raw == "" {
		return "", "", fmt.Errorf("%w: missing", errInvalidLogoutToken)
	}
	// Steps 2 to 4: signature, algorithm, iss, aud and exp are validated as for an ID token.
	token, err := fe.logoutVerifier.Verify(ctx, raw)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", errInvalidLogoutToken, err)
	}
	var claims struct {
		Events map[string]json.RawMessage `json:"events"`
		SID    string                     `json:"sid"`
		JTI    string                     `json:"jti"`
		AZP    string                     `json:"azp"`
		Nonce  json.RawMessage            `json:"nonce"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("%w: %w", errInvalidLogoutToken, err)
	}
	// Step 4: additional audiences require azp, as for an ID token.
	if err := fe.checkAudience(token.Audience, claims.AZP); err != nil {
		return "", "", fmt.Errorf("%w: %w", errInvalidLogoutToken, err)
	}
	// Step 5: a sub claim, a sid claim, or both.
	if token.Subject == "" && claims.SID == "" {
		return "", "", fmt.Errorf("%w: no sub nor sid", errInvalidLogoutToken)
	}
	// Step 6: the events claim contains the back-channel logout event, whose value is a JSON object.
	if event, ok := claims.Events[backchannelLogoutEvent]; !ok || !bytes.HasPrefix(bytes.TrimSpace(event), []byte("{")) {
		return "", "", fmt.Errorf("%w: no back-channel logout event", errInvalidLogoutToken)
	}
	// Step 7: no nonce, so an ID token cannot be used as a logout token.
	if claims.Nonce != nil {
		return "", "", fmt.Errorf("%w: nonce present", errInvalidLogoutToken)
	}
	// Section 2.4: iat and jti are required.
	if token.IssuedAt.IsZero() || claims.JTI == "" {
		return "", "", fmt.Errorf("%w: missing iat or jti", errInvalidLogoutToken)
	}
	return token.Subject, claims.SID, nil
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
// Connect Back-Channel Logout. It panics if the frontend has no store.
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
			badRequest(w)
			return
		}
		subject, sid, err := fe.verifyLogoutToken(r.Context(), r.PostForm.Get("logout_token"))
		if err != nil {
			badRequest(w)
			return
		}

		records, err := fe.cfg.store.DeleteBy(r.Context(), subject, sid)
		if err != nil {
			internalError(w)
			return
		}
		for id, rec := range records {
			data, err := fe.aead.Decrypt(rec.Data, storeAssociatedData(id))
			if err != nil {
				continue
			}
			if s, err := decodeSession(data); err == nil && s.RefreshToken != "" {
				_ = fe.revoke(r.Context(), s.RefreshToken)
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// verifyLogoutToken validates the logout token as defined by Back-Channel Logout 2.6 and returns its subject and
// provider session ID, one of which may be empty.
func (fe *Frontend) verifyLogoutToken(ctx context.Context, raw string) (string, string, error) {
	if raw == "" {
		return "", "", errInvalidLogoutToken
	}
	// Steps 2 to 4: signature, algorithm, iss, aud and exp are validated as for an ID token.
	token, err := fe.verifier.Verify(ctx, raw)
	if err != nil {
		return "", "", errInvalidLogoutToken
	}
	var claims struct {
		Events map[string]json.RawMessage `json:"events"`
		SID    string                     `json:"sid"`
		JTI    string                     `json:"jti"`
		Nonce  json.RawMessage            `json:"nonce"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", "", errInvalidLogoutToken
	}
	// Step 5: a sub claim, a sid claim, or both.
	if token.Subject == "" && claims.SID == "" {
		return "", "", errInvalidLogoutToken
	}
	// Step 6: the events claim contains the back-channel logout event, whose value is a JSON object.
	if event, ok := claims.Events[backchannelLogoutEvent]; !ok || !bytes.HasPrefix(bytes.TrimSpace(event), []byte("{")) {
		return "", "", errInvalidLogoutToken
	}
	// Step 7: no nonce, so an ID token cannot be used as a logout token.
	if claims.Nonce != nil {
		return "", "", errInvalidLogoutToken
	}
	// Section 2.4: iat and jti are required.
	if token.IssuedAt.IsZero() || claims.JTI == "" {
		return "", "", errInvalidLogoutToken
	}
	return token.Subject, claims.SID, nil
}

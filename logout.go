// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/fox-toolkit/fox"
)

const (
	revocationTimeout = 10 * time.Second
	// maxLogoutBody bounds the form body of a logout, which only contains the CSRF token.
	maxLogoutBody = 4096
)

// LogoutHandler returns a handler that ends the session and redirects to the end session endpoint of the provider, as
// defined by OpenID Connect RP-Initiated Logout. It accepts GET with the csrf_token query parameter, and POST with the
// csrf_token form field.
func (fe *Frontend) LogoutHandler() fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")

		switch r.Method {
		case http.MethodGet:
		case http.MethodPost:
			// Forms cannot send a custom header, so only the cross-origin protection applies.
			if err := fe.cop.Check(r); err != nil {
				fe.logRejected(r, "cross-site request", err)
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		s, st, err := fe.readSession(r.Context(), r.Cookies())
		if errors.Is(err, errNoSession) {
			sessionCookie.clear(w.Header(), st.chunks)
			http.Redirect(w, r, fe.postLogoutURL(), http.StatusSeeOther)
			return
		}
		if err != nil {
			fe.logFailed(r, "session store", err)
			internalError(w)
			return
		}

		// On POST, the token is in the form body, so it stays out of the URL.
		var token string
		if r.Method == http.MethodGet {
			token = r.URL.Query().Get("csrf_token")
		} else {
			r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBody)
			if err := r.ParseForm(); err == nil {
				token = r.PostForm.Get("csrf_token")
			}
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.LogoutCSRFToken)) != 1 {
			fe.logRejected(r, "invalid logout", errors.New("missing or invalid csrf token"))
			badRequest(w)
			return
		}

		if err := fe.deleteSession(r.Context(), w.Header(), st); err != nil {
			fe.logFailed(r, "session store", err)
			internalError(w)
			return
		}
		if s.RefreshToken != "" {
			// The session is already deleted, so a failed revocation only leaves the refresh token valid until it expires.
			_ = fe.revoke(r.Context(), s.RefreshToken)
		}
		http.Redirect(w, r, fe.endSessionURL(s.IDToken), http.StatusSeeOther)
	}
}

// endSessionURL returns the URL of the provider end session endpoint, as defined by OpenID Connect RP-Initiated
// Logout, or the post logout redirect URL when the provider has none.
func (fe *Frontend) endSessionURL(idToken string) string {
	if fe.provider.endSessionEndpoint == "" {
		return fe.postLogoutURL()
	}
	u, err := url.Parse(fe.provider.endSessionEndpoint)
	if err != nil {
		return fe.postLogoutURL()
	}
	q := u.Query()
	q.Set("client_id", fe.oauth2.ClientID)
	q.Set("id_token_hint", idToken)
	if fe.postLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", fe.postLogoutRedirectURL)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (fe *Frontend) postLogoutURL() string {
	if fe.postLogoutRedirectURL != "" {
		return fe.postLogoutRedirectURL
	}
	return "/"
}

// revoke revokes the refresh token, as defined by RFC 7009. It does nothing when the provider has no revocation
// endpoint.
func (fe *Frontend) revoke(ctx context.Context, refreshToken string) error {
	err := fe.postRevocation(ctx, refreshToken)
	if err != nil {
		fe.logger.WarnContext(ctx, "refresh token revocation failed", "error", err)
	}
	return err
}

func (fe *Frontend) postRevocation(ctx context.Context, refreshToken string) error {
	if fe.provider.revocationEndpoint == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()

	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := fe.auth.newRequest(ctx, fe.provider.revocationEndpoint, form, fe.now)
	if err != nil {
		return err
	}

	resp, err := fe.provider.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation: unexpected status %d", resp.StatusCode)
	}
	return nil
}

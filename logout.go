// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fox-toolkit/fox"
)

const (
	revocationTimeout     = 10 * time.Second
	maxRevocationAttempts = 3
	// maxLogoutBody bounds the form body of a logout, which only contains the CSRF token.
	maxLogoutBody = 4096
)

// LogoutHandler returns a handler that ends the session, revokes its refresh token and redirects to the end session
// endpoint of the provider, as defined by OpenID Connect RP-Initiated Logout. The browser navigates to it with the
// csrf_token query parameter or form field, set to the logoutCsrfToken returned by [Frontend.UserHandler].
func (fe *Frontend) LogoutHandler() fox.HandlerFunc {
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")

		// A logout comes from a link or a form, which cannot send the CSRF header, so only CrossOriginProtection applies.
		if err := fe.cop.Check(r); err != nil {
			fe.logRejected(r, "cross-site request", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
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

		r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBody)
		// Like the query of the other handlers, a malformed parameter does not prevent reading the others.
		_ = r.ParseForm()
		token := r.Form.Get("csrf_token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.LogoutCSRFToken)) != 1 {
			fe.logRejected(r, "invalid logout", errors.New("missing or invalid csrf token"))
			badRequest(w)
			return
		}

		if err := fe.endSession(r.Context(), w.Header(), s, st); err != nil {
			fe.logFailed(r, "end session", err)
			internalError(w)
			return
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
// endpoint. The request that started it does not cancel it.
func (fe *Frontend) revoke(ctx context.Context, refreshToken string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()
	return fe.revokeWithin(ctx, refreshToken)
}

// revokeWithin is like revoke, but stops when ctx is done.
func (fe *Frontend) revokeWithin(ctx context.Context, refreshToken string) error {
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

	for attempt := 1; ; attempt++ {
		resp, err := fe.sendRevocation(ctx, refreshToken)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		err = fmt.Errorf("revocation: unexpected status %d", resp.StatusCode)
		if resp.StatusCode != http.StatusServiceUnavailable || attempt == maxRevocationAttempts {
			return err
		}
		// RFC 7009 2.2.1: the token still exists, and the request may be retried after a delay.
		delay := retryAfter(resp.Header.Get("Retry-After"), time.Now())
		if deadline, _ := ctx.Deadline(); time.Until(deadline) < delay {
			return err
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return err
		}
	}
}

func (fe *Frontend) sendRevocation(ctx context.Context, refreshToken string) (*http.Response, error) {
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := fe.auth.newRequest(ctx, fe.provider.revocationEndpoint, form, fe.now)
	if err != nil {
		return nil, err
	}
	resp, err := fe.provider.client.Do(req) //nolint:gosec // revocation endpoint from the provider metadata, checked by NewProvider
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return resp, nil
}

// retryAfter returns the delay of a Retry-After header value, in seconds or as a date, or one second when it has none.
func retryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		// A delay beyond the revocation timeout gives up the retry, whatever its value.
		return time.Duration(min(seconds, int64(revocationTimeout/time.Second)+1)) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		return max(t.Sub(now), 0)
	}
	return time.Second
}

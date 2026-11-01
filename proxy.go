// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/fox-toolkit/fox"
	"golang.org/x/net/http/httpguts"
)

var (
	errCrossOrigin   = errors.New("cross-origin request")
	errAccessDenied  = errors.New("access denied")
	errOutsideDomain = errors.New("host outside the cookie domain")
)

// Proxy authenticates the users of the upstream servers it is put in front of, with its own OpenID Connect client and
// user sessions.
type Proxy struct {
	rp     *relyingParty
	scheme string
}

// NewProxy returns a [Proxy] for the OpenID Connect client. A proxy serves the host of the redirect URL of the client,
// or the hosts of its cookie domain (see [WithCookieDomain]).
//
// The aead encrypts the data the proxy stores in cookies and in its store, such as the access, refresh and ID tokens.
// When the proxy is served by several replicas, they must all use the same keys.
func NewProxy(client Client, aead AEAD, opts ...ProxyOption) (*Proxy, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt.applyProxy(cfg); err != nil {
			return nil, err
		}
	}
	cookie := proxySessionCookie
	if cfg.cookieDomain != "" {
		cookie = cookieSpec{name: sharedCookie, purpose: "session", domain: cfg.cookieDomain, sameSite: http.SameSiteLaxMode}
	}
	rp, err := newRelyingParty(client, aead, cfg, cookie)
	if err != nil {
		return nil, err
	}
	redirect, _ := url.Parse(client.RedirectURL)
	if cfg.cookieDomain != "" && !inDomain(redirect.Hostname(), cfg.cookieDomain) {
		return nil, fmt.Errorf("%w: redirect url outside the cookie domain", ErrInvalidConfig)
	}
	return &Proxy{rp: rp, scheme: redirect.Scheme}, nil
}

// Authenticate returns a middleware that authenticates the requests with the session cookie and refreshes the access
// tokens before they expire, including the tokens of the route resources (see [ForResource]). A GET or HEAD request
// without a valid session, with the Sec-Fetch-Mode header set to navigate and the Sec-Fetch-Dest header set to
// document, starts the login, which then returns to the URL of the request. The other requests without a valid session are handled by the unauthorized handler (see
// [WithUnauthorizedHandler]), unless the route has [AllowAnonymous].
//
// The middleware responds with 403 Forbidden when a rule of [WithAccessRule] or [Require] denies access to the user,
// and to a cross-origin request with an unsafe method and a session. On a route with [AllowAnonymous], a user denied
// access by a rule is handled as a request without a session. The middleware sets the headers of [WithIdentityHeader]
// on the request passed to the next handler.
//
// When Pushed Authorization Requests (PAR, RFC 9126) are used, each login sends a request to the pushed authorization
// request endpoint of the provider. If this request fails, the middleware responds with 502 Bad Gateway.
func (p *Proxy) Authenticate() fox.MiddlewareFunc {
	return func(next fox.HandlerFunc) fox.HandlerFunc {
		return func(c *fox.Context) {
			p.serve(c, next)
		}
	}
}

func (p *Proxy) serve(c *fox.Context, next fox.HandlerFunc) {
	rp := p.rp
	r := c.Request()
	w := c.Writer()
	route := c.Route()
	s, resources, pending, ok := rp.authenticate(c, route)
	if !ok {
		return
	}
	if s == nil && !allowAnonymous(route) {
		addSetCookies(w.Header(), pending)
		if !navigation(r) {
			rp.cfg.unauthorized(c)
			return
		}
		returnURL, err := p.returnURL(r)
		if err != nil {
			rp.logFailed(r, "return url", err)
			internalError(w)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		rp.startLogin(w, r, loginState{ReturnURL: returnURL}, "")
		return
	}

	var claims map[string]any
	if s != nil {
		rules := routeRules(route)
		if len(rp.cfg.rules) > 0 || len(rules) > 0 || len(rp.cfg.identityHeaders) > 0 {
			var err error
			claims, err = s.claims()
			if err != nil || !allowed(claims, rp.cfg.rules, rules) {
				if !allowAnonymous(route) {
					// Do not delete the session. The user may have access to other routes.
					addSetCookies(w.Header(), pending)
					rp.logRejected(r, "access denied", errAccessDenied)
					http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return
				}
				s, claims = nil, nil
			}
		}
	}
	if s != nil {
		if err := rp.cop.Check(r); err != nil {
			addSetCookies(w.Header(), pending)
			rp.logRejected(r, "cross-site request", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	req := rp.authenticatedRequest(r, s, resources)
	if len(rp.cfg.identityHeaders) > 0 {
		rp.setIdentityHeaders(r, req.Header, claims)
	}
	forward(c, next, req, pending)
}

// returnURL returns the URL of r, where the login returns. It is absolute with a cookie domain, since the login
// completes on the host of the redirect URL.
func (p *Proxy) returnURL(r *http.Request) (string, error) {
	path := r.URL.RequestURI()
	if encoded, _ := json.Marshal(path); len(encoded)-2 > maxReturnURL || !localURL(path) {
		path = "/"
	}
	domain := p.rp.cookie.domain
	if domain == "" {
		return path, nil
	}
	if !inDomain((&url.URL{Host: r.Host}).Hostname(), domain) {
		return "", fmt.Errorf("%w: %q", errOutsideDomain, r.Host)
	}
	return p.scheme + "://" + r.Host + path, nil
}

// navigation reports whether r is a top-level navigation of a browser that can be redirected to the provider.
func navigation(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		r.Header.Get("Sec-Fetch-Dest") == "document"
}

// setIdentityHeaders removes the identity headers from h, and from its Connection header, then sets them with the
// claims.
func (rp *relyingParty) setIdentityHeaders(r *http.Request, h http.Header, claims map[string]any) {
	for name := range h {
		if rp.identityHeader(name) {
			delete(h, name)
		}
	}
	// A reverse proxy removes the headers named in the Connection header, after the middleware.
	if lines := h["Connection"]; len(lines) > 0 {
		var kept []string
		for _, line := range lines {
			for token := range strings.SplitSeq(line, ",") {
				if token = strings.TrimSpace(token); token != "" && !rp.identityHeader(token) {
					kept = append(kept, token)
				}
			}
		}
		if len(kept) == 0 {
			delete(h, "Connection")
		} else {
			h["Connection"] = []string{strings.Join(kept, ", ")}
		}
	}
	for _, ih := range rp.cfg.identityHeaders {
		v, ok := claims[ih.claim]
		if !ok {
			continue
		}
		value, ok := headerValue(v)
		if !ok {
			rp.logger.WarnContext(r.Context(), "invalid identity header value", "path", r.URL.Path, "header", ih.name, "claim", ih.claim)
			continue
		}
		h[ih.name] = []string{value}
	}
}

func (rp *relyingParty) identityHeader(name string) bool {
	for _, ih := range rp.cfg.identityHeaders {
		if headerName(name) == headerName(ih.name) {
			return true
		}
	}
	return false
}

// headerValue returns the header value of a string, number or boolean claim, or of an array of strings.
func headerValue(v any) (string, bool) {
	var value string
	switch v := v.(type) {
	case string:
		value = v
	case float64, bool:
		b, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		value = string(b)
	case []any:
		values := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return "", false
			}
			values[i] = s
		}
		value = strings.Join(values, ",")
	default:
		return "", false
	}
	return value, httpguts.ValidHeaderFieldValue(value)
}

// headerName returns the name of a header in lowercase, with dashes in place of underscores, as some servers read
// them.
func headerName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// CallbackHandler returns the handler of the redirect URL. It completes the login, creates a new session and redirects
// to the URL of the request that started the login. It responds with 403 Forbidden without a session if the provider
// returns an error, such as access_denied, or if a rule of [WithAccessRule] denies access to the user.
func (p *Proxy) CallbackHandler() fox.HandlerFunc {
	rules := p.rp.cfg.rules
	if len(rules) == 0 {
		return p.rp.callbackHandler(nil, true)
	}
	return p.rp.callbackHandler(func(s *session) bool {
		claims, err := s.claims()
		return err == nil && allowed(claims, rules)
	}, true)
}

// LogoutHandler returns a handler that ends the session, revokes its refresh token and redirects to the end session
// endpoint of the provider, as defined by OpenID Connect RP-Initiated Logout. The browser must navigate to it from the
// same origin, with any method.
func (p *Proxy) LogoutHandler() fox.HandlerFunc {
	rp := p.rp
	return func(c *fox.Context) {
		r := c.Request()
		w := c.Writer()
		w.Header().Set("Cache-Control", "no-store")
		// http.CrossOriginProtection does not check the GET requests, which a logout can use.
		if !sameOrigin(r) {
			rp.logRejected(r, "cross-site request", errCrossOrigin)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		rp.logout(w, r, nil)
	}
}

// sameOrigin reports whether r is a same-origin request, as [http.CrossOriginProtection] checks the requests with an
// unsafe method.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// BackchannelHandler returns a handler that ends the sessions designated by a logout token, as defined by OpenID
// Connect Back-Channel Logout. The provider must call it with a POST request. It panics if the proxy has no store.
func (p *Proxy) BackchannelHandler() fox.HandlerFunc {
	return p.rp.backchannelHandler()
}

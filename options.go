// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var ErrInvalidConfig = errors.New("invalid config")

const (
	// DefaultIdleTimeout is the default idle timeout of a session.
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultAbsoluteTimeout is the default absolute timeout of a session.
	DefaultAbsoluteTimeout = 8 * time.Hour
)

// FrontendOption configures a [Frontend].
type FrontendOption interface {
	applyFrontend(*config) error
}

// ProxyOption configures a [Proxy].
type ProxyOption interface {
	applyProxy(*config) error
}

// Option configures a [Frontend] or a [Proxy].
type Option interface {
	FrontendOption
	ProxyOption
}

type optionFunc func(*config) error

func (f optionFunc) applyFrontend(c *config) error {
	return f(c)
}

func (f optionFunc) applyProxy(c *config) error {
	return f(c)
}

type frontendOptionFunc func(*config) error

func (f frontendOptionFunc) applyFrontend(c *config) error {
	return f(c)
}

type proxyOptionFunc func(*config) error

func (f proxyOptionFunc) applyProxy(c *config) error {
	return f(c)
}

type config struct {
	logHandler      slog.Handler
	store           store.Store
	unauthorized    fox.HandlerFunc
	csrfHeader      string
	csrfValue       string
	cookieDomain    string
	signingAlgs     []string
	resources       []string
	trustedOrigins  []string
	identityHeaders []identityHeader
	rules           []Rule
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	userInfo        bool
	dpop            bool
	requestObject   bool
	par             PushedAuthorization
}

func defaultConfig() *config {
	return &config{
		logHandler:      slog.DiscardHandler,
		unauthorized:    DefaultUnauthorized,
		idleTimeout:     DefaultIdleTimeout,
		absoluteTimeout: DefaultAbsoluteTimeout,
	}
}

// WithStore enables stateful sessions, stored in s. The session cookie then contains only the session ID. By default,
// sessions are stateless and stored in the cookie. [Frontend.BackchannelHandler] and [Proxy.BackchannelHandler] require
// a store.
func WithStore(s store.Store) Option {
	return optionFunc(func(c *config) error {
		if s == nil {
			return fmt.Errorf("%w: nil store", ErrInvalidConfig)
		}
		c.store = s
		return nil
	})
}

// WithLogHandler sets the handler of the logs written when a request is rejected or fails. By default, nothing is
// logged.
func WithLogHandler(h slog.Handler) Option {
	return optionFunc(func(c *config) error {
		if h == nil {
			return fmt.Errorf("%w: nil log handler", ErrInvalidConfig)
		}
		c.logHandler = h
		return nil
	})
}

// WithIdleTimeout sets the duration of inactivity after which a session ends. The default is [DefaultIdleTimeout].
func WithIdleTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: idle timeout must be positive", ErrInvalidConfig)
		}
		c.idleTimeout = d
		return nil
	})
}

// WithAbsoluteTimeout sets the maximum lifetime of a session. The default is [DefaultAbsoluteTimeout].
func WithAbsoluteTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: absolute timeout must be positive", ErrInvalidConfig)
		}
		c.absoluteTimeout = d
		return nil
	})
}

// WithUserInfo requests the UserInfo endpoint at login and after each refresh, and adds its claims to the claims of the
// user, such as the ones returned by [UserClaims].
func WithUserInfo(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.userInfo = enable
		return nil
	})
}

// WithDPoP binds the access tokens to a key generated for each session, as defined by RFC 9449. The remote APIs must
// accept DPoP-bound access tokens. Changing this option ends the existing sessions.
func WithDPoP(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.dpop = enable
		return nil
	})
}

// WithSigningAlgorithms restricts the algorithms accepted for the signature of the ID tokens and logout tokens. They
// should include the algorithm registered for the client at the provider. By default, the algorithms advertised by
// the provider are accepted.
func WithSigningAlgorithms(algs ...string) Option {
	return optionFunc(func(c *config) error {
		for _, alg := range algs {
			if !slices.Contains(signingAlgs, alg) {
				return fmt.Errorf("%w: unsupported signing algorithm %q", ErrInvalidConfig, alg)
			}
		}
		c.signingAlgs = appendUnique(c.signingAlgs, algs...)
		return nil
	})
}

// WithResources declares the protected resources the frontend requests access tokens for, as defined by RFC 8707.
// Each resource is an absolute URI without fragment, usually the base URI of an API. The resources are requested at
// login, and a route obtains the access tokens of its resources with [ForResource].
func WithResources(resources ...string) Option {
	return optionFunc(func(c *config) error {
		for _, resource := range resources {
			u, err := url.Parse(resource)
			if err != nil || !u.IsAbs() || strings.Contains(resource, "#") {
				return fmt.Errorf("%w: invalid resource %q", ErrInvalidConfig, resource)
			}
		}
		c.resources = appendUnique(c.resources, resources...)
		return nil
	})
}

func appendUnique(s []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(s, v) {
			s = append(s, v)
		}
	}
	return s
}

var signingAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
	oidc.EdDSA,
}

// WithTrustedOrigins accepts the requests from the given origins, for a browser-based application that is
// cross-origin with the BFF, and lets a login return to a URL of these origins. An origin has the form
// "scheme://host[:port]" sent in the Origin header, in lowercase and without the default port, with https or, on a
// loopback host, http. The application and the BFF must be same site, such as https://app.example.com and
// https://bff.example.com, as the session cookie is SameSite=Strict. [NewFrontend] fails if an origin is not same site
// with the redirect URL of the client. A CORS middleware must allow only these origins, with credentials. The BFF
// should also require the header of [WithCSRFHeader], as recommended by RFC 10017.
func WithTrustedOrigins(origins ...string) FrontendOption {
	return frontendOptionFunc(func(c *config) error {
		for _, origin := range origins {
			if !validOrigin(origin) {
				return fmt.Errorf("%w: invalid trusted origin %q", ErrInvalidConfig, origin)
			}
		}
		c.trustedOrigins = appendUnique(c.trustedOrigins, origins...)
		return nil
	})
}

// validOrigin reports whether origin is serialized as a browser sends it, as defined by RFC 6454, with https or
// loopback http.
func validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || checkURL(origin) != nil || u.Scheme+"://"+u.Host != origin {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasSuffix(u.Host, ":") || u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
		return false
	}
	return net.ParseIP(host) != nil || strings.Trim(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
}

// sameSite reports whether the origin and the URL are same site, as browsers compare them for SameSite cookies. A
// host without a registrable domain, such as localhost or an IP address, is only same site with itself.
func sameSite(origin, u *url.URL) bool {
	if origin.Scheme != u.Scheme {
		return false
	}
	a := origin.Hostname()
	// The URL may have an uppercase or Unicode host, which browsers convert to ASCII lowercase.
	b, err := idna.Lookup.ToASCII(u.Hostname())
	if err != nil {
		b = strings.ToLower(u.Hostname())
	}
	siteA, errA := publicsuffix.EffectiveTLDPlusOne(a)
	siteB, errB := publicsuffix.EffectiveTLDPlusOne(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return siteA == siteB
}

// PushedAuthorization defines when a [Frontend] or a [Proxy] pushes its authorization requests to the provider, as
// defined by RFC 9126.
type PushedAuthorization uint8

const (
	// PushedAuthorizationIfAvailable pushes the authorization requests when the provider has a pushed authorization
	// request endpoint.
	PushedAuthorizationIfAvailable PushedAuthorization = iota
	// PushedAuthorizationRequired pushes the authorization requests. [NewFrontend] and [NewProxy] fail if the provider
	// has no pushed authorization request endpoint.
	PushedAuthorizationRequired
	// PushedAuthorizationDisabled never pushes the authorization requests. [NewFrontend] and [NewProxy] fail if the
	// provider requires pushed authorization requests.
	PushedAuthorizationDisabled
)

// WithPushedAuthorization sets when the authorization requests are pushed to the provider. The default is
// [PushedAuthorizationIfAvailable].
func WithPushedAuthorization(mode PushedAuthorization) Option {
	return optionFunc(func(c *config) error {
		if mode > PushedAuthorizationDisabled {
			return fmt.Errorf("%w: invalid pushed authorization mode", ErrInvalidConfig)
		}
		c.par = mode
		return nil
	})
}

// WithRequestObject sends the authorization parameters in a request object signed with the client key, as defined
// by RFC 9101. [NewFrontend] and [NewProxy] fail if the client has no key or if the authorization requests are not
// pushed to the provider. They also fail if the provider requires request objects and this option is disabled.
func WithRequestObject(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.requestObject = enable
		return nil
	})
}

// WithCSRFHeader requires the header with the given value on the requests handled by [Frontend.Authenticate] and
// [Frontend.UserHandler]. A browser sends a cross-origin request with a custom header only after a CORS preflight,
// which prevents cross-site request forgery (RFC 10017, Section 6.1.3.3.2).
func WithCSRFHeader(name, value string) FrontendOption {
	return frontendOptionFunc(func(c *config) error {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("%w: invalid csrf header name", ErrInvalidConfig)
		}
		if value == "" || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("%w: invalid csrf header value", ErrInvalidConfig)
		}
		c.csrfHeader = http.CanonicalHeaderKey(name)
		c.csrfValue = value
		return nil
	})
}

// WithUnauthorizedHandler sets the handler called for the requests without a valid session. A [Proxy] calls it only
// for the requests that are not navigations. The default is [DefaultUnauthorized].
func WithUnauthorizedHandler(handler fox.HandlerFunc) Option {
	return optionFunc(func(c *config) error {
		if handler == nil {
			return fmt.Errorf("%w: nil unauthorized handler", ErrInvalidConfig)
		}
		c.unauthorized = handler
		return nil
	})
}

// DefaultUnauthorized responds with 401 Unauthorized.
func DefaultUnauthorized(c *fox.Context) {
	http.Error(c.Writer(), http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

type identityHeader struct {
	name  string
	claim string
}

// WithIdentityHeader sets the header of the given name on the requests passed to the next handler of
// [Proxy.Authenticate], with the value of a claim of the user. A string claim is sent as is, a number or a boolean is
// formatted as in JSON, and an array of strings is joined with commas. The header is omitted when the request has no
// session, when the claim has another type and when its value has characters invalid in a header. The middleware
// always removes the header from the incoming request, including its form with underscores in place of dashes.
func WithIdentityHeader(name, claim string) ProxyOption {
	return proxyOptionFunc(func(c *config) error {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("%w: invalid identity header name", ErrInvalidConfig)
		}
		if claim == "" {
			return fmt.Errorf("%w: empty identity header claim", ErrInvalidConfig)
		}
		name = http.CanonicalHeaderKey(name)
		for _, h := range c.identityHeaders {
			if headerName(h.name) == headerName(name) {
				return fmt.Errorf("%w: duplicate identity header %q", ErrInvalidConfig, name)
			}
		}
		c.identityHeaders = append(c.identityHeaders, identityHeader{name: name, claim: claim})
		return nil
	})
}

// WithAccessRule requires the rule to grant access to the user, at login and on each request handled by
// [Proxy.Authenticate]. The rules of several calls must all grant access.
func WithAccessRule(rule Rule) ProxyOption {
	return proxyOptionFunc(func(c *config) error {
		if rule == nil {
			return fmt.Errorf("%w: nil access rule", ErrInvalidConfig)
		}
		c.rules = append(c.rules, rule)
		return nil
	})
}

// WithCookieDomain shares the sessions of the proxy between the hosts of the domain, such as apps.example.com for
// app1.apps.example.com and app2.apps.example.com. The login completes on the host of the redirect URL, which must be
// in the domain. [NewProxy] fails if the domain is a public suffix. The proxy responds with 500 Internal Server Error to
// a request for a host outside the domain.
func WithCookieDomain(domain string) ProxyOption {
	return proxyOptionFunc(func(c *config) error {
		d, err := idna.Lookup.ToASCII(domain)
		if err == nil {
			// EffectiveTLDPlusOne also rejects an IP address and an empty label.
			_, err = publicsuffix.EffectiveTLDPlusOne(d)
		}
		if err != nil {
			return fmt.Errorf("%w: invalid cookie domain %q", ErrInvalidConfig, domain)
		}
		c.cookieDomain = d
		return nil
	})
}

// inDomain reports whether the host is the domain or one of its subdomains.
func inDomain(host, domain string) bool {
	host = strings.ToLower(host)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fox-toolkit/bff/store"
	"github.com/fox-toolkit/fox"
	"golang.org/x/net/http/httpguts"
)

var ErrInvalidConfig = errors.New("invalid config")

const (
	// DefaultIdleTimeout is the default idle timeout of a session.
	DefaultIdleTimeout = 30 * time.Minute
	// DefaultAbsoluteTimeout is the default absolute timeout of a session.
	DefaultAbsoluteTimeout = 8 * time.Hour
)

// Option configures a [Frontend].
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error {
	return f(c)
}

type config struct {
	logHandler       slog.Handler
	store            store.Store
	unauthorized     fox.HandlerFunc
	csrfHeader       string
	csrfValue        string
	signingAlgs      []string
	resources        []string
	idleTimeout      time.Duration
	absoluteTimeout  time.Duration
	userInfo         bool
	dpop             bool
	crossOriginLogin bool
	requestObject    bool
	par              PushedAuthorization
}

func defaultConfig() *config {
	return &config{
		logHandler:      slog.DiscardHandler,
		unauthorized:    DefaultUnauthorized,
		idleTimeout:     DefaultIdleTimeout,
		absoluteTimeout: DefaultAbsoluteTimeout,
	}
}

// WithStore keeps the sessions in the store, and the session cookie only contains a key to its session. By default,
// the session is kept in the cookie.
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

// WithUserInfo requests the UserInfo endpoint at login and adds its claims to the ID token claims.
func WithUserInfo(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.userInfo = enable
		return nil
	})
}

// WithDPoP binds the access tokens to a key generated for each session, as defined by RFC 9449. The remote APIs must
// accept DPoP-bound access tokens.
func WithDPoP(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.dpop = enable
		return nil
	})
}

// WithSigningAlgorithms restricts the algorithms accepted for the signature of the ID tokens and logout tokens. They
// should include the algorithm registered for the client at the provider. Each call adds to the algorithms of the
// previous ones. By default, the algorithms advertised by the provider are accepted.
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
// login, and the access token of a resource is obtained with [ResourceTransport] or [ResourceAccessToken]. Each call
// adds to the resources of the previous ones.
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

// WithCrossOriginLogin lets a login started from another origin redirect to the provider. By default, such a login
// redirects to its return URL without starting the flow.
func WithCrossOriginLogin(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.crossOriginLogin = enable
		return nil
	})
}

// PushedAuthorization defines when a [Frontend] pushes its authorization requests to the provider, as defined by
// RFC 9126.
type PushedAuthorization uint8

const (
	// PushedAuthorizationIfAvailable pushes the authorization requests when the provider has a pushed authorization
	// request endpoint.
	PushedAuthorizationIfAvailable PushedAuthorization = iota
	// PushedAuthorizationRequired pushes the authorization requests. [NewFrontend] fails if the provider has no pushed
	// authorization request endpoint.
	PushedAuthorizationRequired
	// PushedAuthorizationDisabled never pushes the authorization requests. [NewFrontend] fails if the provider requires
	// pushed authorization requests.
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
// by RFC 9101. [NewFrontend] fails if the client has no key or if the authorization requests are not pushed to the
// provider. It also fails if the provider requires request objects and this option is disabled.
func WithRequestObject(enable bool) Option {
	return optionFunc(func(c *config) error {
		c.requestObject = enable
		return nil
	})
}

// WithCSRFHeader requires the header with the given value on the requests handled by [Frontend.Authenticate] and
// [Frontend.UserHandler].
func WithCSRFHeader(name, value string) Option {
	return optionFunc(func(c *config) error {
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

// WithUnauthorizedHandler sets the handler called for the requests without a valid session. The default is
// [DefaultUnauthorized].
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

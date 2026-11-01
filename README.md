[![Go Reference](https://pkg.go.dev/badge/github.com/fox-toolkit/rp.svg)](https://pkg.go.dev/github.com/fox-toolkit/rp)
[![tests](https://github.com/fox-toolkit/rp/actions/workflows/tests.yaml/badge.svg)](https://github.com/fox-toolkit/rp/actions?query=workflow%3Atests)
[![codecov](https://codecov.io/gh/fox-toolkit/rp/graph/badge.svg?token=7M87P7Q31N)](https://codecov.io/gh/fox-toolkit/rp)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/fox-toolkit/rp)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/fox-toolkit/rp)

# RP

RP is an open-source OpenID Connect Relying Party for the [Fox](https://github.com/fox-toolkit/fox) router. It provides
the handlers and middleware to build authentication gateways such as Backend for Frontend (BFF), as described in
[OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html), or Identity-Aware Proxy (IAP).

RP supports any OpenID Provider through OpenID Connect Discovery, with sessions stored in encrypted cookies or in a
server-side store, such as Redis or any implementation of the
[Store](https://pkg.go.dev/github.com/fox-toolkit/rp/store#Store) interface.

## Disclaimer
The current API is not yet stabilized. Breaking changes may occur before v1.0.0 and will be noted on the release note.

## Getting started
### Installation

````shell
go get -u github.com/fox-toolkit/rp
````

### Usage
#### Backend for Frontend
````go
package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/fox-toolkit/rp"
	"github.com/fox-toolkit/fox"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
)

func main() {
	provider, err := rp.NewProvider(context.Background(), "https://idp.example.com")
	if err != nil {
		log.Fatal(err)
	}
	
	aead, err := subtle.NewAESGCM([]byte(os.Getenv("BFF_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	fe, err := rp.NewFrontend(rp.Client{
		Provider:              provider,
		ClientID:              "app",
		ClientSecret:          os.Getenv("CLIENT_SECRET"),
		RedirectURL:           "https://app.example.com/bff/callback",
		PostLogoutRedirectURL: "https://app.example.com/",
		Scopes:                []string{"openid", "profile"},
	}, aead)
	if err != nil {
		log.Fatal(err)
	}
	
	api, _ := url.Parse("https://api.example.com")
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(api)
		},
		Transport: rp.Transport(nil),
	}

	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/bff/login", fe.LoginHandler())
	f.MustAdd(fox.MethodGet, "/bff/callback", fe.CallbackHandler())
	f.MustAdd([]string{http.MethodGet, http.MethodPost}, "/bff/logout", fe.LogoutHandler())
	f.MustAdd(fox.MethodGet, "/bff/user", fe.UserHandler())
	
	// Proxy to the resource server, with the user's access token.
	f.MustAdd(fox.MethodAny, "/api/*{path}", fox.WrapH(proxy), fox.WithMiddleware(fe.Authenticate()))

	// The browser-based application is served here by the BFF. For other deployments, see
	// https://www.rfc-editor.org/rfc/rfc10017.html#section-6.1.2.5. A cross-origin
	// application requires rp.WithTrustedOrigins and a CORS middleware that allows its origin with credentials.
	f.MustAdd(fox.MethodGet, "/*{filepath}", fox.WrapH(http.FileServer(http.Dir("dist"))))
	
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", f))
}
````

#### Identity-Aware Proxy
````go
p, err := rp.NewProxy(rp.Client{
	Provider:              provider,
	ClientID:              "dashboard",
	ClientSecret:          os.Getenv("CLIENT_SECRET"),
	RedirectURL:           "https://dashboard.example.com/oauth2/callback",
	PostLogoutRedirectURL: "https://dashboard.example.com/",
	Scopes:                []string{"openid", "email", "groups"},
}, aead,
	rp.WithAccessRule(rp.EmailDomain("example.com")),
	rp.WithIdentityHeader("X-Forwarded-Email", "email"),
	rp.WithIdentityHeader("X-Forwarded-Groups", "groups"),
)
if err != nil {
	log.Fatal(err)
}

upstream, _ := url.Parse("http://dashboard.internal:8080")
proxy := &httputil.ReverseProxy{
	Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(upstream)
		r.SetXForwarded()
		r.Out.Host = r.In.Host
	},
}

f := fox.MustRouter()
f.MustAdd(fox.MethodGet, "/oauth2/callback", p.CallbackHandler())
f.MustAdd(fox.MethodAny, "/oauth2/logout", p.LogoutHandler())

// A navigation without a session starts the OpenID Connect Authorization Code Flow, see
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
f.MustAdd(fox.MethodAny, "/*{path}", fox.WrapH(proxy), fox.WithMiddleware(p.Authenticate()))
````

## Open Standards
RP implements Open Standards set by the IETF:

* [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
* [The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
* [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
* [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
* [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
* [Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
* [The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)
* [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
* [OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
* [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
* [Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)

and the OpenID Foundation:

* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
* [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
* [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html) (signed authorization requests)

## Conformance
RP passes the client test plans of the [OpenID Foundation conformance suite](https://openid.net/certification/)
v5.3.4 (see the [conformance](conformance) module). The FAPI 2.0 Security Profile and FAPI 2.0 Message Signing plans
use the configuration below, and the OpenID Connect Basic, Config, refresh token, Back-Channel Logout and RP-Initiated
Logout plans use a client secret.

````go
fe, err := rp.NewFrontend(rp.Client{
	Provider:    provider,
	ClientID:    "app",
	ClientKey:   key, // EC P-256, RSA or Ed25519 private key
	RedirectURL: "https://app.example.com/bff/callback",
	Scopes:      []string{"openid"},
}, aead,
	rp.WithPushedAuthorization(rp.PushedAuthorizationRequired),
	rp.WithDPoP(true),
	rp.WithRequestObject(true), // FAPI 2.0 Message Signing only
	rp.WithSigningAlgorithms("PS256", "ES256", "EdDSA"),
)
````

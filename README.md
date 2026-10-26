[![Go Reference](https://pkg.go.dev/badge/github.com/fox-toolkit/bff.svg)](https://pkg.go.dev/github.com/fox-toolkit/bff)
[![tests](https://github.com/fox-toolkit/bff/actions/workflows/tests.yaml/badge.svg)](https://github.com/fox-toolkit/bff/actions?query=workflow%3Atests)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/fox-toolkit/bff)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/fox-toolkit/bff)

# BFF

BFF is an OpenID Connect Relying Party and OAuth 2.0 client for the [Fox](https://github.com/fox-toolkit/fox) router.
It provides a set of handlers and middleware to build a Backend For Frontend, the server-side gateway between a browser
application and its APIs, as described in
[OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps).

## Disclaimer
The current API is not yet stabilized. Breaking changes may occur before v1.0.0 and will be noted on the release note.

## Getting started
### Installation

````shell
go get -u github.com/fox-toolkit/bff
````

### Usage
````go
package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/fox-toolkit/bff"
	"github.com/fox-toolkit/fox"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
)

func main() {
	provider, err := bff.NewProvider(context.Background(), "https://idp.example.com")
	if err != nil {
		log.Fatal(err)
	}
	
	aead, err := subtle.NewAESGCM([]byte(os.Getenv("BFF_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	fe, err := bff.NewFrontend(bff.Client{
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
		Rewrite:      func(r *httputil.ProxyRequest) { r.SetURL(api) },
		Transport:    bff.Transport(nil),
		ErrorHandler: bff.ProxyErrorHandler,
	}

	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/bff/login", fe.LoginHandler())
	f.MustAdd(fox.MethodGet, "/bff/callback", fe.CallbackHandler())
	f.MustAdd([]string{http.MethodGet, http.MethodPost}, "/bff/logout", fe.LogoutHandler())
	f.MustAdd(fox.MethodGet, "/bff/user", fe.UserHandler())
	
	// Proxy to the resource server, with the user's access token.
	f.MustAdd(fox.MethodAny, "/api/*{path}", fox.WrapH(proxy), fox.WithMiddleware(fe.Authenticate()))

	// The browser application, served from the same origin as the BFF.
	f.MustAdd(fox.MethodGet, "/*{filepath}", fox.WrapH(http.FileServer(http.Dir("dist"))))
	
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", f))
}
````

## Open Standards
BFF implements Open Standards set by the IETF:

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
BFF passes the client test plans of the [OpenID Foundation conformance suite](https://openid.net/certification/)
v5.3.3: FAPI 2.0 Security Profile and FAPI 2.0 Message Signing with the configuration below, and OpenID Connect Basic,
refresh token, Back-Channel Logout and RP-Initiated Logout with a client secret.

````go
fe, err := bff.NewFrontend(bff.Client{
	Provider:    provider,
	ClientID:    "app",
	ClientKey:   key, // EC P-256, RSA or Ed25519 private key, its public key registered at the provider
	RedirectURL: "https://app.example.com/bff/callback",
	Scopes:      []string{"openid"},
}, aead,
	bff.WithPushedAuthorization(bff.PushedAuthorizationRequired),
	bff.WithDPoP(true),
	bff.WithRequestObject(true), // FAPI 2.0 Message Signing only
	bff.WithSigningAlgorithms("PS256", "ES256", "EdDSA"),
)
````

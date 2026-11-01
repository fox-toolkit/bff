// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store/memory"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func BenchmarkFrontend(b *testing.B) {
	for _, tc := range []struct {
		name      string
		opts      []FrontendOption
		resources []string
	}{
		{name: "stateless"},
		{name: "stateful", opts: []FrontendOption{WithStore(memory.NewStore())}},
		{name: "stateless resource", opts: []FrontendOption{WithResources(billing)}, resources: []string{billing}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			e := newTestEnv(b, oidctest.Options{AccessTokenTTL: 24 * time.Hour}, tc.opts...)
			routeOpts := []fox.RouteOption{fox.WithMiddleware(e.fe.Authenticate())}
			if len(tc.resources) > 0 {
				routeOpts = append(routeOpts, ForResource(tc.resources...))
			}
			_, err := e.router.Add(fox.MethodGet, "/api", func(c *fox.Context) {
				c.Writer().WriteHeader(http.StatusOK)
			}, routeOpts...)
			require.NoError(b, err)

			req, err := http.NewRequest(http.MethodGet, appOrigin+"/api", nil)
			require.NoError(b, err)
			cookies := e.loggedIn(b)
			if len(tc.resources) > 0 {
				// The first request obtains the access token of the resource.
				rec := e.do(http.MethodGet, "/api", cookies, nil)
				require.Equal(b, http.StatusOK, rec.Code)
				cookies = requestCookies(b, rec.Header())
			}
			for _, c := range cookies {
				req.AddCookie(c)
			}

			b.ReportAllocs()
			for b.Loop() {
				e.router.ServeHTTP(new(discardWriter), req)
			}
		})
	}
}

func BenchmarkProxy(b *testing.B) {
	claims := map[string]any{"email": "alice@example.com", "groups": []any{"dev", "ops"}}
	rules := []ProxyOption{
		WithAccessRule(Group("dev")),
		WithIdentityHeader("X-Auth-Request-Email", "email"),
		WithIdentityHeader("X-Auth-Request-Groups", "groups"),
	}
	for _, tc := range []struct {
		name string
		opts []ProxyOption
		idp  oidctest.Options
	}{
		{name: "stateless"},
		{name: "stateless rules", opts: rules, idp: oidctest.Options{Claims: claims}},
		{name: "stateless rules userinfo", opts: append([]ProxyOption{WithUserInfo(true)}, rules...), idp: oidctest.Options{UserInfo: claims}},
		{name: "stateful", opts: []ProxyOption{WithStore(memory.NewStore())}},
		{name: "stateful rules", opts: append([]ProxyOption{WithStore(memory.NewStore())}, rules...), idp: oidctest.Options{Claims: claims}},
		{name: "stateful rules userinfo", opts: append([]ProxyOption{WithStore(memory.NewStore()), WithUserInfo(true)}, rules...), idp: oidctest.Options{UserInfo: claims}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			tc.idp.AccessTokenTTL = 24 * time.Hour
			e := newProxyEnv(b, tc.idp, tc.opts...)
			_, err := e.router.Add(fox.MethodGet, "/api", func(c *fox.Context) {
				c.Writer().WriteHeader(http.StatusOK)
			}, fox.WithMiddleware(e.p.Authenticate()))
			require.NoError(b, err)

			req, err := http.NewRequest(http.MethodGet, appOrigin+"/api", nil)
			require.NoError(b, err)
			for _, c := range e.loggedIn(b) {
				req.AddCookie(c)
			}

			b.ReportAllocs()
			for b.Loop() {
				e.router.ServeHTTP(new(discardWriter), req)
			}
		})
	}
}

func BenchmarkWriteSession(b *testing.B) {
	resources := []string{"https://a.example.com/", "https://b.example.com/", "https://c.example.com/"}
	for _, n := range []int{0, len(resources)} {
		b.Run(fmt.Sprintf("%d resources", n), func(b *testing.B) {
			fe := newTestFrontend(b, WithResources(resources...))
			s := testSession()
			for _, resource := range resources[:n] {
				s.setResourceToken(resource, &oauth2.Token{
					AccessToken: strings.Repeat("a", 1000),
					Expiry:      time.Now().Add(time.Hour),
				}, time.Now())
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := fe.rp.writeSession(b.Context(), make(http.Header), s, sessionState{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type okTransport struct{}

func (okTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
}

func BenchmarkTransport(b *testing.B) {
	_, raw, err := newDPoPKey()
	require.NoError(b, err)
	for _, tc := range []struct {
		name string
		s    *session
	}{
		{name: "bearer", s: &session{AccessToken: "access-token", TokenType: "Bearer"}},
		{name: "dpop", s: &session{AccessToken: "access-token", TokenType: "DPoP", DPoPKey: raw}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			rt := Transport(okTransport{})
			ctx := context.WithValue(b.Context(), sessionKey{}, &requestState{session: tc.s})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/orders", nil)
			require.NoError(b, err)

			b.ReportAllocs()
			for b.Loop() {
				_, _ = rt.RoundTrip(req)
			}
		})
	}
}

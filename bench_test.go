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

func BenchmarkMiddleware(b *testing.B) {
	for _, stateful := range []bool{false, true} {
		name := "stateless"
		var opts []Option
		if stateful {
			name = "stateful"
			opts = append(opts, WithStore(memory.NewStore()))
		}
		b.Run(name, func(b *testing.B) {
			e := newTestEnv(b, oidctest.Options{AccessTokenTTL: 24 * time.Hour}, opts...)
			_, err := e.router.Add(fox.MethodGet, "/api", func(c *fox.Context) {
				c.Writer().WriteHeader(http.StatusOK)
			}, fox.WithMiddleware(e.fe.Authenticate()))
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
				if err := fe.writeSession(b.Context(), make(http.Header), s, sessionState{}); err != nil {
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

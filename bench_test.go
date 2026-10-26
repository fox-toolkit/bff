// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/fox-toolkit/bff/internal/oidctest"
	"github.com/fox-toolkit/bff/store/memory"
	"github.com/fox-toolkit/fox"
	"github.com/stretchr/testify/require"
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
			}, fox.WithMiddleware(e.fe.Middleware()))
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

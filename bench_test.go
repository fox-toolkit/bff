// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
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

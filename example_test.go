// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff_test

import (
	"errors"
	"net/http"

	"github.com/fox-toolkit/bff"
	"github.com/fox-toolkit/fox"
)

func ExampleResourceAccessToken() {
	var fe *bff.Frontend // created with bff.NewFrontend and bff.WithResources("https://billing.example.com")

	f := fox.MustRouter()
	f.MustAdd(fox.MethodGet, "/invoices", func(c *fox.Context) {
		// The token is requested before the response is written. With a session stored in the cookie, a new token is
		// saved in the Set-Cookie header, which cannot change once the response is written.
		token, err := bff.ResourceAccessToken(c.Request().Context(), "https://billing.example.com")
		if errors.Is(err, bff.ErrNoSession) {
			fe.Unauthorized(c)
			return
		}
		if err != nil {
			http.Error(c.Writer(), http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		// Call the billing API with the token, then write the response.
		_ = token
	}, fox.WithMiddleware(fe.Authenticate()))
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"slices"
	"strings"

	"github.com/fox-toolkit/fox"
)

type rulesKey struct{}

// Rule reports whether the user with the given claims has access. The claims are the ones of [UserClaims].
type Rule func(claims map[string]any) bool

// EmailDomain returns a [Rule] that grants access to a user with a verified email address of one of the domains.
func EmailDomain(domains ...string) Rule {
	domains = slices.Clone(domains)
	return func(claims map[string]any) bool {
		email, ok := verifiedEmail(claims)
		if !ok {
			return false
		}
		i := strings.LastIndexByte(email, '@')
		return i >= 0 && slices.ContainsFunc(domains, func(d string) bool { return equalFoldASCII(email[i+1:], d) })
	}
}

// Email returns a [Rule] that grants access to a user with one of the verified email addresses.
func Email(emails ...string) Rule {
	emails = slices.Clone(emails)
	return func(claims map[string]any) bool {
		email, ok := verifiedEmail(claims)
		return ok && slices.ContainsFunc(emails, func(e string) bool { return equalFoldASCII(email, e) })
	}
}

// Group returns a [Rule] that grants access to a user in one of the groups of the groups claim.
func Group(groups ...string) Rule {
	return Claim("groups", groups...)
}

// Claim returns a [Rule] that grants access to a user whose claim is one of the values, or an array that contains one
// of the values.
func Claim(name string, values ...string) Rule {
	values = slices.Clone(values)
	return func(claims map[string]any) bool {
		switch v := claims[name].(type) {
		case string:
			return slices.Contains(values, v)
		case []any:
			return slices.ContainsFunc(v, func(e any) bool {
				s, ok := e.(string)
				return ok && slices.Contains(values, s)
			})
		}
		return false
	}
}

// OpenID Connect Core 5.1 defines email_verified as a boolean.
func verifiedEmail(claims map[string]any) (string, bool) {
	email, _ := claims["email"].(string)
	verified, _ := claims["email_verified"].(bool)
	return email, email != "" && verified
}

// equalFoldASCII reports whether a and b are equal with ASCII case folding. strings.EqualFold also folds Unicode
// characters, such as the Kelvin sign U+212A to k.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// Require returns a [fox.RouteOption] that lets [Proxy.Authenticate] respond with 403 Forbidden to a user who is not
// granted access by all the rules, in addition to the rules of [WithAccessRule]. It panics if a rule is nil.
func Require(rules ...Rule) fox.RouteOption {
	for _, rule := range rules {
		if rule == nil {
			panic("bff: nil rule")
		}
	}
	return fox.WithAnnotation(rulesKey{}, slices.Clone(rules))
}

func routeRules(route *fox.Route) []Rule {
	if route == nil {
		return nil
	}
	rules, _ := route.Annotation(rulesKey{}).([]Rule)
	return rules
}

func allowed(claims map[string]any, rules ...[]Rule) bool {
	for _, rs := range rules {
		for _, rule := range rs {
			if !rule(claims) {
				return false
			}
		}
	}
	return true
}

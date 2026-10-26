// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

const (
	cookiePrefix = "__Host-"
	// maxChunkSize is the maximum length of a cookie value. It leaves room for the name and attributes within the
	// 4096 bytes that browsers accept for a cookie.
	maxChunkSize = 3800
)

var (
	errNoCookie      = errors.New("no cookie")
	errInvalidCookie = errors.New("invalid cookie")
)

// cookieSpec is an encrypted cookie, split into chunks named name.0, name.1 and so on when its value is too long.
type cookieSpec struct {
	name     string
	purpose  string
	sameSite http.SameSite
}

// sessionCookie is only sent on same-site requests. The SPA calls the BFF from its own origin.
var sessionCookie = cookieSpec{name: cookiePrefix + "bff", purpose: "session", sameSite: http.SameSiteStrictMode}

// loginCookie contains the state of one login flow. It must be sent on the cross-site navigation from the provider to
// the callback, hence the lax mode.
func loginCookie(id string) cookieSpec {
	return cookieSpec{name: cookiePrefix + "bff-login-" + id, purpose: "login", sameSite: http.SameSiteLaxMode}
}

func (s cookieSpec) associatedData() []byte {
	return []byte(s.purpose + "\x00" + s.name)
}

// write seals the plaintext and adds the chunks to h. A maxAge of 0 makes a browser session cookie. prev is the
// number of chunks sent by the client, the ones that are no longer needed are deleted.
func (s cookieSpec) write(h http.Header, aead AEAD, plaintext []byte, maxAge, prev int) error {
	ciphertext, err := aead.Encrypt(plaintext, s.associatedData())
	if err != nil {
		return err
	}
	value := base64.RawURLEncoding.EncodeToString(ciphertext)
	n := 0
	for len(value) > 0 {
		chunk := value[:min(len(value), maxChunkSize)]
		value = value[len(chunk):]
		h.Add("Set-Cookie", s.cookie(n, chunk, maxAge))
		n++
	}
	for i := n; i < prev; i++ {
		h.Add("Set-Cookie", s.cookie(i, "", -1))
	}
	return nil
}

func (s cookieSpec) clear(h http.Header, prev int) {
	for i := range prev {
		h.Add("Set-Cookie", s.cookie(i, "", -1))
	}
}

// read reassembles and opens the chunks among cookies. It also returns the number of chunks found, so they can be
// deleted when the cookie is invalid.
func (s cookieSpec) read(cookies []*http.Cookie, aead AEAD) ([]byte, int, error) {
	var chunks []string
	found := 0
	prefix := s.name + "."
	for _, c := range cookies {
		suffix, ok := strings.CutPrefix(c.Name, prefix)
		if !ok {
			continue
		}
		found++
		i, ok := chunkIndex(suffix)
		if !ok || i >= len(cookies) {
			return nil, found, errInvalidCookie
		}
		if i >= len(chunks) {
			chunks = append(chunks, make([]string, i+1-len(chunks))...)
		}
		if chunks[i] != "" || c.Value == "" {
			return nil, found, errInvalidCookie
		}
		chunks[i] = c.Value
	}
	if found == 0 {
		return nil, 0, errNoCookie
	}
	if found != len(chunks) {
		return nil, found, errInvalidCookie
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(strings.Join(chunks, ""))
	if err != nil {
		return nil, found, errInvalidCookie
	}
	plaintext, err := aead.Decrypt(ciphertext, s.associatedData())
	if err != nil {
		return nil, found, errInvalidCookie
	}
	return plaintext, found, nil
}

func (s cookieSpec) cookie(i int, value string, maxAge int) string {
	c := http.Cookie{ //nolint:gosec // false positive, SameSite is set from the spec (Strict or Lax)
		Name:     s.name + "." + strconv.Itoa(i),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: s.sameSite,
	}
	return c.String()
}

// chunkIndex parses a decimal index of at most 6 digits, without sign or leading zero.
func chunkIndex(s string) (int, bool) {
	if s == "" || len(s) > 6 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

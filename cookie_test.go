// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

package bff

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type gcmAEAD struct {
	aead cipher.AEAD
}

func newGCMAEAD(t testing.TB) gcmAEAD {
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return gcmAEAD{aead: aead}
}

func (a gcmAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	nonce := make([]byte, a.aead.NonceSize(), a.aead.NonceSize()+len(plaintext)+a.aead.Overhead())
	_, _ = rand.Read(nonce)
	return a.aead.Seal(nonce, nonce, plaintext, associatedData), nil
}

func (a gcmAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < a.aead.NonceSize() {
		return nil, errors.New("short ciphertext")
	}
	n := a.aead.NonceSize()
	return a.aead.Open(nil, ciphertext[:n], ciphertext[n:], associatedData)
}

func requestCookies(t testing.TB, h http.Header) []*http.Cookie {
	t.Helper()
	var cookies []*http.Cookie
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		if c.MaxAge >= 0 {
			cookies = append(cookies, &http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return cookies
}

func TestCookieRoundTrip(t *testing.T) {
	aead := newGCMAEAD(t)
	for _, size := range []int{1, maxChunkSize, 3 * maxChunkSize} {
		plaintext := bytes.Repeat([]byte{'a'}, size)
		h := make(http.Header)
		require.NoError(t, sessionCookie.write(h, aead, plaintext, 0, 0))

		lines := h.Values("Set-Cookie")
		for _, line := range lines {
			assert.LessOrEqual(t, len(line), 4096)
			assert.True(t, strings.HasPrefix(line, "__Host-Http-BFF."))
			assert.Contains(t, line, "; Path=/; HttpOnly; Secure; SameSite=Strict")
		}

		got, n, err := sessionCookie.read(requestCookies(t, h), aead)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
		assert.Equal(t, len(lines), n)
	}
}

func TestCookieWriteDeletesStaleChunks(t *testing.T) {
	aead := newGCMAEAD(t)
	h := make(http.Header)
	require.NoError(t, sessionCookie.write(h, aead, bytes.Repeat([]byte{'a'}, 2*maxChunkSize), 0, 0))
	prev := len(h.Values("Set-Cookie"))
	require.Equal(t, 3, prev)

	h = make(http.Header)
	require.NoError(t, sessionCookie.write(h, aead, []byte("a"), 3600, prev))
	lines := h.Values("Set-Cookie")
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "__Host-Http-BFF.0=")
	assert.Contains(t, lines[0], "Max-Age=3600")
	assert.Contains(t, lines[1], "__Host-Http-BFF.1=; Path=/; Max-Age=0")
	assert.Contains(t, lines[2], "__Host-Http-BFF.2=; Path=/; Max-Age=0")
}

func TestCookieReadIgnoresStaleChunks(t *testing.T) {
	aead := newGCMAEAD(t)
	h := make(http.Header)
	require.NoError(t, sessionCookie.write(h, aead, bytes.Repeat([]byte{'a'}, 2*maxChunkSize), 0, 0))
	old := requestCookies(t, h)
	require.Len(t, old, 3)

	h = make(http.Header)
	require.NoError(t, sessionCookie.write(h, aead, []byte("b"), 0, 0))
	cookies := append(requestCookies(t, h), old[1:]...)

	got, n, err := sessionCookie.read(cookies, aead)
	require.NoError(t, err)
	assert.Equal(t, []byte("b"), got)
	assert.Equal(t, 3, n)
}

func TestCookieClear(t *testing.T) {
	h := make(http.Header)
	loginCookie(sessionCookie, "abc").clear(h, 2)
	assert.Equal(t, []string{
		"__Host-Http-BFF-Login-abc.0=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
		"__Host-Http-BFF-Login-abc.1=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
	}, h.Values("Set-Cookie"))
}

func TestCookieReadInvalid(t *testing.T) {
	aead := newGCMAEAD(t)
	h := make(http.Header)
	require.NoError(t, sessionCookie.write(h, aead, bytes.Repeat([]byte{'a'}, 2*maxChunkSize), 0, 0))
	valid := requestCookies(t, h)
	require.Len(t, valid, 3)

	cookie := func(name, value string) *http.Cookie { return &http.Cookie{Name: name, Value: value} }

	t.Run("no cookie", func(t *testing.T) {
		_, n, err := sessionCookie.read([]*http.Cookie{cookie("other", "x")}, aead)
		assert.ErrorIs(t, err, errNoCookie)
		assert.Zero(t, n)
	})

	cases := []struct {
		name    string
		cookies []*http.Cookie
		spec    cookieSpec
	}{
		{name: "missing chunk", cookies: []*http.Cookie{valid[0], valid[2]}},
		{name: "duplicate chunk", cookies: []*http.Cookie{valid[0], valid[1], valid[1]}},
		{name: "swapped chunks", cookies: []*http.Cookie{cookie(valid[0].Name, valid[1].Value), cookie(valid[1].Name, valid[0].Value), valid[2]}},
		{name: "tampered value", cookies: []*http.Cookie{valid[0], valid[1], cookie(valid[2].Name, "AAAA"+valid[2].Value[4:])}},
		{name: "invalid base64", cookies: []*http.Cookie{cookie("__Host-Http-BFF.0", "!!!")}},
		{name: "empty value", cookies: []*http.Cookie{cookie("__Host-Http-BFF.0", "")}},
		{name: "leading zero", cookies: []*http.Cookie{cookie("__Host-Http-BFF.00", "x")}},
		{name: "signed index", cookies: []*http.Cookie{cookie("__Host-Http-BFF.+0", "x")}},
		{name: "not a number", cookies: []*http.Cookie{cookie("__Host-Http-BFF.x", "x")}},
		{name: "index out of range", cookies: []*http.Cookie{cookie("__Host-Http-BFF.999999", "x")}},
		{name: "no count", cookies: []*http.Cookie{cookie("__Host-Http-BFF.0", "abc")}},
		{name: "zero count", cookies: []*http.Cookie{cookie("__Host-Http-BFF.0", "0.abc")}},
		{name: "count beyond chunks", cookies: []*http.Cookie{cookie("__Host-Http-BFF.0", "2.abc")}},
		{name: "other purpose", cookies: valid, spec: cookieSpec{name: sessionCookie.name, purpose: "login"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := sessionCookie
			if tc.spec.name != "" {
				spec = tc.spec
			}
			_, _, err := spec.read(tc.cookies, aead)
			assert.ErrorIs(t, err, errInvalidCookie)
		})
	}
}

func FuzzCookieRead(f *testing.F) {
	aead := newGCMAEAD(f)
	h := make(http.Header)
	require.NoError(f, sessionCookie.write(h, aead, bytes.Repeat([]byte{'a'}, maxChunkSize), 0, 0))
	var seed []string
	for _, c := range requestCookies(f, h) {
		seed = append(seed, c.String())
	}
	f.Add(strings.Join(seed, "; "))
	f.Add("__Host-Http-BFF.1=a; __Host-Http-BFF.0=b; __Host-Http-BFF.0=c")

	f.Fuzz(func(t *testing.T, line string) {
		cookies, err := http.ParseCookie(line)
		if err != nil {
			return
		}
		plaintext, n, err := sessionCookie.read(cookies, aead)
		if err == nil {
			assert.Positive(t, n)
			assert.Equal(t, bytes.Repeat([]byte{'a'}, maxChunkSize), plaintext)
		}
	})
}

// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/fox-toolkit/bff/store"
	"golang.org/x/oauth2"
)

const sessionVersion = 1

var ErrNoSession = errors.New("no session")

// session is the state of a logged in user. Times are unix seconds, to keep the stateless cookie small.
type session struct {
	// Resources are the access tokens of the resources declared with [WithResources].
	Resources    map[string]resourceToken `json:"res,omitempty"`
	Subject      string                   `json:"sub,omitempty"`
	SID          string                   `json:"sid,omitempty"`
	IDToken      string                   `json:"idt,omitempty"`
	AccessToken  string                   `json:"at,omitempty"`
	TokenType    string                   `json:"tt,omitempty"`
	RefreshToken string                   `json:"rt,omitempty"`
	// LogoutCSRFToken protects the logout handler against cross-site requests.
	LogoutCSRFToken string          `json:"lt"`
	UserInfo        json.RawMessage `json:"ui,omitempty"`
	DPoPKey         []byte          `json:"dk,omitempty"`
	Version         int             `json:"v"`
	// Expiry is the expiration time of the access token, and Lifetime its lifetime in seconds when it was issued.
	Expiry   int64 `json:"exp,omitzero"`
	Lifetime int64 `json:"ttl,omitzero"`
	Created  int64 `json:"iat"`
	LastSeen int64 `json:"seen"`
	// Generation counts the changes of the tokens, so the latest tokens of the session are found.
	Generation int64 `json:"gen,omitzero"`
}

// resourceToken is the access token of a resource (RFC 8707).
type resourceToken struct {
	AccessToken string `json:"at"`
	TokenType   string `json:"tt,omitempty"`
	Expiry      int64  `json:"exp,omitzero"`
	Lifetime    int64  `json:"ttl,omitzero"`
}

func (t resourceToken) token() *oauth2.Token {
	token := &oauth2.Token{AccessToken: t.AccessToken, TokenType: t.TokenType}
	if t.Expiry != 0 {
		token.Expiry = time.Unix(t.Expiry, 0)
	}
	return token
}

func newSession(now time.Time) *session {
	return &session{
		Version:         sessionVersion,
		LogoutCSRFToken: randomString(),
		Created:         now.Unix(),
		LastSeen:        now.Unix(),
	}
}

// expires returns the time at which the session ends, whichever of the idle and absolute timeouts comes first.
func (s *session) expires(cfg *config) time.Time {
	idle := time.Unix(s.LastSeen, 0).Add(cfg.idleTimeout)
	absolute := time.Unix(s.Created, 0).Add(cfg.absoluteTimeout)
	if idle.Before(absolute) {
		return idle
	}
	return absolute
}

// setToken sets the access token and its expiration. The refresh token is kept when the provider issues none.
func (s *session) setToken(token *oauth2.Token, now time.Time) {
	s.AccessToken = token.AccessToken
	s.TokenType = token.TokenType
	s.Expiry, s.Lifetime = expiration(token, now)
	s.setRefreshToken(token)
}

// setResourceToken sets the access token of the resource. The refresh token is kept when the provider issues none.
func (s *session) setResourceToken(resource string, token *oauth2.Token, now time.Time) {
	t := resourceToken{AccessToken: token.AccessToken, TokenType: token.TokenType}
	t.Expiry, t.Lifetime = expiration(token, now)
	if s.Resources == nil {
		s.Resources = make(map[string]resourceToken, 1)
	}
	s.Resources[resource] = t
	s.setRefreshToken(token)
}

func (s *session) setRefreshToken(token *oauth2.Token) {
	if token.RefreshToken != "" {
		s.RefreshToken = token.RefreshToken
	}
	s.Generation++
}

// expiration returns the expiration time of the token and its lifetime in seconds, or zeros when it has no expiration.
func expiration(token *oauth2.Token, now time.Time) (int64, int64) {
	if token.Expiry.IsZero() {
		return 0, 0
	}
	return token.Expiry.Unix(), int64(token.Expiry.Sub(now) / time.Second)
}

// refreshSkew returns how long before its expiration the access token is refreshed, at most half its lifetime so
// a short-lived token is not refreshed on every request.
func (s *session) refreshSkew() time.Duration {
	return skew(s.Lifetime)
}

func skew(lifetime int64) time.Duration {
	if lifetime > 0 {
		return min(refreshSkew, time.Duration(lifetime)*time.Second/2)
	}
	return refreshSkew
}

// stale reports whether the access token must be refreshed. A token without expiration is never refreshed.
func (s *session) stale(now time.Time) bool {
	return s.Expiry != 0 && !now.Add(skew(s.Lifetime)).Before(time.Unix(s.Expiry, 0))
}

func (t resourceToken) stale(now time.Time) bool {
	return t.Expiry != 0 && !now.Add(skew(t.Lifetime)).Before(time.Unix(t.Expiry, 0))
}

// adopt replaces the tokens of s with the tokens of latest.
func (s *session) adopt(latest *session) {
	s.IDToken = latest.IDToken
	s.AccessToken = latest.AccessToken
	s.TokenType = latest.TokenType
	s.RefreshToken = latest.RefreshToken
	s.Resources = maps.Clone(latest.Resources)
	s.Expiry = latest.Expiry
	s.Lifetime = latest.Lifetime
	s.Generation = latest.Generation
}

// prune removes the access tokens of the resources that expired or are no longer declared.
func (s *session) prune(resources []string, now time.Time) {
	maps.DeleteFunc(s.Resources, func(resource string, t resourceToken) bool {
		return t.Expiry != 0 && !now.Before(time.Unix(t.Expiry, 0)) || !slices.Contains(resources, resource)
	})
}

func decodeSession(data []byte) (*session, error) {
	s := new(session)
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Version != sessionVersion {
		return nil, ErrNoSession
	}
	return s, nil
}

// randomString returns 32 random bytes encoded in base64url.
func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessionState describes the session cookie of a request, with its number of chunks and, for a stateful frontend, its
// store id. An empty id means the next write creates a new session.
type sessionState struct {
	id     string
	chunks int
}

// readSession returns the session of the request. It returns ErrNoSession when the request has no valid session, with
// the state of the cookie so it can be deleted.
func (fe *Frontend) readSession(ctx context.Context, cookies []*http.Cookie) (*session, sessionState, error) {
	plaintext, chunks, err := sessionCookie.read(cookies, fe.aead)
	st := sessionState{chunks: chunks}
	if err != nil {
		return nil, st, ErrNoSession
	}
	if fe.cfg.store == nil {
		s, decodeErr := decodeSession(plaintext)
		if decodeErr != nil {
			return nil, st, ErrNoSession
		}
		return s, st, nil
	}

	id := storeID(plaintext)
	r, err := fe.cfg.store.Load(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, st, ErrNoSession
	}
	if err != nil {
		return nil, st, err
	}
	data, err := fe.aead.Decrypt(r.Data, storeAssociatedData(id))
	if err != nil {
		return nil, st, ErrNoSession
	}
	s, err := decodeSession(data)
	if err != nil {
		return nil, st, ErrNoSession
	}
	st.id = id
	return s, st, nil
}

// writeSession saves the session and adds the cookie to h when it changes. A stateful frontend creates a new session
// key when the state has no id, so a login never reuses an existing session. It returns ErrNoSession when an existing
// session no longer exists in the store.
func (fe *Frontend) writeSession(ctx context.Context, h http.Header, s *session, st sessionState) error {
	s.prune(fe.cfg.resources, fe.now())
	data, err := json.Marshal(s) //nolint:gosec // the tokens are encrypted before leaving the process
	if err != nil {
		return err
	}
	if fe.cfg.store == nil {
		return sessionCookie.write(h, fe.aead, data, 0, st.chunks)
	}

	var key []byte
	if st.id == "" {
		key = []byte(randomString())
		st.id = storeID(key)
	}
	ciphertext, err := fe.aead.Encrypt(data, storeAssociatedData(st.id))
	if err != nil {
		return err
	}
	r := store.Record{
		Expires:    s.expires(fe.cfg),
		Partition:  fe.partition,
		Subject:    s.Subject,
		SID:        s.SID,
		Data:       ciphertext,
		Generation: s.Generation,
	}
	if key == nil {
		// An existing session is never created again, since it may have been ended in the meantime.
		err = fe.cfg.store.Update(ctx, st.id, r)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return ErrNoSession
		case errors.Is(err, store.ErrConflict):
			// Another request stored newer tokens of the session.
			return nil
		}
		return err
	}
	if err := fe.cfg.store.Create(ctx, st.id, r); err != nil {
		return err
	}
	return sessionCookie.write(h, fe.aead, key, 0, st.chunks)
}

func (fe *Frontend) deleteSession(ctx context.Context, h http.Header, st sessionState) error {
	sessionCookie.clear(h, st.chunks)
	if fe.cfg.store == nil || st.id == "" {
		return nil
	}
	return fe.cfg.store.Delete(ctx, st.id)
}

// deleteSessionsBy deletes the stored sessions of the subject, restricted to the sid when it is not empty, and revokes
// their refresh tokens.
func (fe *Frontend) deleteSessionsBy(ctx context.Context, subject, sid string) error {
	records, err := fe.cfg.store.DeleteBy(ctx, fe.partition, subject, sid)
	if err != nil {
		return err
	}
	for id, r := range records {
		data, err := fe.aead.Decrypt(r.Data, storeAssociatedData(id))
		if err != nil {
			continue
		}
		if s, err := decodeSession(data); err == nil && s.RefreshToken != "" {
			_ = fe.revoke(ctx, s.RefreshToken)
		}
	}
	return nil
}

// storeID returns the store id of a session key. Only the hash is stored, so the store content cannot be used as a
// cookie.
func storeID(key []byte) string {
	sum := sha256.Sum256(key)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func storeAssociatedData(id string) []byte {
	return []byte("store\x00" + id)
}

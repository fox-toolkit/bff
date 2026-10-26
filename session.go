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
	"net/http"
	"time"

	"github.com/fox-toolkit/bff/store"
	"golang.org/x/oauth2"
)

const sessionVersion = 1

var errNoSession = errors.New("no session")

// session is the state of a logged in user. Times are unix seconds, to keep the stateless cookie small.
type session struct {
	Subject      string `json:"sub,omitempty"`
	SID          string `json:"sid,omitempty"`
	IDToken      string `json:"idt,omitempty"`
	AccessToken  string `json:"at,omitempty"`
	TokenType    string `json:"tt,omitempty"`
	RefreshToken string `json:"rt,omitempty"`
	// LogoutCSRFToken protects the logout handler against cross-site requests.
	LogoutCSRFToken string          `json:"lt"`
	UserInfo        json.RawMessage `json:"ui,omitempty"`
	Version         int             `json:"v"`
	// Expiry is the expiration time of the access token, and Lifetime its lifetime in seconds when it was issued.
	Expiry   int64 `json:"exp,omitzero"`
	Lifetime int64 `json:"ttl,omitzero"`
	Created  int64 `json:"iat"`
	LastSeen int64 `json:"seen"`
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
	if token.RefreshToken != "" {
		s.RefreshToken = token.RefreshToken
	}
	s.Expiry, s.Lifetime = 0, 0
	if !token.Expiry.IsZero() {
		s.Expiry = token.Expiry.Unix()
		s.Lifetime = int64(token.Expiry.Sub(now) / time.Second)
	}
}

// refreshSkew returns how long before its expiration the access token is refreshed, at most half its lifetime so
// a short-lived token is not refreshed on every request.
func (s *session) refreshSkew() time.Duration {
	if s.Lifetime > 0 {
		return min(refreshSkew, time.Duration(s.Lifetime)*time.Second/2)
	}
	return refreshSkew
}

func decodeSession(data []byte) (*session, error) {
	s := new(session)
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	if s.Version != sessionVersion {
		return nil, errNoSession
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

// readSession returns the session of the request. It returns errNoSession when the request has no valid session, with
// the state of the cookie so it can be deleted.
func (fe *Frontend) readSession(ctx context.Context, cookies []*http.Cookie) (*session, sessionState, error) {
	plaintext, chunks, err := sessionCookie.read(cookies, fe.aead)
	st := sessionState{chunks: chunks}
	if err != nil {
		return nil, st, errNoSession
	}
	if fe.cfg.store == nil {
		s, decodeErr := decodeSession(plaintext)
		if decodeErr != nil {
			return nil, st, errNoSession
		}
		return s, st, nil
	}

	id := storeID(plaintext)
	r, err := fe.cfg.store.Load(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, st, errNoSession
	}
	if err != nil {
		return nil, st, err
	}
	data, err := fe.aead.Decrypt(r.Data, storeAssociatedData(id))
	if err != nil {
		return nil, st, errNoSession
	}
	s, err := decodeSession(data)
	if err != nil {
		return nil, st, errNoSession
	}
	st.id = id
	return s, st, nil
}

// writeSession saves the session and adds the cookie to h when it changes. A stateful frontend creates a new session
// key when the state has no id, so a login never reuses an existing session. It returns errNoSession when an existing
// session no longer exists in the store.
func (fe *Frontend) writeSession(ctx context.Context, h http.Header, s *session, st sessionState) error {
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
		Expires:   s.expires(fe.cfg),
		Partition: fe.partition,
		Subject:   s.Subject,
		SID:       s.SID,
		Data:      ciphertext,
	}
	if key == nil {
		// An existing session is never created again, since it may have been ended in the meantime.
		err = fe.cfg.store.Update(ctx, st.id, r)
		if errors.Is(err, store.ErrNotFound) {
			return errNoSession
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

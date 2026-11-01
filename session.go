// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/rp/blob/main/LICENSE.

package rp

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
	"sync"
	"time"

	"github.com/fox-toolkit/rp/store"
	"golang.org/x/oauth2"
)

const (
	sessionVersion = 1
	// maxConcurrentRevocations bounds the revocations sent at once when several sessions end together.
	maxConcurrentRevocations = 4
)

var errNoSession = errors.New("no session")

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

// mergeTokens replaces the tokens of s with the tokens of a newer version of the session. It keeps the access tokens of
// the resources that newer does not have, since they stay valid until they expire.
func (s *session) mergeTokens(newer *session) {
	resources := make(map[string]resourceToken, len(s.Resources)+len(newer.Resources))
	maps.Copy(resources, s.Resources)
	maps.Copy(resources, newer.Resources)
	s.Resources = resources
	s.IDToken = newer.IDToken
	s.UserInfo = newer.UserInfo
	s.AccessToken = newer.AccessToken
	s.TokenType = newer.TokenType
	s.RefreshToken = newer.RefreshToken
	s.Expiry = newer.Expiry
	s.Lifetime = newer.Lifetime
	s.Generation = newer.Generation
}

// clone returns a copy of s that does not share its access tokens of the resources.
func (s *session) clone() *session {
	c := *s
	c.Resources = maps.Clone(s.Resources)
	return &c
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
func (rp *relyingParty) readSession(ctx context.Context, cookies []*http.Cookie) (*session, sessionState, error) {
	plaintext, chunks, err := rp.cookie.read(cookies, rp.aead)
	st := sessionState{chunks: chunks}
	if err != nil {
		return nil, st, errNoSession
	}
	if rp.cfg.store == nil {
		s, decodeErr := decodeSession(plaintext)
		if decodeErr != nil {
			return nil, st, errNoSession
		}
		return s, st, nil
	}

	id := storeID(plaintext)
	r, err := rp.cfg.store.Load(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, st, errNoSession
	}
	if err != nil {
		return nil, st, err
	}
	data, err := rp.aead.Decrypt(r.Data, storeAssociatedData(id))
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
func (rp *relyingParty) writeSession(ctx context.Context, h http.Header, s *session, st sessionState) error {
	s.prune(rp.cfg.resources, rp.now())
	data, err := json.Marshal(s) //nolint:gosec // the tokens are encrypted before leaving the process
	if err != nil {
		return err
	}
	if rp.cfg.store == nil {
		return rp.cookie.write(h, rp.aead, data, 0, st.chunks)
	}

	var key []byte
	if st.id == "" {
		key = []byte(randomString())
		st.id = storeID(key)
	}
	ciphertext, err := rp.aead.Encrypt(data, storeAssociatedData(st.id))
	if err != nil {
		return err
	}
	r := store.Record{
		Expires:    s.expires(rp.cfg),
		Partition:  rp.partition,
		Subject:    s.Subject,
		SID:        s.SID,
		Data:       ciphertext,
		Generation: s.Generation,
	}
	if key == nil {
		// An existing session is never created again, since it may have been ended in the meantime.
		err = rp.cfg.store.Update(ctx, st.id, r)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return errNoSession
		case errors.Is(err, store.ErrConflict):
			// Another request stored newer tokens of the session.
			return nil
		}
		return err
	}
	if err := rp.cfg.store.Create(ctx, st.id, r); err != nil {
		return err
	}
	return rp.cookie.write(h, rp.aead, key, 0, st.chunks)
}

func (rp *relyingParty) deleteSession(ctx context.Context, h http.Header, st sessionState) error {
	rp.cookie.clear(h, st.chunks)
	if rp.cfg.store == nil || st.id == "" {
		return nil
	}
	return rp.cfg.store.Delete(ctx, st.id)
}

// endSession deletes the session and revokes its refresh token. It holds the lock of the session, so it waits for a
// token request in flight and revokes the latest refresh token, even when s comes from an older cookie. The request
// that started it does not cancel it.
func (rp *relyingParty) endSession(ctx context.Context, h http.Header, s *session, st sessionState) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endSessionTimeout)
	defer cancel()
	return rp.tokens.Do(ctx, s.LogoutCSRFToken, func(latest *session) (*session, error) {
		if st.id != "" {
			// Other replicas may have stored newer tokens.
			stored, err := rp.loadSession(ctx, st.id)
			switch {
			case err == nil:
				if latest == nil || stored.Generation > latest.Generation {
					latest = stored
				}
			case !errors.Is(err, errSessionEnded):
				return nil, err
			}
		}
		if latest != nil && latest.Generation > s.Generation {
			s.mergeTokens(latest)
		}
		if err := rp.deleteSession(ctx, h, st); err != nil {
			return nil, err
		}
		rp.tokens.Forget(s.LogoutCSRFToken)
		if s.RefreshToken != "" {
			// The session is already deleted, so a failed revocation only leaves the refresh token valid until it expires.
			_ = rp.revoke(ctx, s.RefreshToken)
		}
		return nil, nil
	})
}

// deleteSessionsBy deletes the stored sessions of the subject, restricted to the sid when it is not empty, and revokes
// their refresh tokens.
func (rp *relyingParty) deleteSessionsBy(ctx context.Context, subject, sid string) error {
	// The request cancels neither the deletion nor the revocations, which share one budget. The sessions deleted
	// before an error are revoked too.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endSessionTimeout)
	defer cancel()
	records, deleteErr := rp.cfg.store.DeleteBy(ctx, rp.partition, subject, sid)

	sem := make(chan struct{}, maxConcurrentRevocations)
	var (
		wg        sync.WaitGroup
		panicOnce sync.Once
		panicked  any
	)
	skipped := 0
	for id, r := range records {
		data, err := rp.aead.Decrypt(r.Data, storeAssociatedData(id))
		if err != nil {
			continue
		}
		// Back-Channel Logout 2.7 keeps the refresh tokens issued with offline_access, but here a refresh token only
		// lives in the session, so nothing can use it once the session is deleted.
		s, err := decodeSession(data)
		if err != nil || s.RefreshToken == "" {
			continue
		}
		// select picks at random when both cases are ready.
		if ctx.Err() != nil {
			skipped++
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			skipped++
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			defer func() {
				if p := recover(); p != nil {
					panicOnce.Do(func() { panicked = p })
				}
			}()
			tctx, cancel := context.WithTimeout(ctx, revocationTimeout)
			defer cancel()
			_ = rp.revokeWithin(tctx, s.RefreshToken)
		})
	}
	wg.Wait()
	if skipped > 0 {
		rp.logger.WarnContext(ctx, "refresh tokens not revoked", "count", skipped)
	}
	// The panic of a revocation is raised on the goroutine of the caller, where the server recovers it.
	if panicked != nil {
		panic(panicked)
	}
	return deleteErr
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

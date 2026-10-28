// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.

// Package redis provides a implementation of [store.Store] for Redis 6.2 or later.
package redis

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/fox-toolkit/bff/store"
	goredis "github.com/redis/go-redis/v9"
)

var ErrInvalidConfig = errors.New("invalid config")

// DefaultKeyPrefix is the default prefix of the keys written by a [Store].
const DefaultKeyPrefix = "bff:"

// Option configures a [Store].
type Option interface {
	apply(*config) error
}

type optionFunc func(*config) error

func (f optionFunc) apply(c *config) error {
	return f(c)
}

type config struct {
	prefix string
}

// WithKeyPrefix sets the prefix of the keys written by the store. The default is [DefaultKeyPrefix].
func WithKeyPrefix(prefix string) Option {
	return optionFunc(func(c *config) error {
		if prefix == "" {
			return fmt.Errorf("%w: empty key prefix", ErrInvalidConfig)
		}
		c.prefix = prefix
		return nil
	})
}

// createScript starts with HSET, which Redis refuses at maxmemory. Redis checks maxmemory only until the first write
// of a script.
var createScript = goredis.NewScript(`
redis.call('HSET', KEYS[1], 'd', ARGV[1], 'g', ARGV[2], 'p', ARGV[3], 'u', ARGV[4], 'i', ARGV[5], 'e', ARGV[6])
redis.call('PEXPIREAT', KEYS[1], ARGV[6])
return 1
`)

var updateScript = goredis.NewScript(`
local cur = redis.call('HMGET', KEYS[1], 'g', 'e')
if not cur[1] or tonumber(cur[2]) <= tonumber(ARGV[7]) then
	return 0
end
if tonumber(cur[1]) > tonumber(ARGV[2]) then
	return 1
end
redis.call('HSET', KEYS[1], 'd', ARGV[1], 'g', ARGV[2], 'p', ARGV[3], 'u', ARGV[4], 'i', ARGV[5], 'e', ARGV[6])
redis.call('PEXPIREAT', KEYS[1], ARGV[6])
return 2
`)

// takeScript deletes the session and returns its fields when its subject and sid match the non-empty arguments, and its
// partition the third argument when there is one. It returns 0 when the session does not exist and 1 when it does
// not match.
var takeScript = goredis.NewScript(`
local r = redis.call('HMGET', KEYS[1], 'd', 'g', 'p', 'u', 'i', 'e')
if not r[6] then
	return 0
end
if (ARGV[1] ~= '' and r[4] ~= ARGV[1]) or (ARGV[2] ~= '' and r[5] ~= ARGV[2]) or (ARGV[3] and r[3] ~= ARGV[3]) then
	return 1
end
redis.call('DEL', KEYS[1])
return r
`)

// indexScript adds the session before pruning, for maxmemory as in createScript. It prunes with the server time, the
// clock that expires the sessions.
var indexScript = goredis.NewScript(`
redis.call('ZADD', KEYS[1], 'GT', ARGV[1], ARGV[2])
local t = redis.call('TIME')
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', string.format('%.0f', t[1] * 1000 + math.floor(t[2] / 1000)))
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if last[2] then
	redis.call('PEXPIREAT', KEYS[1], string.format('%.0f', tonumber(last[2])))
end
return 1
`)

const (
	conflict = 1
	missing  = 0
)

// Store implements [store.Store] for Redis.
type Store struct {
	client goredis.UniversalClient
	now    func() time.Time
	prefix string
}

// NewStore returns a [Store] that uses the given client. The client must read from the master: replicas lag behind
// it, so do not enable ReadOnly, RouteByLatency or RouteRandomly. The server must use the noeviction policy: an
// evicted index hides its sessions from DeleteBy.
func NewStore(client goredis.UniversalClient, opts ...Option) (*Store, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidConfig)
	}
	cfg := &config{prefix: DefaultKeyPrefix}
	for _, opt := range opts {
		if err := opt.apply(cfg); err != nil {
			return nil, err
		}
	}
	return &Store{client: client, now: time.Now, prefix: cfg.prefix}, nil
}

func (s *Store) Load(ctx context.Context, id string) (store.Record, error) {
	fields, err := s.client.HMGet(ctx, s.sessionKey(id), "d", "g", "p", "u", "i", "e").Result()
	if err != nil {
		return store.Record{}, err
	}
	if fields[5] == nil {
		return store.Record{}, store.ErrNotFound
	}
	r, err := decodeRecord(fields)
	if err != nil {
		return store.Record{}, err
	}
	if !s.now().Before(r.Expires) {
		return store.Record{}, store.ErrNotFound
	}
	return r, nil
}

// Create implements [store.Store]. It indexes the session by subject and sid before writing it, so DeleteBy finds every
// live session. An index may keep the ids of deleted sessions.
func (s *Store) Create(ctx context.Context, id string, r store.Record) error {
	if err := s.index(ctx, id, r); err != nil {
		return err
	}
	return createScript.Run(ctx, s.client, []string{s.sessionKey(id)}, recordArgs(r)...).Err()
}

// Update implements [store.Store]. Like Create, it indexes the session first, and an index never lowers the expiry of
// a session (ZADD GT).
func (s *Store) Update(ctx context.Context, id string, r store.Record) error {
	if err := s.index(ctx, id, r); err != nil {
		return err
	}
	args := append(recordArgs(r), s.now().UnixMilli())
	res, err := updateScript.Run(ctx, s.client, []string{s.sessionKey(id)}, args...).Int()
	if err != nil {
		return err
	}
	switch res {
	case missing:
		return store.ErrNotFound
	case conflict:
		return store.ErrConflict
	}
	return nil
}

// Delete implements [store.Store].
func (s *Store) Delete(ctx context.Context, id string) error {
	r, ok, err := s.take(ctx, id, "", "")
	if err != nil || !ok {
		return err
	}
	s.unindex(ctx, id, r)
	return nil
}

// DeleteBy implements [store.Store].
func (s *Store) DeleteBy(ctx context.Context, partition, subject, sid string) (map[string]store.Record, error) {
	var key string
	switch {
	case sid != "":
		key = s.indexKey("i:", partition, sid)
	case subject != "":
		key = s.indexKey("u:", partition, subject)
	default:
		return nil, nil
	}
	ids, err := s.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	deleted := make(map[string]store.Record)
	var errs []error
	for _, id := range ids {
		r, ok, err := s.take(ctx, id, subject, sid, partition)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ok {
			deleted[id] = r
			s.unindex(ctx, id, r)
		}
	}
	return deleted, errors.Join(errs...)
}

// take runs takeScript with the subject, the sid and an optional partition, and returns the deleted session.
func (s *Store) take(ctx context.Context, id string, args ...any) (store.Record, bool, error) {
	res, err := takeScript.Run(ctx, s.client, []string{s.sessionKey(id)}, args...).Result()
	if err != nil {
		return store.Record{}, false, err
	}
	fields, ok := res.([]any)
	if !ok {
		return store.Record{}, false, nil
	}
	r, err := decodeRecord(fields)
	if err != nil {
		return store.Record{}, false, err
	}
	return r, true, nil
}

func (s *Store) index(ctx context.Context, id string, r store.Record) error {
	exp := r.Expires.UnixMilli()
	if r.Subject != "" {
		key := s.indexKey("u:", r.Partition, r.Subject)
		if err := indexScript.Run(ctx, s.client, []string{key}, exp, id).Err(); err != nil {
			return err
		}
	}
	if r.SID != "" {
		key := s.indexKey("i:", r.Partition, r.SID)
		if err := indexScript.Run(ctx, s.client, []string{key}, exp, id).Err(); err != nil {
			return err
		}
	}
	return nil
}

// unindex removes a deleted session from its indexes. An entry left on error only points to a missing session.
func (s *Store) unindex(ctx context.Context, id string, r store.Record) {
	pipe := s.client.Pipeline()
	if r.Subject != "" {
		pipe.ZRem(ctx, s.indexKey("u:", r.Partition, r.Subject), id)
	}
	if r.SID != "" {
		pipe.ZRem(ctx, s.indexKey("i:", r.Partition, r.SID), id)
	}
	_, _ = pipe.Exec(ctx)
}

func (s *Store) sessionKey(id string) string {
	return s.prefix + "s:" + id
}

func (s *Store) indexKey(kind, partition, value string) string {
	return s.prefix + kind + base64.RawURLEncoding.EncodeToString([]byte(partition)) + ":" +
		base64.RawURLEncoding.EncodeToString([]byte(value))
}

func recordArgs(r store.Record) []any {
	return []any{r.Data, r.Generation, r.Partition, r.Subject, r.SID, r.Expires.UnixMilli()}
}

var errInvalidRecord = errors.New("invalid session record")

// decodeRecord decodes the fields d, g, p, u, i and e of a session.
func decodeRecord(fields []any) (store.Record, error) {
	var str [6]string
	if len(fields) != len(str) {
		return store.Record{}, errInvalidRecord
	}
	for i, f := range fields {
		v, ok := f.(string)
		if !ok {
			return store.Record{}, errInvalidRecord
		}
		str[i] = v
	}
	gen, err := strconv.ParseInt(str[1], 10, 64)
	if err != nil {
		return store.Record{}, errInvalidRecord
	}
	exp, err := strconv.ParseInt(str[5], 10, 64)
	if err != nil {
		return store.Record{}, errInvalidRecord
	}
	r := store.Record{
		Expires:    time.UnixMilli(exp),
		Partition:  str[2],
		Subject:    str[3],
		SID:        str[4],
		Generation: gen,
	}
	if str[0] != "" {
		r.Data = []byte(str[0])
	}
	return r, nil
}

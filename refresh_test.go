// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRefreshGroupConcurrent(t *testing.T) {
	g := newRefreshGroup(time.Now)
	var calls atomic.Int32
	release := make(chan struct{})
	fn := func() (refreshResult, error) {
		calls.Add(1)
		<-release
		return refreshResult{token: &oauth2.Token{AccessToken: "new"}}, nil
	}

	var wg sync.WaitGroup
	results := make([]refreshResult, 10)
	for i := range results {
		wg.Go(func() {
			res, err := g.Do("rt", fn)
			assert.NoError(t, err)
			results[i] = res
		})
	}
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load())
	for _, res := range results {
		assert.Equal(t, "new", res.token.AccessToken)
	}
}

func TestRefreshGroupReuse(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := newRefreshGroup(func() time.Time { return now })
	calls := 0
	fn := func() (refreshResult, error) {
		calls++
		return refreshResult{token: &oauth2.Token{AccessToken: "new"}}, nil
	}

	_, err := g.Do("rt", fn)
	require.NoError(t, err)
	now = now.Add(refreshReuse - time.Second)
	_, err = g.Do("rt", fn)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)

	now = now.Add(time.Second)
	_, err = g.Do("rt", fn)
	require.NoError(t, err)
	assert.Equal(t, 2, calls)

	now = now.Add(refreshReuse)
	_, err = g.Do("other", fn)
	require.NoError(t, err)
	assert.Len(t, g.recent, 1)
}

func TestRefreshGroupError(t *testing.T) {
	g := newRefreshGroup(time.Now)
	calls := 0
	fn := func() (refreshResult, error) {
		calls++
		return refreshResult{}, errors.New("unavailable")
	}
	for range 2 {
		_, err := g.Do("rt", fn)
		assert.Error(t, err)
	}
	assert.Equal(t, 2, calls)
}

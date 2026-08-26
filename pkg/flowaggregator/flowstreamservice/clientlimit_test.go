// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowstreamservice

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	authenticationv1 "k8s.io/api/authentication/v1"
)

// fakeAddr is a net.Addr returning a fixed string, so tests can present any peer address shape.
type fakeAddr string

func (fakeAddr) Network() string  { return "tcp" }
func (a fakeAddr) String() string { return string(a) }
func contextWithPeer(s string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: fakeAddr(s)})
}

// TestClientKey pins down that the key is the host alone. The port differs on every connection, so
// including it would turn the per-client cap into a per-connection one and make it a no-op on
// reconnect.
func TestClientKey(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"pod IP", contextWithPeer("10.244.1.7:53616"), "10.244.1.7"},
		{"same client, different ephemeral port", contextWithPeer("10.244.1.7:39252"), "10.244.1.7"},
		{"node gateway, the collapsed key", contextWithPeer("10.244.1.1:48679"), "10.244.1.1"},
		{"IPv6 is unbracketed by SplitHostPort", contextWithPeer("[fd00:10:244::5]:14740"), "fd00:10:244::5"},
		{"no peer in context", context.Background(), ""},
		{"address without a port is used whole", contextWithPeer("10.244.1.7"), "10.244.1.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, clientKey(tc.ctx))
		})
	}
	// The two Pod-IP cases above must agree, or reconnecting would earn a fresh budget.
	assert.Equal(t, clientKey(contextWithPeer("10.244.1.7:53616")), clientKey(contextWithPeer("10.244.1.7:39252")))
}

func TestClientStreamLimiter_PerClientCap(t *testing.T) {
	l := newClientStreamLimiter()
	releases := make([]func(), 0, maxStreamsPerClient)
	for i := range maxStreamsPerClient {
		release, err := l.acquire("10.244.1.7")
		require.NoError(t, err, "acquire %d should have succeeded", i)
		releases = append(releases, release)
	}

	_, err := l.acquire("10.244.1.7")
	assert.ErrorIs(t, err, errTooManyStreamsForClient, "the cap should refuse one past maxStreamsPerClient")

	// A different client is unaffected: the cap is per key, not global-with-extra-steps.
	release, err := l.acquire("10.244.1.8")
	require.NoError(t, err)
	release()

	// Releasing frees the slot for the same client again.
	releases[0]()
	release, err = l.acquire("10.244.1.7")
	require.NoError(t, err)
	release()
	for _, r := range releases[1:] {
		r()
	}
}

func TestClientStreamLimiter_TotalCap(t *testing.T) {
	l := newClientStreamLimiter()
	// One key per stream, so the per-client cap never binds and only the total can. Keys are opaque to
	// the limiter, so a counter stands in for a client address.
	var releases []func()
	for i := range maxTotalStreams {
		release, err := l.acquire(strconv.Itoa(i))
		require.NoError(t, err, "acquire %d should have succeeded", i)
		releases = append(releases, release)
	}
	_, err := l.acquire("10.244.9.9")
	assert.ErrorIs(t, err, errTooManyStreamsTotal, "the total cap should refuse a client that is itself well under its own cap")

	releases[0]()
	release, err := l.acquire("10.244.9.9")
	require.NoError(t, err, "a freed slot should be reusable by any client")
	release()
}

// TestClientStreamLimiter_ReleaseDropsEntry covers that the map does not grow with client churn: a
// long-running Flow Aggregator sees an unbounded number of distinct short-lived client IPs.
func TestClientStreamLimiter_ReleaseDropsEntry(t *testing.T) {
	l := newClientStreamLimiter()
	for i := range 100 {
		release, err := l.acquire(strconv.Itoa(i))
		require.NoError(t, err)
		release()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	assert.Empty(t, l.perClient, "released keys should not be retained")
	assert.Zero(t, l.total)
}

// TestStreamInterceptor_StreamCapIsPerClientAndPreAuthentication covers the two properties that make
// the cap worth having: it is charged before the credential is checked, so a saturated client cannot
// make the Flow Aggregator do authentication work, and it is keyed per client, so one client cannot
// lock out another.
func TestStreamInterceptor_StreamCapIsPerClientAndPreAuthentication(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	noisy, quiet := "10.244.1.7", "10.244.1.8"
	for range maxStreamsPerClient {
		_, err := a.streamLimiter.acquire(noisy)
		require.NoError(t, err)
	}

	// A valid credential is refused, and refused as ResourceExhausted rather than Unauthenticated,
	// since nothing is wrong with the credential.
	handlerCalled := false
	ctx := peer.NewContext(contextWithAuthHeader("Bearer good-token"), &peer.Peer{Addr: fakeAddr(noisy + ":40001")})
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.ResourceExhausted)
	assert.False(t, handlerCalled)
	// The token was never reviewed, so no authentication slot was consumed either.
	assert.Empty(t, a.tokenAuthSlots)

	// A different client is unaffected.
	ctx = peer.NewContext(contextWithAuthHeader("Bearer good-token"), &peer.Peer{Addr: fakeAddr(quiet + ":40002")})
	require.NoError(t, a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil)))
	assert.True(t, handlerCalled)
}

// TestStreamInterceptor_StreamSlotHeldForStreamLifetime covers what distinguishes this from a rate
// limiter: the slot is held until the handler returns, so long-lived streams accumulate against the
// cap rather than only their rate of opening being limited.
func TestStreamInterceptor_StreamSlotHeldForStreamLifetime(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	ctx := peer.NewContext(contextWithAuthHeader("Bearer good-token"), &peer.Peer{Addr: fakeAddr("10.244.1.7:40003")})

	inHandler := make(chan struct{})
	finish := make(chan struct{})
	go func() {
		_ = a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{},
			func(any, grpc.ServerStream) error {
				close(inHandler)
				<-finish
				return nil
			})
	}()

	<-inHandler
	a.streamLimiter.mu.Lock()
	held := a.streamLimiter.total
	a.streamLimiter.mu.Unlock()
	assert.Equal(t, 1, held, "the slot should still be held while the handler runs")

	close(finish)
	assert.Eventually(t, func() bool {
		a.streamLimiter.mu.Lock()
		defer a.streamLimiter.mu.Unlock()
		return a.streamLimiter.total == 0
	}, time.Second, 10*time.Millisecond, "the slot should be released when the handler returns")
}

// TestStreamCapsAreOrdered pins the relationship the caps rely on: the connection limit the server
// advertises must stay above the per-client cap, or a client reaching it first would have its RPC
// parked by its own gRPC transport instead of being answered with ResourceExhausted.
func TestStreamCapsAreOrdered(t *testing.T) {
	assert.Greater(t, maxStreamsPerConn, maxStreamsPerClient,
		"maxStreamsPerConn must not preempt the per-client cap")
	assert.LessOrEqual(t, maxStreamsPerClient, maxTotalStreams,
		"a single client must be able to reach its own cap")
}

func TestClientStreamLimiter_ConcurrentAcquireRelease(t *testing.T) {
	l := newClientStreamLimiter()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if release, err := l.acquire("10.244.1.7"); err == nil {
					release()
				}
			}
		}()
	}
	wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	assert.Zero(t, l.total, "every acquire should have been released")
	assert.Empty(t, l.perClient)
}

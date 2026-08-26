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
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/peer"
)

const (
	// maxStreamsPerClient caps concurrent GetFlows streams per client IP, maxTotalStreams caps them
	// across all clients. Both are deliberately loose, because a key is a source IP and several paths
	// put unrelated identities behind one:
	//   - a client that holds its users' credentials and opens one stream per user is a single Pod, so
	//     for it maxStreamsPerClient is a ceiling on how many of its users can watch flows at once
	//     rather than a bound on misbehaviour. This is the shipped path: antrea-ui authenticates each
	//     browser user and streams on their behalf, so 64 is the number of concurrent viewers it can
	//     serve, and raising that number means raising this one.
	//   - a hostNetwork client, and an external client arriving through a NodePort Service with
	//     externalTrafficPolicy=Cluster, are both seen as the ingress node's antrea-gw0 address and so
	//     share one key with each other. Antrea exposes 14740 only on a ClusterIP Service, which
	//     preserves the client Pod IP, so neither applies unless an operator adds such a path.
	// A client refused by either cap is told ResourceExhausted, which is retryable.
	maxStreamsPerClient = 64
	maxTotalStreams     = 256
)

// errTooManyStreamsForClient and errTooManyStreamsTotal name which cap refused a stream, so that the
// log distinguishes one client holding its whole allowance from the service being saturated across
// all of them. They are values rather than formatted per refusal, since refusals are the path an
// abusive client drives.
var (
	errTooManyStreamsForClient = fmt.Errorf("client already holds its %d concurrent streams", maxStreamsPerClient)
	errTooManyStreamsTotal     = fmt.Errorf("all %d concurrent stream slots are in use across clients", maxTotalStreams)
)

// clientStreamLimiter caps concurrent streams per client key and in total. A stream holds its slot for
// its whole lifetime, which is what a rate limiter cannot do: GetFlows streams are long-lived by
// design, so limiting how fast they are opened does not bound how many accumulate.
type clientStreamLimiter struct {
	mu        sync.Mutex
	perClient map[string]int
	total     int
}

func newClientStreamLimiter() *clientStreamLimiter {
	return &clientStreamLimiter{perClient: make(map[string]int)}
}

// acquire reserves a slot for key and returns the func releasing it. The error names the cap that
// refused the stream; no slot is taken and release is nil in that case.
func (l *clientStreamLimiter) acquire(key string) (release func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.total >= maxTotalStreams {
		return nil, errTooManyStreamsTotal
	}
	if l.perClient[key] >= maxStreamsPerClient {
		return nil, errTooManyStreamsForClient
	}
	l.perClient[key]++
	l.total++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		l.total--
		l.perClient[key]--
		// Drop the entry at zero, so churn of short-lived client IPs cannot grow the map without bound.
		if l.perClient[key] <= 0 {
			delete(l.perClient, key)
		}
	}, nil
}

// clientKey identifies the peer for per-client limits. Only the host half of the address is used: the
// port differs per connection, so keying on the whole address would make the cap per-connection. An
// unidentifiable peer yields "", so those calls share one bucket rather than escaping the cap.
func clientKey(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

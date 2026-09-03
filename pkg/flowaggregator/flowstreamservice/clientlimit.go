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
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/peer"
)

// StreamLimits are the caps on concurrent GetFlows streams. Both defaults are deliberately loose,
// because a key is a source IP and several paths put unrelated identities behind one:
//   - a client that holds its users' credentials and opens one stream per user is a single Pod, so for
//     it MaxStreamsPerClientIP is a ceiling on how many of its users can watch flows at once rather
//     than a bound on misbehavior. As the primary consumer, antrea-ui authenticates each browser user
//     and streams on their behalf, so the cap is the number of concurrent viewers it can serve.
//   - a hostNetwork client, and an external client arriving through a NodePort Service with
//     externalTrafficPolicy=Cluster, are both seen as the ingress node's antrea-gw0 address and so
//     share one key with each other. The Flow Aggregator chart exposes 14740 only on the
//     flow-aggregator Service, which is a ClusterIP Service that preserves the client Pod IP.
//
// A client refused by either cap is told ResourceExhausted, which is retryable. Both come from the
// Flow Aggregator's flowStreamService configuration and are read once at startup: the limiter is built
// with them and never rebuilt, so changing either needs a restart.
type StreamLimits struct {
	// MaxStreamsPerClientIP caps concurrent streams sharing one client IP. It must be greater than 0.
	MaxStreamsPerClientIP int
	// MaxTotalStreams caps concurrent streams across all clients. It must be strictly greater than
	// MaxStreamsPerClientIP, so that a client on a single connection is answered by the per-client-IP
	// cap rather than having its call parked by its own gRPC transport; see maxStreamsPerConn.
	MaxTotalStreams int
}

func (l StreamLimits) validate() error {
	if l.MaxStreamsPerClientIP < 1 {
		return fmt.Errorf("MaxStreamsPerClientIP must be greater than 0, got %d", l.MaxStreamsPerClientIP)
	}
	if l.MaxTotalStreams <= l.MaxStreamsPerClientIP {
		return fmt.Errorf("MaxTotalStreams (%d) must be greater than MaxStreamsPerClientIP (%d)",
			l.MaxTotalStreams, l.MaxStreamsPerClientIP)
	}
	return nil
}

// errTooManyStreamsForClientIP and errTooManyStreamsTotal name which cap refused a stream, so that the
// log distinguishes one client IP holding its whole allowance from the service being saturated across
// all of them. clientStreamLimiter wraps each with the cap that was reached once at construction,
// rather than formatting per refusal, since refusals are the path an abusive client drives.
var (
	errTooManyStreamsForClientIP = errors.New("client IP already holds all of its concurrent streams")
	errTooManyStreamsTotal       = errors.New("all concurrent stream slots are in use across clients")
)

// clientStreamLimiter caps concurrent streams per client key and in total. A stream holds its slot for
// its whole lifetime, which is what a rate limiter cannot do: GetFlows streams are long-lived by
// design, so limiting how fast they are opened does not bound how many accumulate.
type clientStreamLimiter struct {
	mu                 sync.Mutex
	limits             StreamLimits
	refusedPerClientIP error
	refusedTotal       error
	perClientIPCounter map[string]int
	total              int
}

func newClientStreamLimiter(limits StreamLimits) *clientStreamLimiter {
	return &clientStreamLimiter{
		limits:             limits,
		refusedPerClientIP: fmt.Errorf("%w (%d)", errTooManyStreamsForClientIP, limits.MaxStreamsPerClientIP),
		refusedTotal:       fmt.Errorf("%w (%d)", errTooManyStreamsTotal, limits.MaxTotalStreams),
		perClientIPCounter: make(map[string]int),
	}
}

// acquire reserves a slot for key and returns the func releasing it. The error names the cap that
// refused the stream; no slot is taken and release is nil in that case.
func (l *clientStreamLimiter) acquire(key string) (release func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.total >= l.limits.MaxTotalStreams {
		return nil, l.refusedTotal
	}
	if l.perClientIPCounter[key] >= l.limits.MaxStreamsPerClientIP {
		return nil, l.refusedPerClientIP
	}
	l.perClientIPCounter[key]++
	l.total++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		l.total--
		l.perClientIPCounter[key]--
		// Drop the entry at zero, so churn of short-lived client IPs cannot grow the map without bound.
		if l.perClientIPCounter[key] <= 0 {
			delete(l.perClientIPCounter, key)
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

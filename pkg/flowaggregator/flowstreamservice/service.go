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

// Package flowstreamservice implements the FlowStreamService gRPC server-streaming
// RPC. It reads flow records from the Flow Aggregator's ring buffer and streams
// them to connected clients with server-side filtering.
package flowstreamservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/exporter"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

const (
	internalBatchSize = exporter.ConsumeMultipleBatchSize
	// flowStreamPort is the port on which the FlowStreamService gRPC server listens.
	flowStreamPort = 14740
)

// State is where a FlowStreamService server is in its serving lifecycle. The Flow Aggregator maps
// it onto its readiness and liveness probes: only StateServing is ready, and only StateFailed is
// not live.
type State int32

const (
	// StateStarting is the zero value: the server has not started serving yet. This is also where
	// it stays if Run is never called, e.g. while the server certificate is not available yet,
	// which is a wait, not a failure, so it is neither ready nor restart-worthy.
	StateStarting State = iota
	// StateServing means the listener is bound and the gRPC server is serving on it.
	StateServing
	// StateStopping means the server was asked to stop, which only happens when the Flow Aggregator
	// stops, and is draining its connections. The listener is already closed or about to be, so the
	// server is not ready, but this is a deliberate stop and not a failure.
	StateStopping
	// StateFailed means the server could not start, stopped serving on its own, or its certificate
	// could not be updated. Only a restart of the process is sure to recover from it.
	StateFailed
)

// FlowStreamService implements flowpb.FlowStreamServiceServer. Each client
// connection gets its own independent ring-buffer Consumer, so clients are
// fully decoupled and a slow client never stalls faster ones.
//
// Connecting clients must present valid Kubernetes credentials. Supported credentials are either:
//   - a bearer token in the "authorization" gRPC metadata header formatted as "Bearer <token>"
//     (validated via TokenReview), or
//   - an X.509 client certificate presented as the TLS client credential of the gRPC connection
//     (validated against the cluster's client CA bundle).
//
// The call is rejected with codes.Unauthenticated if credentials are missing, malformed, or do not
// authenticate, or with codes.Unavailable if its only credential is a client certificate and the
// client CA bundle has not loaded yet. Only this package's own tests can build a service that skips authentication.
//
// The identity authenticated then decides what the client receives: every stream is authorized
// with Kubernetes RBAC against the virtual "flows.observability.antrea.io" resource, in
// each Namespace the request names, and each endpoint of each record is disclosed only as far as
// the client's permissions in that endpoint's Namespace reach (see authorization.go and
// redaction.go). As with authentication, only this package's own tests can build a service that
// skips it.
type FlowStreamService struct {
	flowpb.UnimplementedFlowStreamServiceServer
	buffer ringbuffer.BroadcastBuffer[*flowpb.Flow]
	// authenticator authenticates every client before its RPC runs. It is nil only for a service
	// built by newFlowStreamServiceWithoutAuthentication, which serves every client unauthenticated.
	authenticator *StreamServerAuthenticator
	// authorizer decides which records each authenticated client receives, and how much of each
	// record. It is nil only for a service built by newFlowStreamServiceWithoutAuthentication with
	// no authorizer, which streams every record to every client.
	authorizer *Authorizer
	// maxStreamsPerConn bounds concurrent streams on one connection. It is deliberately set to the
	// service-wide cap rather than the per-client-IP one, so that the per-client-IP cap is what a
	// client runs into first: a gRPC client parks an RPC that would exceed the stream limit the server
	// advertises until that RPC's context is done, so a connection limit reached first would hang the
	// call instead of answering it with the retryable ResourceExhausted the per-client-IP cap returns.
	// The service-wide cap is the natural value, since no stream past it can be admitted anyway.
	maxStreamsPerConn uint32
	// streamEpoch identifies this Flow Aggregator process. Generated once at construction, it is what
	// lets a client's ResumeToken be recognized as stale after a FA restart: the ring buffer, and the
	// sequence numbers naming positions in it, both start over from zero then, so a sequence_number
	// from a previous epoch could otherwise silently name a different flow than the one it was issued for.
	streamEpoch string
	// serverCert is the certificate the server presents in TLS handshakes. UpdateCertificate swaps it
	// in place when the Flow Aggregator's certificate is rotated, so that a rotation only affects new
	// handshakes. Restarting the server instead would have to wait for every open follow stream to
	// end, and refuse every new connection in the meantime.
	serverCert atomic.Pointer[tls.Certificate]
}

// NewFlowStreamService creates a FlowStreamService backed by the given buffer. authenticator
// authenticates clients (bearer token metadata or a TLS client certificate) before their RPC runs,
// and authorizer decides which records each authenticated client receives, and how much of each
// record. Both are required: a nil one is rejected rather than quietly serving every client, or
// streaming every record to every authenticated client unredacted. The stream limits the
// authenticator was built with also fix the number of concurrent streams the server advertises per
// connection.
func NewFlowStreamService(buffer ringbuffer.BroadcastBuffer[*flowpb.Flow], authenticator *StreamServerAuthenticator, authorizer *Authorizer) (*FlowStreamService, error) {
	if authenticator == nil {
		return nil, fmt.Errorf("authenticator is required; only this package's tests may serve clients without authentication, via newFlowStreamServiceWithoutAuthentication")
	}
	if authorizer == nil {
		return nil, fmt.Errorf("authorizer is required; without one every authenticated client would receive every record unredacted")
	}
	return &FlowStreamService{
		buffer:            buffer,
		authenticator:     authenticator,
		authorizer:        authorizer,
		maxStreamsPerConn: uint32(authenticator.streamLimiter.limits.MaxTotalStreams),
		streamEpoch:       uuid.NewV4().String(),
	}, nil
}

// newFlowStreamServiceWithoutAuthentication creates a FlowStreamService that accepts every client
// without authenticating it, and authorizes the streams it serves with authorizer, or does not
// authorize them at all when that is nil. It exists for this package's tests, which have no API
// server to validate credentials against. It is deliberately unexported.
func newFlowStreamServiceWithoutAuthentication(buffer ringbuffer.BroadcastBuffer[*flowpb.Flow], authorizer *Authorizer) *FlowStreamService {
	return &FlowStreamService{
		buffer:            buffer,
		authorizer:        authorizer,
		maxStreamsPerConn: flowaggregatorconfig.DefaultFlowStreamMaxTotalStreams,
		streamEpoch:       uuid.NewV4().String(),
	}
}

// Listen binds the TCP listener on FlowStreamPort for Run. It is separate from Run so that the
// caller can tell a failure to bind, which is permanent, from the server's own lifecycle, and so
// that Run can be exercised without a real socket.
func (s *FlowStreamService) Listen() (net.Listener, error) {
	addr := fmt.Sprintf("0.0.0.0:%d", flowStreamPort)
	// #nosec G102: binding to all network interfaces is intentional
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return lis, nil
}

// UpdateCertificate sets the server certificate and private key, PEM-encoded, that the server
// presents from the next TLS handshake on. Connections already established, and the streams they
// carry, are left alone. On error, the certificate in use is left unchanged.
func (s *FlowStreamService) UpdateCertificate(serverCertPEM, serverKeyPEM []byte) error {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse server TLS key pair: %w", err)
	}
	s.serverCert.Store(&cert)
	return nil
}

func (s *FlowStreamService) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := s.serverCert.Load()
	if cert == nil {
		return nil, fmt.Errorf("no server certificate available")
	}
	return cert, nil
}

// Run starts a dedicated TLS gRPC server for the FlowStreamService on lis, which it takes
// ownership of (it is closed when Run returns). The server presents the certificate set by
// UpdateCertificate, which must have been called first.
// When the service was constructed with a non-nil authenticator, clients must present a valid
// Kubernetes bearer token or client certificate, or the call is rejected before GetFlows runs.
// Run blocks until stopCh is closed.
//
// setState is called as the server moves through its lifecycle, so that the caller can back it
// with something a readiness/liveness check can read live (e.g. an atomic's Store method); Run
// itself has no probe-serving responsibility, see pkg/flowaggregator/apiserver, which is what
// actually exposes this over HTTP:
//   - StateServing once the server is about to serve on the already-bound listener.
//   - StateStopping as soon as stopCh is closed, before the graceful stop starts. The graceful
//     stop closes the listener at its start but only returns once every connection has drained,
//     so waiting for it would leave the server reported as serving after it refuses new
//     connections.
//   - StateFailed if no certificate was set, or if Serve returns an error. Once reported,
//     StateFailed is final for this call: a later stop does not overwrite it.
func (s *FlowStreamService) Run(lis net.Listener, stopCh <-chan struct{}, setState func(State)) error {
	var mu sync.Mutex
	failed := false
	transition := func(state State) {
		mu.Lock()
		defer mu.Unlock()
		if failed {
			return
		}
		failed = state == StateFailed
		setState(state)
	}

	if s.serverCert.Load() == nil {
		lis.Close()
		transition(StateFailed)
		return fmt.Errorf("no server certificate set, UpdateCertificate must be called before Run")
	}
	tlsConfig := &tls.Config{
		// The certificate is looked up on every handshake rather than fixed here, so that a
		// certificate rotation does not require restarting the server.
		GetCertificate: s.getCertificate,
		MinVersion:     tls.VersionTLS12,
		// RequestClientCert asks every client for a certificate without requiring one: a client
		// authenticating with a bearer token simply presents none and the handshake still succeeds.
		// Verification is deliberately left to the authenticator rather than to the TLS stack
		// (which RequireAndVerifyClientCert would do), so that an unverifiable certificate is
		// reported as a gRPC Unauthenticated error, or Unavailable if the client CA bundle has not
		// loaded, rather than as an opaque handshake failure. ClientCAs is left unset for the same reason.
		ClientAuth: tls.RequestClientCert,
	}
	transition(StateServing)

	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(rejectUnaryRPC),
		// grpc-go's default is math.MaxUint32, i.e. one connection may open unbounded concurrent
		// streams. This is a transport-level backstop rather than a replacement for the per-client-IP cap
		// the authenticator applies — an attacker can always open more connections — and it is set high
		// enough not to preempt that cap; see the maxStreamsPerConn field.
		grpc.MaxConcurrentStreams(s.maxStreamsPerConn),
	}
	if s.authenticator != nil {
		serverOpts = append(serverOpts, grpc.StreamInterceptor(s.authenticator.StreamInterceptor))
	}
	server := grpc.NewServer(serverOpts...)
	flowpb.RegisterFlowStreamServiceServer(server, s)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		klog.InfoS("Starting FlowStreamService gRPC server", "addr", lis.Addr())
		// Serve returns nil if Stop or GracefulStop is called while it is serving, and an error
		// otherwise, in which case the server is no longer reachable and will not recover on its
		// own. The exception is grpc.ErrServerStopped, which Serve returns when the stop ran
		// first, i.e. when stopCh was already closed (or closed right away) and GracefulStop beat
		// this goroutine to Serve. That is a stop, not a failure, and it can only happen once Run
		// has been asked to stop, so it cannot hide a real failure.
		if err := server.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			klog.ErrorS(err, "FlowStreamService gRPC server failed")
			transition(StateFailed)
		}
	}()
	<-stopCh
	transition(StateStopping)
	// GracefulStop waits for all active GetFlows RPCs to return before shutting down. stopCh is
	// only closed when the Flow Aggregator stops, as a certificate rotation does not restart the
	// server, and active streams then drain because the Flow Aggregator also shuts down the ring
	// buffer, which causes every consumer's ConsumeMultiple to return shutdown=true and GetFlows to
	// return promptly. A follow stream would otherwise only end when its client goes away.
	server.GracefulStop()
	wg.Wait()
	return nil
}

// rejectUnaryRPC refuses every unary RPC. FlowStreamService is server-streaming only, so the
// authenticator is installed as a stream interceptor and a unary method would be served with no
// credential check at all.
// The rejection is logged at V(2) for the same reason authentication failures are: it happens before
// any credential is checked, so an unauthenticated peer must not be able to flood the log by calling
// a unary method in a loop.
func rejectUnaryRPC(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	klog.V(2).ErrorS(nil, "Refusing unary RPC on FlowStreamService, which serves streaming RPCs only", "method", info.FullMethod)
	return nil, status.Errorf(codes.Unauthenticated, "%s is a unary RPC, which FlowStreamService does not serve", info.FullMethod)
}

// GetFlows is the server-streaming RPC handler. The gRPC framework spawns a
// goroutine per connected client and calls this method. It exits when:
//   - the client disconnects (ctx cancelled / stream.Send error),
//   - follow=false and all historical flows have been sent,
//   - max_count flows have been sent,
//   - or the ring buffer shuts down.
func (s *FlowStreamService) GetFlows(req *flowpb.GetFlowsRequest, stream flowpb.FlowStreamService_GetFlowsServer) error {
	ctx := stream.Context()

	// username is only used for logging; what the client may observe is decided by streamAuth.
	var username string
	var streamAuth *StreamAuthorization
	if s.authorizer != nil {
		u, ok := request.UserFrom(ctx)
		if !ok {
			// Only reachable if the service was built with an authorizer but no authenticator,
			// which the Flow Aggregator never does. Fail closed rather than serve a stream whose
			// permissions cannot be resolved.
			return status.Error(codes.Unauthenticated, "no authenticated user for this stream")
		}
		username = u.GetName()
		var err error
		if streamAuth, err = s.authorizer.NewStreamAuthorization(ctx, u, req); err != nil {
			klog.V(2).InfoS("Rejected a FlowStreamService client", "user", username, "err", err)
			return err
		}
	}

	var since time.Time
	if ts := req.GetSince(); ts != nil {
		since = ts.AsTime()
	}
	maxCount := int(req.GetMaxCount())
	follow := req.GetFollow()

	// Parse label selectors and IP filters for each filter upfront so we can return
	// InvalidArgument before touching the ring buffer.
	reqFilters := req.GetFilters()
	parsedFilters := make([]flowFilter, len(reqFilters))
	for i, f := range reqFilters {
		pf, err := parseFlowFilter(f)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid filter %d: %v", i, err)
		}
		parsedFilters[i] = pf
	}

	klog.InfoS("Client connected to FlowStreamService",
		"user", username,
		"namespaces", req.GetNamespaces(),
		"clusterWide", req.GetClusterWide(),
		"follow", follow,
		"since", since,
		"maxCount", maxCount,
		"filters", reqFilters,
		"resume", req.GetResume())

	// A resume token from this same FA process is validated before the ring buffer is touched at
	// all, and rejects a value this server could never have issued: -1 is the lowest sequence number
	// possible (nothing accounted for yet), and a sequence_number this server issued is never at
	// or beyond its own current position, since sequence numbers only ever increase.
	//
	// A token whose stream_epoch does not match is a different, non-error case: the Flow Aggregator
	// restarted, so nothing about the previous epoch's ring buffer is known here — including whether
	// the client missed anything. Such a token cannot name a position in this epoch's buffer, so it
	// is treated exactly like no resume token at all: replay from the oldest record still held. The
	// client learns its resume was not honored from the stream_epoch in the handshake response,
	// which is always this process's own.
	//
	// resumePos is the position just before where the consumer starts: the resume point if there is
	// a valid one, or otherwise the position just before the oldest record the buffer holds now
	// (-1 if it has not wrapped yet). It is computed once and used both to position the consumer and
	// as the handshake's token, so that the token always names where this stream actually starts: a
	// client that disconnects before any data response and resumes from it must not be told that
	// records evicted (before this stream even opened) were dropped. In the rare case where the
	// producer advances between Tip and NewConsumer, the consumer starts slightly behind the buffer
	// and its first read counts those records as dropped, which is correct: they were held when the
	// stream started, and were evicted before it could deliver them.
	resumePos := max(s.buffer.Tip()-s.buffer.Capacity(), 0) - 1
	if r := req.GetResume(); r != nil && r.GetStreamEpoch() == s.streamEpoch {
		if r.GetSequenceNumber() < -1 {
			return status.Errorf(codes.InvalidArgument,
				"resume sequence_number %d is invalid: must be -1 or greater", r.GetSequenceNumber())
		}
		if tip := s.buffer.Tip(); r.GetSequenceNumber() >= tip {
			return status.Errorf(codes.InvalidArgument,
				"resume sequence_number %d is invalid: must be less than %d, the next position to be written",
				r.GetSequenceNumber(), tip)
		}
		// A resume point that has already fallen out of the ring buffer deliberately leaves the
		// consumer positioned behind the buffer rather than clamped forward to the oldest record
		// still held: the whole evicted span then arrives as dropped on the first read below,
		// instead of being silently replayed as if it were new.
		resumePos = r.GetSequenceNumber()
	}

	consumer := s.buffer.NewConsumer(
		ringbuffer.WithReadFromSequenceNumber(resumePos),
		ringbuffer.WithMaxConsumeDeadline(exporter.ConsumeDeadline),
	)

	// The stream is live. This first response confirms that authentication and authorization
	// succeeded, and carries the stream epoch, from which a resuming client learns whether its
	// resume was honored. Clients recognize it as the first response on the stream. Flows is always
	// empty here, and nothing has been read yet: the token names the position just before where the
	// consumer starts, and dropped_count is left 0 for the same reason rather than as a measurement.
	if err := stream.Send(&flowpb.GetFlowsResponse{
		ResumeToken: &flowpb.ResumeToken{StreamEpoch: s.streamEpoch, SequenceNumber: resumePos},
	}); err != nil {
		klog.InfoS("Send initial response to client failed, closing GetFlows stream", "err", err)
		return err
	}

	// The scope a stream was opened with is not reported back to the client: a request is
	// authorized in full or rejected outright, and at most one Namespace may be named, so the
	// authorized set is always exactly what the client asked for. If an under-specified scope is
	// ever accepted — an empty namespaces list coming to mean "every Namespace I may observe",
	// which Kubernetes cannot answer today — the server will have to report what it resolved to,
	// and a field can be added to GetFlowsResponse then.

	sent := 0
	var totalDropped uint64
	batch := make([]*flowpb.Flow, internalBatchSize)
	// lastTokenPos is the sequence number of the last resume token sent. When authorization or the
	// client's filters remove every record in a batch, nothing needs to be sent, but the client's
	// resume point then falls behind; once it has fallen behind by tokenRefreshSpan, a response
	// with no flows is sent just to carry the token forward. Otherwise, a restricted/selective
	// client could stay connected while the buffer wraps many times, and on reconnect be told
	// that records filtered out for it were dropped. Waiting for half the buffer's capacity
	// bounds how often such responses are sent, while leaving the other half as headroom for the
	// client to reconnect before its resume point is evicted.
	lastTokenPos := resumePos
	tokenRefreshSpan := max(s.buffer.Capacity()/2, 1)

	for {
		if err := ctx.Err(); err != nil {
			klog.InfoS("Client disconnected from FlowStreamService", "err", err)
			return status.FromContextError(err).Err()
		}

		if streamAuth != nil {
			// Re-checking the stream's own scope is what makes revoking a grant end a stream that
			// is already running. It is a no-op except once every revalidationInterval.
			if err := streamAuth.Revalidate(ctx); err != nil {
				klog.InfoS("Closing GetFlows stream", "user", username, "err", err)
				return err
			}
		}

		// A batch returned together with shutdown is still processed and sent below before the
		// stream closes: it is the last one the buffer will ever hand out.
		n, dropped, endPos, shutdown := consumer.ConsumeMultiple(batch)
		totalDropped += uint64(dropped)

		limit := 0
		if maxCount > 0 {
			limit = maxCount - sent
		}
		filtered, examined := selectRecords(ctx, streamAuth, batch[:n], parsedFilters, since, limit)
		// tokenPos is the ring-buffer position of the last record this stream accounted for.
		// batch[:n] holds positions [endPos-n, endPos), so batch[i] is at endPos-n+i, and the
		// last examined record is at endPos-n+examined-1. Normally examined == n and the token
		// is endPos-1. When max_count stops consumption early, the records after the last examined
		// one have not been sent, so tokenPos stops before them; otherwise a client resuming from
		// it would skip them.
		tokenPos := endPos - int64(n) + int64(examined) - 1
		if len(filtered) > 0 || dropped > 0 || tokenPos-lastTokenPos >= tokenRefreshSpan {
			resp := &flowpb.GetFlowsResponse{
				Flows:        filtered,
				DroppedCount: totalDropped,
				ResumeToken:  &flowpb.ResumeToken{StreamEpoch: s.streamEpoch, SequenceNumber: tokenPos},
			}
			if err := stream.Send(resp); err != nil {
				klog.InfoS("Send to client failed, closing GetFlows stream", "err", err)
				return err
			}
			sent += len(filtered)
			lastTokenPos = tokenPos
		}

		if maxCount > 0 && sent >= maxCount {
			klog.InfoS("Reached max_count, closing GetFlows stream", "sent", sent)
			return nil
		}

		if shutdown {
			klog.InfoS("Ring buffer shut down, closing GetFlows stream")
			return nil
		}

		// n == 0 with dropped > 0 is not the tail: every record available to this read was
		// overwritten before it could be read, and the buffer may still hold more.
		if !follow && n == 0 && dropped == 0 {
			// Sending up-to-date tokenPos for a non-follow stream at the tail keeps a selective
			// client's dropped_count accurate across repeated non-follow polls.
			if tokenPos > lastTokenPos {
				if err := stream.Send(&flowpb.GetFlowsResponse{
					DroppedCount: totalDropped,
					ResumeToken:  &flowpb.ResumeToken{StreamEpoch: s.streamEpoch, SequenceNumber: tokenPos},
				}); err != nil {
					klog.InfoS("Send to client failed, closing GetFlows stream", "err", err)
					return err
				}
			}
			klog.InfoS("Caught up to ring buffer tail, closing non-follow stream")
			return nil
		}
	}
}

// selectRecords returns the records in batch that the stream may observe and that match the
// client's filters, in order, stopping once limit records are selected (a limit of 0 means no
// limit). It also returns how many records of batch it examined, which is len(batch) unless the
// limit stopped it early: the records past that were neither delivered nor filtered out.
//
// Authorization runs before the client's own filters, and before the max_count accounting, so
// that a record the client may not observe is never counted against the records it asked for, and
// so that filters only ever match what it can see. That last point is also what gives a filter
// naming a Namespace outside the stream's scope its meaning: every record here already has an
// endpoint in scope, so such a filter selects flows by their peer (or by their Service, with a
// service_names entry qualified by that Namespace), and matches only where that Namespace was
// disclosed.
//
// The selected records are compacted into batch[:0], so batch is modified.
func selectRecords(ctx context.Context, streamAuth *StreamAuthorization, batch []*flowpb.Flow, filters []flowFilter, since time.Time, limit int) ([]*flowpb.Flow, int) {
	records := slices.All(batch)
	if streamAuth != nil {
		records = streamAuth.Authorized(ctx, batch)
	}
	selected := batch[:0]
	examined := len(batch)
	for i, f := range records {
		if !matchFlow(f, filters, since) {
			continue
		}
		selected = append(selected, f)
		if limit > 0 && len(selected) >= limit {
			examined = i + 1
			break
		}
	}
	return selected, examined
}

// flowFilter holds the pre-parsed form of a FlowFilter proto, so that
// expensive operations (label selector parsing, IP/prefix parsing) happen once
// per stream rather than once per flow.
type flowFilter struct {
	proto            *flowpb.FlowFilter
	podLabelSelector labels.Selector
	// parsedAddrs holds exact IP addresses from proto.GetIps().
	parsedAddrs []netip.Addr
	// parsedPrefixes holds CIDR prefixes from proto.GetIps().
	parsedPrefixes []netip.Prefix
	// serviceNames holds the entries of proto.GetServiceNames().
	serviceNames []serviceName
}

// serviceName is a service_names entry. An empty namespace matches a Service of that name in any
// Namespace.
type serviceName struct {
	namespace, name string
}

// parseFlowFilter parses and validates a FlowFilter proto, returning a flowFilter
// with all expensive-to-parse fields pre-computed. Returns an error if any field
// contains an invalid value (e.g. bad label selector or unparseable IP).
func parseFlowFilter(f *flowpb.FlowFilter) (flowFilter, error) {
	pf := flowFilter{proto: f}

	if selStr := f.GetPodLabelSelector(); selStr != "" {
		sel, err := labels.Parse(selStr)
		if err != nil {
			return flowFilter{}, fmt.Errorf("invalid pod_label_selector %q: %w", selStr, err)
		}
		pf.podLabelSelector = sel
	}

	if len(f.GetServiceNames()) > 0 {
		dir := f.GetDirection()
		if dir == flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM {
			return flowFilter{}, fmt.Errorf("service_names filter does not support FROM direction")
		}
	}
	for _, s := range f.GetServiceNames() {
		namespace, name, qualified := strings.Cut(s, "/")
		if !qualified {
			pf.serviceNames = append(pf.serviceNames, serviceName{name: s})
			continue
		}
		if namespace == "" || name == "" || strings.Contains(name, "/") {
			return flowFilter{}, fmt.Errorf("invalid service name %q: expected name or namespace/name", s)
		}
		pf.serviceNames = append(pf.serviceNames, serviceName{namespace: namespace, name: name})
	}

	for _, ipStr := range f.GetIps() {
		if strings.Contains(ipStr, "/") {
			prefix, err := netip.ParsePrefix(ipStr)
			if err != nil {
				return flowFilter{}, fmt.Errorf("invalid IP prefix %q: %w", ipStr, err)
			}
			pf.parsedPrefixes = append(pf.parsedPrefixes, prefix)
		} else {
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				return flowFilter{}, fmt.Errorf("invalid IP address %q: %w", ipStr, err)
			}
			pf.parsedAddrs = append(pf.parsedAddrs, addr)
		}
	}

	return pf, nil
}

// matchFlow reports whether a single flow passes the "since" cutoff and matches ALL of the
// provided filters (AND semantics across filters). An empty filters slice matches all flows.
func matchFlow(f *flowpb.Flow, filters []flowFilter, since time.Time) bool {
	// (*timestamppb.Timestamp).AsTime() is nil-safe and returns the zero time,
	// which is before any non-zero since value, so flows with a nil EndTs are
	// correctly excluded when a "since" cutoff is active.
	if !since.IsZero() && f.GetEndTs().AsTime().Before(since) {
		return false
	}
	for i := range filters {
		if !matchFilter(f, &filters[i]) {
			return false
		}
	}
	return true
}

// matchFilter reports whether f matches pf. Its criteria are AND-ed:
//   - flow_types and service_names apply to the flow as a whole, whatever the direction:
//     service_names matches the flow's destination Service, by name or by Namespace and name.
//   - The directional criteria (namespaces, pod_names, pod_label_selector, ips) are all matched
//     against the same endpoint, which the direction picks, so that for example namespaces and
//     pod_names select a single Pod. With BOTH, either endpoint may be the one that matches.
func matchFilter(f *flowpb.Flow, pf *flowFilter) bool {
	filter := pf.proto
	k8s := f.GetK8S()
	if len(filter.GetFlowTypes()) > 0 {
		if k8s == nil || !containsFlowType(filter.GetFlowTypes(), k8s.GetFlowType()) {
			return false
		}
	}
	if len(pf.serviceNames) > 0 {
		namespace, name := destinationService(k8s.GetDestinationServicePortName())
		if !slices.ContainsFunc(pf.serviceNames, func(s serviceName) bool {
			return s.name == name && (s.namespace == "" || s.namespace == namespace)
		}) {
			return false
		}
	}
	switch filter.GetDirection() {
	case flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM:
		return matchEndpoint(f, pf, true)
	case flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO:
		return matchEndpoint(f, pf, false)
	default:
		return matchEndpoint(f, pf, true) || matchEndpoint(f, pf, false)
	}
}

// matchEndpoint reports whether one endpoint of f, its source if source is true and its
// destination otherwise, meets every directional criterion of pf. A filter with no directional
// criterion matches either endpoint.
func matchEndpoint(f *flowpb.Flow, pf *flowFilter, source bool) bool {
	filter := pf.proto
	k8s := f.GetK8S()
	var namespace, podName string
	var podLabels *flowpb.Labels
	var ip []byte
	if source {
		namespace, podName = k8s.GetSourcePodNamespace(), k8s.GetSourcePodName()
		podLabels, ip = k8s.GetSourcePodLabels(), f.GetIp().GetSource()
	} else {
		namespace, podName = k8s.GetDestinationPodNamespace(), k8s.GetDestinationPodName()
		podLabels, ip = k8s.GetDestinationPodLabels(), f.GetIp().GetDestination()
		if namespace == "" {
			// A destination without a Pod Namespace, such as a Service backed by Node or
			// external IPs (e.g. default/kubernetes), is in its Service's Namespace. This
			// cannot reveal a withheld Namespace: redaction removes the Service whenever it
			// withholds the destination's Namespace.
			namespace, _ = destinationService(k8s.GetDestinationServicePortName())
		}
	}

	needsK8s := len(filter.GetNamespaces()) > 0 || len(filter.GetPodNames()) > 0 || pf.podLabelSelector != nil
	if needsK8s && k8s == nil {
		return false
	}
	if len(filter.GetNamespaces()) > 0 && !slices.Contains(filter.GetNamespaces(), namespace) {
		return false
	}
	if len(filter.GetPodNames()) > 0 && !slices.Contains(filter.GetPodNames(), podName) {
		return false
	}
	if pf.podLabelSelector != nil && !pf.podLabelSelector.Matches(labelsFromProto(podLabels)) {
		return false
	}
	if len(pf.parsedAddrs) > 0 || len(pf.parsedPrefixes) > 0 {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return false
		}
		if !slices.Contains(pf.parsedAddrs, addr) && !slices.ContainsFunc(pf.parsedPrefixes, func(p netip.Prefix) bool {
			return p.Contains(addr)
		}) {
			return false
		}
	}
	return true
}

func labelsFromProto(l *flowpb.Labels) labels.Set {
	if l == nil {
		return labels.Set{}
	}
	return labels.Set(l.GetLabels())
}

func containsFlowType(types []flowpb.FlowType, t flowpb.FlowType) bool {
	for _, ft := range types {
		if ft == t {
			return true
		}
	}
	return false
}

// destinationService extracts the Service's Namespace and bare name from a
// DestinationServicePortName value. That field is set by the flow exporter from
// proxy.ServicePortName.String(), which produces "namespace/name:portName" (or
// "namespace/name" when the port has no named port).
func destinationService(s string) (namespace, name string) {
	namespace, s, ok := strings.Cut(s, "/")
	if !ok {
		return "", ""
	}
	name, _, _ = strings.Cut(s, ":")
	return namespace, name
}

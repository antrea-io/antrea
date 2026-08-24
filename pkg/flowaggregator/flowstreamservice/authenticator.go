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
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/klog/v2"
)

const (
	// authorizationMetadataKey is the gRPC metadata key clients must set to carry their bearer token,
	// mirroring the HTTP Authorization header. gRPC metadata keys are matched case-insensitively.
	// The value must be formatted as "Bearer <token>" (RFC 6750), though the scheme itself is matched
	// case-insensitively, since Kubernetes' bearertoken authenticator lowercases it before comparing.
	authorizationMetadataKey = "authorization"

	// clientCAConfigMapNamespace, clientCAConfigMapName and clientCAConfigMapKey locate the CA bundle
	// used to verify client certificates. Reading it requires the extension-apiserver-authentication-reader
	// Role in kube-system, which the Flow Aggregator is already bound to.
	clientCAConfigMapNamespace = metav1.NamespaceSystem
	clientCAConfigMapName      = "extension-apiserver-authentication"
	clientCAConfigMapKey       = "client-ca-file"

	// maxConcurrentTokenAuthentications bounds how many authentications that may reach kube-apiserver
	// are in flight at once. Without this bound, any Pod that can reach the FlowStreamService port
	// could turn cheap gRPC connects into unbounded concurrent requests against kube-apiserver without
	// ever presenting a valid credential.
	// A call is charged a slot whenever it carries authorization metadata, which is a slight
	// over-estimate: a client that presents both a token and a client certificate that verifies is
	// identified by the certificate and never reaches kube-apiserver, yet still holds a slot while
	// that is determined. Certificate-only calls take no slot, since they need no bound at all.
	maxConcurrentTokenAuthentications = 8
	// tokenAuthenticationTimeout bounds one TokenReview, including the retries the delegating
	// authenticator makes on a failing webhook, and so caps how long one credential can hold a slot.
	// The value is deliberately set above the delegating authenticator's 10s default plus retry
	// cycle, which the Flow Aggregator's own API server found too short (see authenticationTimeout in
	// pkg/flowaggregator/apiserver/apiserver.go).
	tokenAuthenticationTimeout = 30 * time.Second
)

// errAuthenticationOverloaded means the authenticator declined to check a credential because too
// many TokenReviews were already in flight, not that the credential was bad. It is reported to the
// client as ResourceExhausted, which is retryable, rather than as Unauthenticated.
var errAuthenticationOverloaded = errors.New("too many authentication requests in flight")

// StreamServerAuthenticator authenticates FlowStreamService clients. It provides the gRPC stream
// interceptor that runs before any RPC on the service reaches its handler; every RPC the service
// serves is server-streaming, and rejectUnaryRPC keeps it that way.
// Clients present either a Kubernetes bearer token in gRPC metadata (validated via TokenReview) or an
// X.509 client certificate as the TLS client credential of the gRPC connection (validated locally
// against the cluster's client CA bundle). The resolved identity is attached to the RPC context via
// request.WithUser and can be read back with request.UserFrom by authorization logic.
// A call that carries both credentials is identified by its client certificate, because that is the
// order the delegating authenticator tries them in, and the order kube-apiserver itself uses. If the
// certificate does not verify against the cluster's client CA bundle, TokenReview will be attempted
// and used as identity if successful.
type StreamServerAuthenticator struct {
	// authenticator is the delegated authenticator kube-apiserver's own aggregated API servers are
	// built with: x509 against the cluster's client CA bundle, then TokenReview, with the
	// system:authenticated group added to whichever succeeds. It reads the trust bundle through
	// clientCAProvider on every call, so a rotated CA takes effect without a restart.
	authenticator authenticator.Request
	// clientCAProvider caches and watches the cluster's client CA bundle. It must be started with Run
	// before the client certificate path can accept anything.
	clientCAProvider *dynamiccertificates.ConfigMapCAController
	// tokenAuthSlots is a semaphore bounding authentications that may reach kube-apiserver to
	// maxConcurrentTokenAuthentications. A send acquires a slot, a receive releases it, and a failed
	// non-blocking send means the path is saturated and declines the credential rather than queueing
	// behind the ones already in flight.
	tokenAuthSlots chan struct{}
}

// NewStreamServerAuthenticator builds an authenticator that resolves credentials against the cluster
// k8sClient talks to.
func NewStreamServerAuthenticator(k8sClient kubernetes.Interface) (*StreamServerAuthenticator, error) {
	return newStreamServerAuthenticator(k8sClient, k8sClient.AuthenticationV1())
}

// newStreamServerAuthenticator takes the TokenReview client separately from the client the CA bundle
// is read with, so that tests can supply one and fake the other.
func newStreamServerAuthenticator(k8sClient kubernetes.Interface, tokenReviewClient authenticationv1client.AuthenticationV1Interface) (*StreamServerAuthenticator, error) {
	clientCAProvider, err := dynamiccertificates.NewDynamicCAFromConfigMapController(
		"client-ca", clientCAConfigMapNamespace, clientCAConfigMapName, clientCAConfigMapKey, k8sClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create client CA provider: %w", err)
	}
	// Log the CA bundle whenever it changes, including the first time it is loaded.
	clientCAProvider.AddListener(caBundleListenerFunc(func() {
		klog.InfoS("Loaded client CA bundle for FlowStreamService client certificate authentication",
			"namespace", clientCAConfigMapNamespace, "configMap", clientCAConfigMapName,
			"key", clientCAConfigMapKey, "bytes", len(clientCAProvider.CurrentCABundleContent()))
	}))

	delegating := authenticatorfactory.DelegatingAuthenticatorConfig{
		ClientCertificateCAContentProvider: clientCAProvider,
		TokenAccessReviewClient:            tokenReviewClient,
		TokenAccessReviewTimeout:           tokenAuthenticationTimeout,
		WebhookRetryBackoff:                genericoptions.DefaultAuthWebhookRetryBackoff(),
		// Anonymous is left nil, so no anonymous authenticator is appended to the chain and a call
		// carrying no credential is declined instead of being admitted as system:anonymous.
	}
	auth, _, err := delegating.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create delegating authenticator: %w", err)
	}

	return &StreamServerAuthenticator{
		authenticator:    auth,
		clientCAProvider: clientCAProvider,
		tokenAuthSlots:   make(chan struct{}, maxConcurrentTokenAuthentications),
	}, nil
}

// Run keeps the client CA bundle used to verify client certificates in sync with the ConfigMap
// kube-apiserver publishes it in. It blocks until stopCh is closed.
// The bundle is read through an informer that Run starts, so client certificate authentication only
// becomes available once that informer has synced. Until then — and permanently on a cluster whose
// kube-apiserver publishes no client CA at all — x509 verification has no trust bundle and declines
// every peer certificate rather than accepting an unverified one. Bearer-token authentication does
// not depend on any of this and keeps working either way.
func (a *StreamServerAuthenticator) Run(stopCh <-chan struct{}) {
	a.clientCAProvider.Run(wait.ContextForChannel(stopCh), 1)
}

// caBundleListenerFunc adapts a function to dynamiccertificates.Listener.
type caBundleListenerFunc func()

func (f caBundleListenerFunc) Enqueue() { f() }

// StreamInterceptor implements grpc.StreamServerInterceptor. It rejects the call with
// codes.Unauthenticated if the request does not carry a valid bearer token or client certificate;
// otherwise it attaches the resolved identity to the stream context before invoking handler.
func (a *StreamServerAuthenticator) StreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	u, err := a.authenticate(ss.Context())
	if err != nil {
		return authenticationStatusError(err)
	}

	return handler(srv, &authenticatedServerStream{
		ServerStream: ss,
		ctx:          request.WithUser(ss.Context(), u),
	})
}

// authenticationStatusError logs an authentication failure and maps it to the gRPC status returned to
// the client. Failures are logged at V(2) rather than unconditionally: the call is rejected before any
// credential is validated, so an unauthenticated peer must not be able to flood the log by
// reconnecting.
func authenticationStatusError(err error) error {
	klog.V(2).ErrorS(err, "FlowStreamService client authentication failed")
	if errors.Is(err, errAuthenticationOverloaded) {
		return status.Error(codes.ResourceExhausted, "too many authentication requests in flight, retry later")
	}
	return status.Error(codes.Unauthenticated, "invalid client credentials")
}

// authenticate resolves the credentials the call carries to an identity. It is called once per RPC,
// so the credential is re-checked every time a stream is opened rather than being trusted for the
// lifetime of the connection: a token that has since been invalidated is refused by TokenReview, and
// an expired client certificate fails verification. Client certificate revocation is not detected,
// since x509 verification is local and consults no CRL or OCSP responder, so a revoked certificate
// keeps working until it expires — the same exposure a revoked certificate has against
// kube-apiserver itself.
func (a *StreamServerAuthenticator) authenticate(ctx context.Context) (user.Info, error) {
	req, carriesToken := authenticationRequest(ctx)
	// Only a call carrying authorization metadata can reach kube-apiserver, so only that call is
	// charged a slot; see maxConcurrentTokenAuthentications. The slot is released as soon as the
	// credential is resolved, not held for the lifetime of the stream it opens.
	if carriesToken {
		select {
		case a.tokenAuthSlots <- struct{}{}:
			defer func() { <-a.tokenAuthSlots }()
		default:
			return nil, errAuthenticationOverloaded
		}
	}

	resp, ok, err := a.authenticator.AuthenticateRequest(req)
	if err != nil {
		// Reported when a credential was presented and rejected: an unverifiable certificate, a token
		// TokenReview declined, or a TokenReview that could not be completed at all.
		return nil, fmt.Errorf("credentials were not accepted: %w", err)
	}
	if !ok {
		// Reported when nothing the call carries is a credential: no authorization metadata and no
		// client certificate, or an authorization value that is not a bearer token.
		return nil, fmt.Errorf("call carries no credential to authenticate")
	}
	u := resp.User

	// Neither path should ever produce an unnamed or anonymous identity, so this fails closed for both.
	if u.GetName() == "" {
		return nil, fmt.Errorf("credential resolved to an empty user name")
	}
	if u.GetName() == user.Anonymous || slices.Contains(u.GetGroups(), user.AllUnauthenticated) {
		return nil, fmt.Errorf("credential resolved to the anonymous user")
	}
	return u, nil
}

// authenticationRequest renders the credentials a gRPC call carries as the *http.Request the
// Kubernetes authenticators expect, because they were written for an HTTP server. Only two fields are
// read: TLS, from which the x509 authenticator takes the peer's certificate chain, and the
// Authorization header, from which the bearer token authenticator takes the token. The reported bool
// is whether the call carried authorization metadata at all, not whether it is a usable token.
//
// The call's context is attached so that the TokenReview issued on it is cancelled when the client
// gives up, rather than running to its own timeout with nobody waiting for the answer.
func authenticationRequest(ctx context.Context) (*http.Request, bool) {
	req := (&http.Request{
		Header: http.Header{},
		TLS:    peerTLSState(ctx),
	}).WithContext(ctx)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return req, false
	}
	values := md.Get(authorizationMetadataKey)
	if len(values) == 0 {
		return req, false
	}
	// http.Header.Set canonicalizes the lowercase gRPC metadata key to "Authorization", which is what
	// the bearertoken authenticator reads.
	req.Header.Set(authorizationMetadataKey, values[0])
	return req, true
}

// peerTLSState returns the TLS handshake state of the gRPC peer, or nil if the peer is unknown or did
// not connect over TLS. The FlowStreamService listener requests a client certificate without
// requiring one, so a client authenticating with a bearer token reaches here with a valid TLS state
// whose certificate chain is empty.
func peerTLSState(ctx context.Context) *tls.ConnectionState {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return &tlsInfo.State
}

// authenticatedServerStream wraps a grpc.ServerStream to override Context(),
// since grpc.ServerStream does not otherwise allow attaching values to the
// stream's context.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}

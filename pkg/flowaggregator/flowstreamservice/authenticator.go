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
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	// authorizationMetadataKey is the gRPC metadata key clients must set to carry their bearer token,
	// mirroring the HTTP Authorization header. gRPC metadata keys are matched case-insensitively.
	authorizationMetadataKey = "authorization"
	// bearerTokenScheme is the scheme clients must use in the authorization metadata value, e.g.
	// "Bearer <token>" (RFC 6750). RFC 7235 defines the auth-scheme token as case-insensitive, and
	// Kubernetes' own bearertoken authenticator compares it with strings.EqualFold rather than as a
	// literal prefix, so this does the same instead of rejecting an otherwise valid "bearer <token>"
	// or "BEARER <token>".
	bearerTokenScheme = "Bearer"

	// clientCertMetadataKey and clientKeyMetadataKey carry a PEM-encoded X.509 client certificate and
	// private key respectively. This is how a client that authenticated via a Pinniped Concierge
	// TokenCredentialRequest (which always returns a short-lived client cert, never a bearer token)
	// presents its credential. The "-bin" suffix is required by gRPC for metadata values that are not
	// valid ASCII; grpc-go base64-encodes/decodes such headers transparently at the transport layer,
	// so values read back from the incoming context here are already raw PEM bytes, not base64 text.
	clientCertMetadataKey = "client-cert-bin"
	clientKeyMetadataKey  = "client-key-bin"

	// maxConcurrentCertAuthentications bounds how many client-certificate authentications, and
	// maxConcurrentTokenAuthentications how many bearer-token authentications, may be in flight at
	// once. Both exist for the same underlying reason: StreamInterceptor runs once per stream,
	// before the credential is validated, and an in-cluster rest.Config leaves QPS at 0, so
	// client-go installs no request-rate limiter for either the per-request client that
	// authenticateCert builds for SelfSubjectReview or the Flow Aggregator's own shared a.k8sClient
	// that authenticateToken uses for TokenReview. Without these bounds, any Pod that can reach the
	// FlowStreamService port could turn cheap gRPC connects into unbounded concurrent requests
	// against kube-apiserver without ever presenting a valid credential.
	//
	// The cert path additionally pays for a TLS handshake and http.Transport per distinct
	// credential, since each cert/key pair is its own client config; the token path reuses one
	// connection pool, so its bound exists purely to cap request rate, not transport cost.
	maxConcurrentCertAuthentications  = 8
	maxConcurrentTokenAuthentications = 8
	// certAuthenticationTimeout bounds one SelfSubjectReview, and tokenAuthenticationTimeout bounds
	// one TokenReview; each is what keeps a slow or unreachable API server from turning its small
	// concurrency bound into a denial of service for legitimate clients, by capping how long a
	// single credential can hold a slot.
	certAuthenticationTimeout  = 10 * time.Second
	tokenAuthenticationTimeout = 10 * time.Second
)

// errAuthenticationOverloaded means the authenticator declined to check a credential because too
// many checks of that kind were already in flight, not that the credential was bad. It is reported
// to the client as ResourceExhausted, which is retryable, rather than as Unauthenticated.
var errAuthenticationOverloaded = errors.New("too many authentication requests in flight")

// newKubernetesClientForConfig builds a Kubernetes ClientSet for cfg. It is a package-level variable,
// so tests can substitute a fake SelfSubjectReviews implementation without standing up a real
// TLS-terminating API server for the ephemeral, per-request client-cert config to authenticate against.
var newKubernetesClientForConfig = func(cfg *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(cfg)
}

// clientCredential is the credential a connecting client presented, extracted from gRPC metadata.
// Exactly one of token or (certPEM, keyPEM) is set.
type clientCredential struct {
	token   string
	certPEM []byte
	keyPEM  []byte
}

// StreamServerAuthenticator is a gRPC stream server interceptor that authenticates FlowStreamService clients.
// Clients present either a Kubernetes bearer token (validated via TokenReview) or a short-lived X.509
// client certificate (validated via SelfSubjectReview against the API server), both carried as gRPC metadata.
// The resolved identity is attached to the stream context via request.WithUser and can be read back with
// request.UserFrom by authorization logic.
type StreamServerAuthenticator struct {
	k8sClient kubernetes.Interface
	// baseConfig is flow-aggregator's own in-cluster rest.Config. It is never used to authenticate as
	// flow-aggregator itself; every per-request config derived from it via rest.AnonymousClientConfig
	// strips flow-aggregator's own credentials first (see authenticateCert), keeping only the Host/CA
	// fields needed to reach and verify the real API server.
	baseConfig *rest.Config
	// certAuthSlots and tokenAuthSlots are semaphores bounding concurrent client-certificate and
	// bearer-token authentications respectively, to maxConcurrentCertAuthentications and
	// maxConcurrentTokenAuthentications. A send acquires a slot, a receive releases it, and a
	// failed non-blocking send means that path is saturated and declines the credential rather
	// than queueing behind the ones already in flight.
	certAuthSlots  chan struct{}
	tokenAuthSlots chan struct{}
}

func NewStreamServerAuthenticator(k8sClient kubernetes.Interface, baseConfig *rest.Config) *StreamServerAuthenticator {
	return &StreamServerAuthenticator{
		k8sClient:      k8sClient,
		baseConfig:     baseConfig,
		certAuthSlots:  make(chan struct{}, maxConcurrentCertAuthentications),
		tokenAuthSlots: make(chan struct{}, maxConcurrentTokenAuthentications),
	}
}

// StreamInterceptor implements grpc.StreamServerInterceptor. It rejects the call with codes.Unauthenticated
// if the request does not carry a valid bearer token or client certificate; otherwise it attaches the resolved
// identity to the stream context before invoking handler.
func (a *StreamServerAuthenticator) StreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	cred, err := credentialFromContext(ss.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	u, err := a.authenticate(ss.Context(), cred)
	if err != nil {
		klog.V(2).ErrorS(err, "FlowStreamService client authentication failed")
		if errors.Is(err, errAuthenticationOverloaded) {
			return status.Error(codes.ResourceExhausted, "too many authentication requests in flight, retry later")
		}
		return status.Error(codes.Unauthenticated, "invalid client credentials")
	}

	return handler(srv, &authenticatedServerStream{
		ServerStream: ss,
		ctx:          request.WithUser(ss.Context(), u),
	})
}

// credentialFromContext extracts the client's credential from the incoming gRPC metadata of a stream:
// either a bearer token in the "authorization" header, or a PEM client cert+key pair in the
// client-cert-bin/client-key-bin headers. A bearer token takes precedence if both happen to be present.
func credentialFromContext(ctx context.Context) (*clientCredential, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing gRPC metadata")
	}

	if values := md.Get(authorizationMetadataKey); len(values) > 0 {
		scheme, token, found := strings.Cut(values[0], " ")
		if !found || !strings.EqualFold(scheme, bearerTokenScheme) || token == "" {
			return nil, fmt.Errorf("authorization header must be a bearer token")
		}
		return &clientCredential{token: token}, nil
	}

	certValues := md.Get(clientCertMetadataKey)
	keyValues := md.Get(clientKeyMetadataKey)
	if len(certValues) > 0 || len(keyValues) > 0 {
		if len(certValues) == 0 || len(keyValues) == 0 {
			return nil, fmt.Errorf("both %s and %s metadata are required", clientCertMetadataKey, clientKeyMetadataKey)
		}
		return &clientCredential{certPEM: []byte(certValues[0]), keyPEM: []byte(keyValues[0])}, nil
	}

	return nil, fmt.Errorf("missing authorization header or client certificate metadata")
}

// authenticate resolves cred to an identity. It is called once per stream, when the stream is opened,
// so the credential is always validated against the Kubernetes API server: a revoked or expired
// credential can never be used to open a new stream.
func (a *StreamServerAuthenticator) authenticate(ctx context.Context, cred *clientCredential) (user.Info, error) {
	if cred.token != "" {
		return a.authenticateToken(ctx, cred.token)
	}
	return a.authenticateCert(ctx, cred.certPEM, cred.keyPEM)
}

// authenticateToken validates token via the TokenReview API.
// This runs once per stream before the credential is validated, against a.k8sClient, whose
// in-cluster rest.Config installs no request-rate limiter. It is bounded by a.tokenAuthSlots for
// that reason; see maxConcurrentTokenAuthentications.
func (a *StreamServerAuthenticator) authenticateToken(ctx context.Context, token string) (*user.DefaultInfo, error) {
	select {
	case a.tokenAuthSlots <- struct{}{}:
		defer func() { <-a.tokenAuthSlots }()
	default:
		return nil, errAuthenticationOverloaded
	}
	ctx, cancel := context.WithTimeout(ctx, tokenAuthenticationTimeout)
	defer cancel()

	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}
	review, err := a.k8sClient.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("TokenReview request failed: %w", err)
	}
	if review.Status.Error != "" {
		return nil, fmt.Errorf("TokenReview returned an error: %s", review.Status.Error)
	}
	if !review.Status.Authenticated {
		return nil, fmt.Errorf("token is not authenticated")
	}
	return userInfoFromK8s(review.Status.User), nil
}

// authenticateCert validates a PEM client cert+key pair via SelfSubjectReview:
// it builds an ephemeral rest.Config that authenticates with the presented certificate data and asks the
// K8s API server "who does the API server think I am, given how I just authenticated to it?"
// This is used for clients (e.g. Pinniped Concierge TokenCredentialRequest) whose only available credential
// is a short-lived client certificate rather than a bearer token.
//
// Unlike the token path, this builds a client of its own, and therefore a TLS handshake of its own,
// for every credential presented. It is bounded by a.certAuthSlots for that reason; see
// maxConcurrentCertAuthentications.
func (a *StreamServerAuthenticator) authenticateCert(ctx context.Context, certPEM, keyPEM []byte) (*user.DefaultInfo, error) {
	if a.baseConfig == nil {
		return nil, fmt.Errorf("baseConfig is required for client certificate authentication")
	}
	// The slot is taken before the client is built, since building it is what allocates the
	// transport that the handshake then runs on.
	select {
	case a.certAuthSlots <- struct{}{}:
		defer func() { <-a.certAuthSlots }()
	default:
		return nil, errAuthenticationOverloaded
	}
	ctx, cancel := context.WithTimeout(ctx, certAuthenticationTimeout)
	defer cancel()
	// rest.AnonymousClientConfig strips every credential (bearer token, client cert, exec plugin, ...)
	// from a.baseConfig, keeping only the fields needed to reach and verify the real API server
	// (Host, APIPath, TLS server-verification settings). This is security-critical:
	// clone of a.baseConfig would still carry flow-aggregator's own ServiceAccount bearer token,
	// and an expired/invalid client cert would silently fall through to authenticating as
	// flow-aggregator's own ServiceAccount instead of failing closed, causing privileged access
	// for clients.
	cfg := rest.AnonymousClientConfig(a.baseConfig)
	cfg.TLSClientConfig.CertData = certPEM
	cfg.TLSClientConfig.KeyData = keyPEM

	client, err := newKubernetesClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build client for SelfSubjectReview: %w", err)
	}

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("SelfSubjectReview request failed: %w", err)
	}
	return userInfoFromK8s(review.Status.UserInfo), nil
}

// userInfoFromK8s converts a Kubernetes authenticationv1.UserInfo (returned by
// both TokenReview and SelfSubjectReview) into the user.DefaultInfo expected
// by request.WithUser.
func userInfoFromK8s(u authenticationv1.UserInfo) *user.DefaultInfo {
	return &user.DefaultInfo{
		Name:   u.Username,
		UID:    u.UID,
		Groups: u.Groups,
		Extra:  convertExtra(u.Extra),
	}
}

// convertExtra converts the Extra field of a TokenReview/SelfSubjectReview's
// UserInfo (map[string]authenticationv1.ExtraValue) into the plain
// map[string][]string expected by user.DefaultInfo.Extra. authenticationv1.ExtraValue
// is defined as `type ExtraValue []string`, so each value assigns to []string
// without a cast; it is the outer map type that differs and must be rebuilt
// key by key.
func convertExtra(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	if extra == nil {
		return nil
	}
	out := make(map[string][]string, len(extra))
	for k, v := range extra {
		out[k] = v
	}
	return out
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

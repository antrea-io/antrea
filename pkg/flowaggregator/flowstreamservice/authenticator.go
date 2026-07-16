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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
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
	// credentialCacheTTL bounds how long a successful authentication outcome
	// (TokenReview or SelfSubjectReview) is cached before the credential is
	// re-validated against the Kubernetes API server. This keeps a long-lived
	// or frequently reconnecting client from generating an API call on every
	// request while still picking up revocation (e.g. ServiceAccount deletion,
	// cert expiry) within a bounded time.
	credentialCacheTTL = 30 * time.Second

	// authorizationMetadataKey is the gRPC metadata key clients must set to
	// carry their bearer token, mirroring the HTTP Authorization header.
	// gRPC metadata keys are matched case-insensitively.
	authorizationMetadataKey = "authorization"
	// bearerTokenPrefix precedes the token in the authorization metadata
	// value, e.g. "Bearer <token>" (RFC 6750).
	bearerTokenPrefix = "Bearer "

	// clientCertMetadataKey and clientKeyMetadataKey carry a PEM-encoded X.509
	// client certificate and private key respectively. This is how a client
	// that authenticated via a Pinniped Concierge TokenCredentialRequest (which
	// always returns a short-lived client cert, never a bearer token) presents
	// its credential. The "-bin" suffix is required by gRPC for metadata values
	// that are not valid ASCII; grpc-go base64-encodes/decodes such headers
	// transparently at the transport layer, so values read back from the
	// incoming context here are already raw PEM bytes, not base64 text.
	clientCertMetadataKey = "client-cert-bin"
	clientKeyMetadataKey  = "client-key-bin"
)

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

// cacheKey returns the key under which this credential's resolved identity is cached. Both Bearer tokens
// and client certs are cached by a digest of the token or cert+key, to prevent data be exposed via heap
// dumps etc.
func (c *clientCredential) cacheKey() string {
	h := sha256.New()
	if c.token != "" {
		h.Write([]byte(c.token))
		return "token:" + hex.EncodeToString(h.Sum(nil))
	}
	h.Write(c.certPEM)
	h.Write(c.keyPEM)
	return "cert:" + hex.EncodeToString(h.Sum(nil))
}

// credentialCacheEntry is a cached authentication result for a clientCredential.
type credentialCacheEntry struct {
	user      user.Info
	expiresAt time.Time
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

	cacheMutex sync.Mutex
	cache      map[string]credentialCacheEntry
}

func NewStreamServerAuthenticator(k8sClient kubernetes.Interface, baseConfig *rest.Config) *StreamServerAuthenticator {
	return &StreamServerAuthenticator{
		k8sClient:  k8sClient,
		baseConfig: baseConfig,
		cache:      make(map[string]credentialCacheEntry),
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
		klog.ErrorS(err, "FlowStreamService client authentication failed")
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
		token, ok := strings.CutPrefix(values[0], bearerTokenPrefix)
		if !ok || token == "" {
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

// authenticate resolves cred to an identity, returning a cached outcome when
// available.
func (a *StreamServerAuthenticator) authenticate(ctx context.Context, cred *clientCredential) (user.Info, error) {
	cacheKey := cred.cacheKey()
	if u, ok := a.getCachedUser(cacheKey); ok {
		return u, nil
	}

	var u *user.DefaultInfo
	var err error
	if cred.token != "" {
		u, err = a.authenticateToken(ctx, cred.token)
	} else {
		u, err = a.authenticateCert(ctx, cred.certPEM, cred.keyPEM)
	}
	if err != nil {
		return nil, err
	}

	a.cacheUser(cacheKey, u)
	return u, nil
}

// authenticateToken validates token via the TokenReview API.
func (a *StreamServerAuthenticator) authenticateToken(ctx context.Context, token string) (*user.DefaultInfo, error) {
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
func (a *StreamServerAuthenticator) authenticateCert(ctx context.Context, certPEM, keyPEM []byte) (*user.DefaultInfo, error) {
	if a.baseConfig == nil {
		return nil, fmt.Errorf("baseConfig is required for client certificate authentication")
	}
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

func (a *StreamServerAuthenticator) getCachedUser(key string) (user.Info, bool) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	entry, ok := a.cache[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(a.cache, key)
		return nil, false
	}
	return entry.user, true
}

func (a *StreamServerAuthenticator) cacheUser(key string, u user.Info) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	// Opportunistically evict expired entries so that a client rotating
	// through many short-lived credentials over time does not grow the cache
	// unboundedly.
	now := time.Now()
	for k, e := range a.cache {
		if now.After(e.expiresAt) {
			delete(a.cache, k)
		}
	}
	a.cache[key] = credentialCacheEntry{user: u, expiresAt: now.Add(credentialCacheTTL)}
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

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
	"k8s.io/klog/v2"
)

const (
	// tokenCacheTTL bounds how long a successful TokenReview outcome is cached
	// before the token is re-validated against the Kubernetes API server. This
	// keeps a long-lived or frequently reconnecting client from generating a
	// TokenReview call on every request while still picking up token
	// invalidation (e.g. ServiceAccount deletion) within a bounded time.
	tokenCacheTTL = 30 * time.Second

	// authorizationMetadataKey is the gRPC metadata key clients must set to
	// carry their bearer token, mirroring the HTTP Authorization header.
	// gRPC metadata keys are matched case-insensitively.
	authorizationMetadataKey = "authorization"
	// bearerTokenPrefix precedes the token in the authorization metadata
	// value, e.g. "Bearer <token>" (RFC 6750).
	bearerTokenPrefix = "Bearer "
)

// tokenCacheEntry is a cached TokenReview outcome for a bearer token.
type tokenCacheEntry struct {
	user      user.Info
	expiresAt time.Time
}

// StreamServerAuthenticator is a gRPC stream server interceptor that
// authenticates FlowStreamService clients using a Kubernetes bearer token
// carried in the "authorization" gRPC metadata header, validated via the
// TokenReview API. The resolved identity is attached to the stream context
// via request.WithUser and can be read back with request.UserFrom by
// authorization logic.
type StreamServerAuthenticator struct {
	k8sClient kubernetes.Interface

	cacheMutex sync.Mutex
	cache      map[string]tokenCacheEntry
}

// NewStreamServerAuthenticator creates a StreamServerAuthenticator that
// validates bearer tokens against the Kubernetes API server via k8sClient.
func NewStreamServerAuthenticator(k8sClient kubernetes.Interface) *StreamServerAuthenticator {
	return &StreamServerAuthenticator{
		k8sClient: k8sClient,
		cache:     make(map[string]tokenCacheEntry),
	}
}

// StreamInterceptor implements grpc.StreamServerInterceptor. It rejects the
// call with codes.Unauthenticated if the request does not carry a valid
// bearer token; otherwise it attaches the resolved identity to the stream
// context before invoking handler.
func (a *StreamServerAuthenticator) StreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	token, err := tokenFromContext(ss.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	u, err := a.authenticate(ss.Context(), token)
	if err != nil {
		klog.ErrorS(err, "FlowStreamService client authentication failed")
		return status.Error(codes.Unauthenticated, "invalid bearer token")
	}

	return handler(srv, &authenticatedServerStream{
		ServerStream: ss,
		ctx:          request.WithUser(ss.Context(), u),
	})
}

// tokenFromContext extracts the bearer token from the authorization gRPC
// metadata header of an incoming stream.
func tokenFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("missing gRPC metadata")
	}
	values := md.Get(authorizationMetadataKey)
	if len(values) == 0 {
		return "", fmt.Errorf("missing authorization header")
	}
	token, ok := strings.CutPrefix(values[0], bearerTokenPrefix)
	if !ok || token == "" {
		return "", fmt.Errorf("authorization header must be a bearer token")
	}
	return token, nil
}

// authenticate resolves token to an identity, returning a cached TokenReview
// outcome when available.
func (a *StreamServerAuthenticator) authenticate(ctx context.Context, token string) (user.Info, error) {
	if u, ok := a.getCachedUser(token); ok {
		return u, nil
	}

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

	u := &user.DefaultInfo{
		Name:   review.Status.User.Username,
		UID:    review.Status.User.UID,
		Groups: review.Status.User.Groups,
		Extra:  convertExtra(review.Status.User.Extra),
	}
	a.cacheUser(token, u)
	return u, nil
}

// convertExtra converts the Extra field of a TokenReview's UserInfo
// (map[string]authenticationv1.ExtraValue) into the plain map[string][]string
// expected by user.DefaultInfo.Extra. authenticationv1.ExtraValue is defined
// as `type ExtraValue []string`, so each value assigns to []string without a
// cast; it is the outer map type that differs and must be rebuilt key by key.
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

func (a *StreamServerAuthenticator) getCachedUser(token string) (user.Info, bool) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	entry, ok := a.cache[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(a.cache, token)
		return nil, false
	}
	return entry.user, true
}

func (a *StreamServerAuthenticator) cacheUser(token string, u user.Info) {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	// Opportunistically evict expired entries so that a client rotating
	// through many short-lived tokens over time does not grow the cache
	// unboundedly.
	now := time.Now()
	for t, e := range a.cache {
		if now.After(e.expiresAt) {
			delete(a.cache, t)
		}
	}
	a.cache[token] = tokenCacheEntry{user: u, expiresAt: now.Add(tokenCacheTTL)}
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

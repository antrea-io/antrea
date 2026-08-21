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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
)

// authReactor installs a "create TokenReviews" Reactor on the fake clientset
// that returns status for the given token, so tests can control the outcome
// of TokenReview without a real API server.
func authReactor(client *k8sfake.Clientset, valid map[string]authenticationv1.TokenReviewStatus) {
	client.PrependReactor("create", "tokenreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		tr := action.(clienttesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		status, ok := valid[tr.Spec.Token]
		if !ok {
			status = authenticationv1.TokenReviewStatus{Authenticated: false}
		}
		tr = tr.DeepCopy()
		tr.Status = status
		return true, tr, nil
	})
}

// withFakeSelfSubjectReviewClient overrides newKubernetesClientForConfig for
// the duration of the test so that authenticateCert's SelfSubjectReview call
// hits client instead of trying to build a real TLS-terminating clientset.
// Every rest.Config passed to the override is recorded, so tests can assert
// on how the ephemeral, per-request config was constructed (e.g. that it
// carries the client cert but not flow-aggregator's own credentials).
func withFakeSelfSubjectReviewClient(t *testing.T, client kubernetes.Interface) *[]*rest.Config {
	t.Helper()
	var gotConfigs []*rest.Config
	orig := newKubernetesClientForConfig
	newKubernetesClientForConfig = func(cfg *rest.Config) (kubernetes.Interface, error) {
		gotConfigs = append(gotConfigs, cfg)
		return client, nil
	}
	t.Cleanup(func() { newKubernetesClientForConfig = orig })
	return &gotConfigs
}

// selfSubjectReviewReactor installs a "create selfsubjectreviews" reactor on
// the fake clientset that returns either reviewErr (if non-nil) or a
// SelfSubjectReview with the given user info.
func selfSubjectReviewReactor(client *k8sfake.Clientset, userInfo authenticationv1.UserInfo, reviewErr error) {
	client.PrependReactor("create", "selfsubjectreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if reviewErr != nil {
			return true, nil, reviewErr
		}
		return true, &authenticationv1.SelfSubjectReview{
			Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: userInfo},
		}, nil
	})
}

// fakeServerStream is a minimal grpc.ServerStream backed by a fixed context,
// sufficient for exercising StreamInterceptor without a real connection.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func contextWithAuthHeader(value string) context.Context {
	if value == "" {
		return context.Background()
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", value))
}

// contextWithClientCert builds an incoming stream context carrying the given
// PEM cert/key under the client-cert-bin/client-key-bin metadata keys. An
// empty certPEM or keyPEM omits that key entirely, so tests can exercise the
// "only one of the pair present" error path. Note this bypasses the
// "-bin"-suffix base64 framing that grpc-go applies at the real transport
// layer: incoming metadata is constructed in-process here, exactly like
// contextWithAuthHeader does for the bearer-token path.
func contextWithClientCert(certPEM, keyPEM string) context.Context {
	var pairs []string
	if certPEM != "" {
		pairs = append(pairs, clientCertMetadataKey, certPEM)
	}
	if keyPEM != "" {
		pairs = append(pairs, clientKeyMetadataKey, keyPEM)
	}
	if len(pairs) == 0 {
		return context.Background()
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func TestStreamInterceptor_MissingToken(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_MalformedAuthHeader(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handler := func(srv any, stream grpc.ServerStream) error { return nil }

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Basic abc123")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestStreamInterceptor_InvalidToken(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, nil)
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer bad-token")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_TokenReviewError(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		tr := action.(clienttesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		tr = tr.DeepCopy()
		tr.Status = authenticationv1.TokenReviewStatus{Authenticated: true, Error: "webhook unavailable"}
		return true, tr, nil
	})
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handler := func(srv any, stream grpc.ServerStream) error { return nil }
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer some-token")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestStreamInterceptor_ValidToken(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: "alice",
				UID:      "uid-1",
				Groups:   []string{"developers", "system:authenticated"},
				Extra: map[string]authenticationv1.ExtraValue{
					"scopes": {"read", "write"},
				},
			},
		},
	})
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	var gotUser user.Info
	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		u, ok := request.UserFrom(stream.Context())
		require.True(t, ok)
		gotUser = u
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer good-token")}, &grpc.StreamServerInfo{}, handler)
	require.NoError(t, err)
	require.True(t, handlerCalled)

	assert.Equal(t, "alice", gotUser.GetName())
	assert.Equal(t, "uid-1", gotUser.GetUID())
	assert.ElementsMatch(t, []string{"developers", "system:authenticated"}, gotUser.GetGroups())
	assert.Equal(t, []string{"read", "write"}, gotUser.GetExtra()["scopes"])
}

func TestStreamInterceptor_MissingClientCredentials(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handler := func(srv any, stream grpc.ServerStream) error { return nil }

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithClientCert("cert-pem-data", "")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestStreamInterceptor_SelfSubjectReviewError(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	selfSubjectReviewReactor(fakeClient, authenticationv1.UserInfo{}, fmt.Errorf("cert verification failed"))
	withFakeSelfSubjectReviewClient(t, fakeClient)

	a := NewStreamServerAuthenticator(k8sfake.NewSimpleClientset(), &rest.Config{})

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithClientCert("cert-pem-data", "key-pem-data")}, &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_ValidClientCert(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	selfSubjectReviewReactor(fakeClient, authenticationv1.UserInfo{
		Username: "admin@test.com",
		UID:      "uid-2",
		Groups:   []string{"admins"},
	}, nil)

	// baseConfig simulates flow-aggregator's own in-cluster rest.Config,
	// complete with its own ServiceAccount bearer token, so the test can
	// confirm authenticateCert never forwards that token in the ephemeral,
	// per-request config it builds for SelfSubjectReview.
	baseConfig := &rest.Config{ //nolint:gosec // test-only, not a real credential
		Host:        "https://kube-apiserver.example",
		BearerToken: "flow-aggregator-sa-token",
	}
	gotConfigs := withFakeSelfSubjectReviewClient(t, fakeClient)

	a := NewStreamServerAuthenticator(k8sfake.NewSimpleClientset(), baseConfig)

	var gotUser user.Info
	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		u, ok := request.UserFrom(stream.Context())
		require.True(t, ok)
		gotUser = u
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithClientCert("cert-pem-data", "key-pem-data")}, &grpc.StreamServerInfo{}, handler)
	require.NoError(t, err)
	require.True(t, handlerCalled)

	assert.Equal(t, "admin@test.com", gotUser.GetName())
	assert.Equal(t, "uid-2", gotUser.GetUID())
	assert.ElementsMatch(t, []string{"admins"}, gotUser.GetGroups())

	require.Len(t, *gotConfigs, 1)
	usedConfig := (*gotConfigs)[0]
	// The ephemeral config used for SelfSubjectReview must not carry
	// flow-aggregator's own ServiceAccount bearer token, or an
	// expired/invalid end-user cert would silently fall back to
	// authenticating as flow-aggregator's own ServiceAccount instead of
	// failing closed.
	assert.Empty(t, usedConfig.BearerToken)
	assert.Equal(t, "https://kube-apiserver.example", usedConfig.Host)
	assert.Equal(t, []byte("cert-pem-data"), usedConfig.TLSClientConfig.CertData)
	assert.Equal(t, []byte("key-pem-data"), usedConfig.TLSClientConfig.KeyData)
}

// TestStreamInterceptor_ClientCertAuthenticationIsBounded covers the cap on concurrent
// client-certificate authentications. That path is reachable by any peer that can connect, and each
// distinct cert/key pair costs a transport and a TLS handshake to kube-apiserver of its own, so it
// must not fan out without limit.
func TestStreamInterceptor_ClientCertAuthenticationIsBounded(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	selfSubjectReviewReactor(fakeClient, authenticationv1.UserInfo{Username: "admin@test.com"}, nil)
	withFakeSelfSubjectReviewClient(t, fakeClient)

	a := NewStreamServerAuthenticator(k8sfake.NewSimpleClientset(), &rest.Config{})

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	newStream := func() *fakeServerStream {
		return &fakeServerStream{ctx: contextWithClientCert("cert-pem-data", "key-pem-data")}
	}

	// Hold every slot, as maxConcurrentCertAuthentications authentications already in flight would.
	for range maxConcurrentCertAuthentications {
		a.certAuthSlots <- struct{}{}
	}

	err := a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	// ResourceExhausted rather than Unauthenticated: the credential was never checked, so the client
	// should retry instead of concluding that it is invalid.
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.False(t, handlerCalled)

	// One slot freed is enough for the next credential to be checked, and that slot is released
	// again when the check returns rather than being held for the lifetime of the stream.
	<-a.certAuthSlots
	require.NoError(t, a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler))
	assert.True(t, handlerCalled)
	assert.Len(t, a.certAuthSlots, maxConcurrentCertAuthentications-1)
}

// TestStreamInterceptor_BearerTokenIsNotBoundedByCertSlots pins down that the cert cap does not
// apply to the token path: the token path goes through the Flow Aggregator's own shared client and
// has its own, independent bound (see TestStreamInterceptor_TokenAuthenticationIsBounded), so it
// must keep working while every client-certificate slot is held.
func TestStreamInterceptor_BearerTokenIsNotBoundedByCertSlots(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, map[string]authenticationv1.TokenReviewStatus{
		"valid-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "user@test.com"}},
	})

	a := NewStreamServerAuthenticator(client, &rest.Config{})
	for range maxConcurrentCertAuthentications {
		a.certAuthSlots <- struct{}{}
	}

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer valid-token")}, &grpc.StreamServerInfo{}, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

// TestStreamInterceptor_TokenAuthenticationIsBounded covers the cap on concurrent bearer-token
// authentications. StreamInterceptor runs once per stream before the credential is validated, and
// an in-cluster rest.Config installs no client-side rate limiter, so this path must not fan out
// without limit either, even though it reuses one shared client rather than building one per
// credential.
func TestStreamInterceptor_TokenAuthenticationIsBounded(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, map[string]authenticationv1.TokenReviewStatus{
		"valid-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "user@test.com"}},
	})

	a := NewStreamServerAuthenticator(client, &rest.Config{})

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	newStream := func() *fakeServerStream {
		return &fakeServerStream{ctx: contextWithAuthHeader("Bearer valid-token")}
	}

	// Hold every slot, as maxConcurrentTokenAuthentications authentications already in flight would.
	for range maxConcurrentTokenAuthentications {
		a.tokenAuthSlots <- struct{}{}
	}

	err := a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.False(t, handlerCalled)

	<-a.tokenAuthSlots
	require.NoError(t, a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler))
	assert.True(t, handlerCalled)
	assert.Len(t, a.tokenAuthSlots, maxConcurrentTokenAuthentications-1)
}

// TestStreamInterceptor_ClientCertIsNotBoundedByTokenSlots is the mirror image of
// TestStreamInterceptor_BearerTokenIsNotBoundedByCertSlots: the two bounds are independent
// semaphores, so saturating one path must not block the other.
func TestStreamInterceptor_ClientCertIsNotBoundedByTokenSlots(t *testing.T) {
	fakeClient := k8sfake.NewSimpleClientset()
	selfSubjectReviewReactor(fakeClient, authenticationv1.UserInfo{Username: "admin@test.com"}, nil)
	withFakeSelfSubjectReviewClient(t, fakeClient)

	a := NewStreamServerAuthenticator(k8sfake.NewSimpleClientset(), &rest.Config{})
	for range maxConcurrentTokenAuthentications {
		a.tokenAuthSlots <- struct{}{}
	}

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithClientCert("cert-pem-data", "key-pem-data")}, &grpc.StreamServerInfo{}, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

// TestStreamInterceptor_BearerSchemeIsCaseInsensitive covers RFC 7235's requirement that the
// auth-scheme token be matched case-insensitively. Kubernetes' own bearertoken authenticator
// lowercases before comparing, so a client sending "bearer <token>" or "BEARER <token>" must be
// accepted here too, not just by whatever authenticator eventually validates the token.
func TestStreamInterceptor_BearerSchemeIsCaseInsensitive(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	a := NewStreamServerAuthenticator(client, &rest.Config{})

	for _, scheme := range []string{"bearer", "Bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			handlerCalled := false
			handler := func(srv any, stream grpc.ServerStream) error {
				handlerCalled = true
				return nil
			}
			err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader(scheme + " good-token")}, &grpc.StreamServerInfo{}, handler)
			require.NoError(t, err)
			assert.True(t, handlerCalled)
		})
	}
}

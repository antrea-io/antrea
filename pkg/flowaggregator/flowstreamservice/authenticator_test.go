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
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// authReactor installs a "create tokenreviews" reactor on the fake clientset
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

func TestStreamInterceptor_MissingToken(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	a := NewStreamServerAuthenticator(client)

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
	a := NewStreamServerAuthenticator(client)

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
	a := NewStreamServerAuthenticator(client)

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
	a := NewStreamServerAuthenticator(client)

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
	a := NewStreamServerAuthenticator(client)

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

func TestStreamInterceptor_TokenReviewCached(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	authReactor(client, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	callCount := 0
	client.PrependReactor("create", "tokenreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
		callCount++
		return false, nil, nil
	})
	a := NewStreamServerAuthenticator(client)

	handler := func(srv any, stream grpc.ServerStream) error { return nil }
	for range 3 {
		err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer good-token")}, &grpc.StreamServerInfo{}, handler)
		require.NoError(t, err)
	}
	// callCount only increments when TokenReviews().Create() is actually
	// invoked; a cache hit skips the call to the fake clientset entirely.
	assert.Equal(t, 1, callCount)
}

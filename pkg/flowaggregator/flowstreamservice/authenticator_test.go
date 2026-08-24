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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

// newTokenReviewClient returns an AuthenticationV1 client that answers TokenReview creates from
// valid, defaulting to "not authenticated" for any token that is not a key of it.
//
// This is served over real HTTP rather than through a fake clientset reactor because the delegating
// authenticator's TokenReview goes through the typed client's RESTClient(), which a fake clientset
// does not provide. Serving it means the token also makes a real round trip through the API
// machinery's serialization, which a reactor would have skipped.
func newTokenReviewClient(t *testing.T, valid map[string]authenticationv1.TokenReviewStatus) authenticationv1client.AuthenticationV1Interface {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review authenticationv1.TokenReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		status, ok := valid[review.Spec.Token]
		if !ok {
			status = authenticationv1.TokenReviewStatus{Authenticated: false}
		}
		// The TypeMeta is set explicitly: the client decodes the body into a typed object and rejects
		// a response that does not say what kind it is.
		review.TypeMeta = metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
		review.Status = status
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&review); err != nil {
			t.Errorf("failed to encode TokenReview response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)
	return client.AuthenticationV1()
}

// testCA is a self-signed certificate authority standing in for the cluster's client CA, i.e. the
// signer whose bundle kube-apiserver publishes in the extension-apiserver-authentication ConfigMap.
type testCA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-client-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

// signClientCert issues a client certificate carrying an identity the way kube-apiserver (and
// Pinniped Concierge, whose TokenCredentialRequest returns exactly this shape) encodes one: the
// Subject's CommonName is the user name and each Organization is a group.
func (ca *testCA) signClientCert(t *testing.T, commonName string, groups []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName, Organization: groups},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// validClientCert issues a currently-valid client certificate for the given identity.
func (ca *testCA) validClientCert(t *testing.T, commonName string, groups []string) *x509.Certificate {
	t.Helper()
	return ca.signClientCert(t, commonName, groups, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
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

// contextWithClientCert builds an incoming stream context that looks like a gRPC connection whose
// TLS handshake presented cert. This is how a client certificate reaches the authenticator: it is
// the credential of the connection, so only the certificate is available here and the client's
// private key never crosses the wire at all.
func contextWithClientCert(ctx context.Context, cert *x509.Certificate) context.Context {
	return peer.NewContext(ctx, &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
}

// newTestAuthenticator returns an authenticator that answers TokenReview from tokens and whose client
// CA bundle is never loaded, so only the bearer-token path can resolve an identity.
func newTestAuthenticator(t *testing.T, tokens map[string]authenticationv1.TokenReviewStatus) *StreamServerAuthenticator {
	t.Helper()
	a, err := newStreamServerAuthenticator(k8sfake.NewSimpleClientset(), newTokenReviewClient(t, tokens))
	require.NoError(t, err)
	return a
}

// newAuthenticatorWithClientCA returns an authenticator that has loaded caPEM as its client CA bundle
// from the ConfigMap kube-apiserver publishes it in, and has confirmed the bundle is in place before
// returning, so client certificate tests do not race the informer that reads it. TokenReview is
// answered from tokens, as in newTestAuthenticator.
func newAuthenticatorWithClientCA(t *testing.T, caPEM []byte, tokens map[string]authenticationv1.TokenReviewStatus) *StreamServerAuthenticator {
	t.Helper()
	k8sClient := k8sfake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: clientCAConfigMapNamespace, Name: clientCAConfigMapName},
		Data:       map[string]string{clientCAConfigMapKey: string(caPEM)},
	})
	a, err := newStreamServerAuthenticator(k8sClient, newTokenReviewClient(t, tokens))
	require.NoError(t, err)

	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })
	go a.Run(stopCh)
	require.Eventually(t, func() bool {
		_, ok := a.clientCAProvider.VerifyOptions()
		return ok
	}, 10*time.Second, 10*time.Millisecond, "client CA bundle was never loaded")
	return a
}

func recordingHandler(called *bool, gotUser *user.Info) grpc.StreamHandler {
	return func(srv any, stream grpc.ServerStream) error {
		*called = true
		if gotUser != nil {
			u, ok := request.UserFrom(stream.Context())
			if !ok {
				return status.Error(codes.Internal, "no user attached to the stream context")
			}
			*gotUser = u
		}
		return nil
	}
}

func requireCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, code, st.Code())
}

// TestStreamInterceptor_MissingCredentials covers a client that presents nothing at all: no
// authorization metadata and no client certificate. It must be rejected rather than admitted as the
// anonymous user, which is what would happen if the delegating authenticator were built with
// anonymous authentication enabled. Unlike an API server, this interceptor has no authorization step
// behind it to reject system:anonymous afterwards.
func TestStreamInterceptor_MissingCredentials(t *testing.T) {
	a := newTestAuthenticator(t, nil)

	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_MalformedAuthHeader(t *testing.T) {
	a := newTestAuthenticator(t, nil)

	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Basic abc123")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_InvalidToken(t *testing.T) {
	a := newTestAuthenticator(t, nil)

	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer bad-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestStreamInterceptor_TokenReviewError covers a TokenReview that declines the token and explains
// why, as it does when the authentication webhook behind kube-apiserver is unreachable. The
// explanation reaches the authenticator's log; the client is told only that its credentials were
// rejected.
func TestStreamInterceptor_TokenReviewError(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"some-token": {Authenticated: false, Error: "webhook unavailable"},
	})

	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer some-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestStreamInterceptor_TokenReviewWithoutUsername covers a TokenReview that reports success but no
// user name. kube-apiserver does not produce that, but an authentication webhook behind it could,
// and the resulting unnamed identity would still carry the system:authenticated group.
func TestStreamInterceptor_TokenReviewWithoutUsername(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"nameless-token": {Authenticated: true, User: authenticationv1.UserInfo{Groups: []string{"developers"}}},
	})

	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer nameless-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_ValidToken(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
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

	var gotUser user.Info
	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer good-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, &gotUser))
	require.NoError(t, err)
	require.True(t, handlerCalled)

	assert.Equal(t, "alice", gotUser.GetName())
	assert.Equal(t, "uid-1", gotUser.GetUID())
	assert.ElementsMatch(t, []string{"developers", "system:authenticated"}, gotUser.GetGroups())
	assert.Equal(t, []string{"read", "write"}, gotUser.GetExtra()["scopes"])
}

// TestStreamInterceptor_BearerSchemeIsCaseInsensitive covers RFC 7235's requirement that the
// auth-scheme token be matched case-insensitively. Kubernetes' bearertoken authenticator, which is
// what parses the header here, lowercases the scheme before comparing, so a client sending
// "bearer <token>" or "BEARER <token>" is accepted.
func TestStreamInterceptor_BearerSchemeIsCaseInsensitive(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})

	for _, scheme := range []string{"bearer", "Bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			handlerCalled := false
			err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader(scheme + " good-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
			require.NoError(t, err)
			assert.True(t, handlerCalled)
		})
	}
}

// TestStreamInterceptor_TokenAuthenticationIsBounded covers the cap on concurrent authentications
// that may reach kube-apiserver. The interceptors run once per RPC before the credential is
// validated, and an in-cluster rest.Config installs no client-side rate limiter, so this path must
// not fan out without limit.
func TestStreamInterceptor_TokenAuthenticationIsBounded(t *testing.T) {
	a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
		"valid-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "user@test.com"}},
	})

	handlerCalled := false
	handler := recordingHandler(&handlerCalled, nil)
	newStream := func() *fakeServerStream {
		return &fakeServerStream{ctx: contextWithAuthHeader("Bearer valid-token")}
	}

	// Hold every slot, as maxConcurrentTokenAuthentications authentications already in flight would.
	for range maxConcurrentTokenAuthentications {
		a.tokenAuthSlots <- struct{}{}
	}

	err := a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler)
	// ResourceExhausted rather than Unauthenticated: the credential was never checked, so the client
	// should retry instead of concluding that it is invalid.
	requireCode(t, err, codes.ResourceExhausted)
	assert.False(t, handlerCalled)

	// One slot freed is enough for the next credential to be checked, and that slot is released
	// again when the check returns rather than being held for the lifetime of the stream.
	<-a.tokenAuthSlots
	require.NoError(t, a.StreamInterceptor(nil, newStream(), &grpc.StreamServerInfo{}, handler))
	assert.True(t, handlerCalled)
	assert.Len(t, a.tokenAuthSlots, maxConcurrentTokenAuthentications-1)
}

// TestStreamInterceptor_ValidClientCert covers the client certificate path: a certificate signed by
// the cluster's client CA resolves to the identity it carries, without any call to kube-apiserver.
func TestStreamInterceptor_ValidClientCert(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, nil)
	cert := ca.validClientCert(t, "admin@test.com", []string{"admins", "viewers"})

	var gotUser user.Info
	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, &gotUser))
	require.NoError(t, err)
	require.True(t, handlerCalled)

	assert.Equal(t, "admin@test.com", gotUser.GetName())
	// The Subject's Organization entries become groups, and system:authenticated is added so that
	// both credential kinds report a consistent group list.
	assert.ElementsMatch(t, []string{"admins", "viewers", user.AllAuthenticated}, gotUser.GetGroups())
}

// TestStreamInterceptor_ClientCertFromUntrustedCA covers a syntactically valid certificate that was
// not signed by the cluster's client CA. Verification is local, so this is rejected without asking
// kube-apiserver anything.
func TestStreamInterceptor_ClientCertFromUntrustedCA(t *testing.T) {
	trustedCA := newTestCA(t)
	otherCA := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, trustedCA.certPEM, nil)
	cert := otherCA.validClientCert(t, "attacker@test.com", []string{"system:masters"})

	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

func TestStreamInterceptor_ExpiredClientCert(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, nil)
	cert := ca.signClientCert(t, "admin@test.com", []string{"admins"}, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))

	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestStreamInterceptor_ClientCertWithoutCABundle covers the window before the client CA bundle has
// been loaded, and clusters whose kube-apiserver never publishes one. With no trust bundle the
// certificate path must fail closed rather than accept an unverified certificate.
func TestStreamInterceptor_ClientCertWithoutCABundle(t *testing.T) {
	ca := newTestCA(t)
	// The authenticator is never Run, so its client CA provider holds no bundle.
	a := newTestAuthenticator(t, nil)
	_, ok := a.clientCAProvider.VerifyOptions()
	require.False(t, ok, "expected no client CA bundle to be loaded")

	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), ca.validClientCert(t, "admin@test.com", nil))
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestStreamInterceptor_ClientCertTakesPrecedenceOverBearerToken pins down which credential wins when
// a call carries both. The delegating authenticator tries the certificate first, so the certificate
// identifies the client and the token is never reviewed — the same precedence kube-apiserver applies
// to a request that arrives with both.
func TestStreamInterceptor_ClientCertTakesPrecedenceOverBearerToken(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	cert := ca.validClientCert(t, "admin@test.com", []string{"admins"})

	var gotUser user.Info
	handlerCalled := false
	ctx := contextWithClientCert(contextWithAuthHeader("Bearer good-token"), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, &gotUser))
	require.NoError(t, err)
	require.True(t, handlerCalled)
	assert.Equal(t, "admin@test.com", gotUser.GetName())
}

// TestStreamInterceptor_UnverifiableClientCertFallsBackToBearerToken covers the case that makes the
// precedence above safe: a certificate that does not chain to the cluster's client CA is not an
// identity, so it does not shadow the token the call also carries. This is the shape a client whose
// gRPC channel presents a certificate for an unrelated reason arrives in — antrea-ui, for one,
// configures a static client certificate signed by the Flow Aggregator's own CA, not the cluster's,
// and a Go client offers it whether or not the current session's credential is a certificate.
func TestStreamInterceptor_UnverifiableClientCertFallsBackToBearerToken(t *testing.T) {
	clusterCA := newTestCA(t)
	unrelatedCA := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, clusterCA.certPEM, map[string]authenticationv1.TokenReviewStatus{
		"good-token": {Authenticated: true, User: authenticationv1.UserInfo{Username: "alice"}},
	})
	cert := unrelatedCA.validClientCert(t, "not-a-cluster-identity", nil)

	var gotUser user.Info
	handlerCalled := false
	ctx := contextWithClientCert(contextWithAuthHeader("Bearer good-token"), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, &gotUser))
	require.NoError(t, err)
	require.True(t, handlerCalled)
	assert.Equal(t, "alice", gotUser.GetName())
}

// TestStreamInterceptor_ClientCertIsNotBoundedByTokenSlots covers that the concurrency bound does not
// apply to a call whose only credential is a certificate: that path is verified locally against the
// cached CA bundle and never calls kube-apiserver, so there is nothing for it to bound.
func TestStreamInterceptor_ClientCertIsNotBoundedByTokenSlots(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, nil)
	for range maxConcurrentTokenAuthentications {
		a.tokenAuthSlots <- struct{}{}
	}

	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), ca.validClientCert(t, "admin@test.com", nil))
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

// TestStreamInterceptor_CertificateMetadataIsIgnored pins down that a certificate and private key
// carried as gRPC metadata are no longer a credential. A client's private key must never be sent to
// the Flow Aggregator: anything able to read the Flow Aggregator's memory could then impersonate
// that user against kube-apiserver with their full privileges until the certificate expired.
func TestStreamInterceptor_CertificateMetadataIsIgnored(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, nil)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"client-cert-bin", string(ca.certPEM),
		"client-key-bin", "any-private-key",
	))
	handlerCalled := false
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestStreamInterceptor_AnonymousTokenIdentityIsRejected covers a TokenReview that reports success
// but resolves to the anonymous user. kube-apiserver does not do this for a bearer token, but an
// authentication webhook behind it could, and the resulting identity would otherwise be admitted as
// an authenticated client and matched against authorization policy by name.
func TestStreamInterceptor_AnonymousTokenIdentityIsRejected(t *testing.T) {
	tests := []struct {
		name     string
		userInfo authenticationv1.UserInfo
	}{
		{
			name:     "anonymous user name",
			userInfo: authenticationv1.UserInfo{Username: user.Anonymous},
		},
		{
			name:     "unauthenticated group",
			userInfo: authenticationv1.UserInfo{Username: "alice", Groups: []string{user.AllUnauthenticated}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAuthenticator(t, map[string]authenticationv1.TokenReviewStatus{
				"anon-token": {Authenticated: true, User: tc.userInfo},
			})

			handlerCalled := false
			err := a.StreamInterceptor(nil, &fakeServerStream{ctx: contextWithAuthHeader("Bearer anon-token")}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
			requireCode(t, err, codes.Unauthenticated)
			assert.False(t, handlerCalled)
		})
	}
}

// TestStreamInterceptor_AnonymousClientCertIsRejected covers the same guard on the certificate path:
// a certificate signed by the cluster's client CA whose Subject CommonName is literally
// "system:anonymous" would otherwise resolve to the anonymous user.
func TestStreamInterceptor_AnonymousClientCertIsRejected(t *testing.T) {
	ca := newTestCA(t)
	a := newAuthenticatorWithClientCA(t, ca.certPEM, nil)
	cert := ca.validClientCert(t, user.Anonymous, nil)

	handlerCalled := false
	ctx := contextWithClientCert(context.Background(), cert)
	err := a.StreamInterceptor(nil, &fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, recordingHandler(&handlerCalled, nil))
	requireCode(t, err, codes.Unauthenticated)
	assert.False(t, handlerCalled)
}

// TestRejectUnaryRPC covers the unary interceptor the server installs. FlowStreamService authenticates
// clients in a stream interceptor, so a unary method would otherwise be served with no credential
// check; this refuses it instead, including when the call carries a credential that would have
// authenticated fine, since the point is that no unary RPC has been designed to be served at all.
func TestRejectUnaryRPC(t *testing.T) {
	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "response", nil
	}

	for _, ctx := range []context.Context{
		context.Background(),
		contextWithAuthHeader("Bearer good-token"),
	} {
		resp, err := rejectUnaryRPC(ctx, "request", &grpc.UnaryServerInfo{FullMethod: "/Svc/DoThing"}, handler)
		requireCode(t, err, codes.Unauthenticated)
		assert.Nil(t, resp)
		assert.False(t, handlerCalled)
	}
}

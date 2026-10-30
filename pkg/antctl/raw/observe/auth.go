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

package observe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc/metadata"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// authorizationMetadataKey must match the gRPC metadata key FlowStreamService's
// StreamServerAuthenticator reads a bearer token from, in
// pkg/flowaggregator/flowstreamservice/authenticator.go.
const (
	authorizationMetadataKey = "authorization"
	bearerTokenPrefix        = "Bearer "
)

// flowAggregatorCredential is the identity observe presents to FlowStreamService. FlowStreamService
// accepts two kinds of credential, and both fields are set when both are configured:
//   - a bearer token, carried as "authorization" gRPC metadata and validated by the server with a
//     TokenReview;
//   - a client certificate, presented as the TLS client certificate of the gRPC connection and
//     verified by the server against the cluster's client CA bundle. It is deliberately not sent as
//     metadata: the server never reads a certificate from metadata.
//
// When both are present, the server tries the certificate first, then the token, matching Kubernetes.
type flowAggregatorCredential struct {
	// metadata carries the bearer token, and is nil when no bearer token is configured.
	metadata metadata.MD
	// getClientCertificate supplies the client certificate during the TLS handshake, and is nil
	// when no client certificate is configured.
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// credentialForFlowAggregator derives the credential observe presents to FlowStreamService, by
// reusing the credential the caller's own kubeconfig already resolves to for talking to the
// Kubernetes API server, rather than minting a new one. This deliberately forwards the caller's
// own identity end to end, so the server resolves who they really are — the opposite choice from
// pkg/antctl/raw/token.go's ServiceAccountTokenSource, which exists specifically to avoid
// forwarding a caller's real credentials to an Agent. Here, forwarding the caller's real identity
// is the point.
//
// Only a static bearer token (inline or from a file) and a static client certificate (inline or
// from files) are covered by e2e tests, and therefore supported. Any other kind of credential
// reaches the best-effort branch at the end, which is not tested end to end.
func credentialForFlowAggregator(ctx context.Context, cfg *rest.Config) (*flowAggregatorCredential, error) {
	cred := &flowAggregatorCredential{}
	switch {
	case cfg.BearerToken != "":
		cred = bearerCredential(cfg.BearerToken)
	case cfg.BearerTokenFile != "":
		tok, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token file %s: %w", cfg.BearerTokenFile, err)
		}
		cred = bearerCredential(string(tok))
	}
	if len(cfg.CertData) > 0 || cfg.CertFile != "" {
		getClientCertificate, err := clientCertificateCallback(cfg)
		if err != nil {
			return nil, err
		}
		cred.getClientCertificate = getClientCertificate
	}
	if cred.metadata != nil || cred.getClientCertificate != nil {
		return cred, nil
	}
	// NOT SUPPORTED, NOT TESTED END TO END: there is no static credential to read directly off
	// cfg (for example an exec plugin, or an auth provider). As a best effort, build the same
	// transport client-go would use for a real API server call, and capture the bearer token it
	// attaches to one lightweight authenticated request. Only a bearer token can be captured:
	// a client certificate supplied by a plugin cannot, and fails here. No e2e test configures
	// such a kubeconfig, so do not document this branch as supported until one does.
	token, err := capturedBearerToken(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a bearer token from the configured kubeconfig credential: %w", err)
	}
	return bearerCredential(token), nil
}

func bearerCredential(token string) *flowAggregatorCredential {
	// client-go may already have populated BearerToken with the untrimmed contents of tokenFile.
	return &flowAggregatorCredential{metadata: metadata.Pairs(authorizationMetadataKey, bearerTokenPrefix+strings.TrimSpace(token))}
}

// clientCertificateCallback returns the callback that supplies the kubeconfig's client certificate
// during a TLS handshake. It is taken from client-go's own TLS configuration for cfg rather than
// parsed here, so that an inline certificate and a certificate file are loaded exactly as they are
// for a request to the API server.
func clientCertificateCallback(cfg *rest.Config) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	tlsConfig, err := rest.TLSConfigFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load the kubeconfig's client certificate: %w", err)
	}
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		return nil, fmt.Errorf("the kubeconfig does not provide a client certificate")
	}
	return tlsConfig.GetClientCertificate, nil
}

// tokenCapturingRoundTripper records the bearer token from the Authorization header of a request
// it sees, then forwards the request unmodified. It never sets or replays a header itself; it only
// observes what an outer, already-configured auth transport wrapper attached before the request
// reached this, the innermost transport. Only an Authorization header using the Bearer scheme is
// recorded: any other scheme (for example Basic) is not a bearer token, and forwarding it as one
// would hand the server a credential it cannot validate, and disclose the original to it.
type tokenCapturingRoundTripper struct {
	rt    http.RoundTripper
	mu    sync.Mutex
	token string
}

func (t *tokenCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, bearerTokenPrefix) {
		t.mu.Lock()
		t.token = strings.TrimPrefix(auth, bearerTokenPrefix)
		t.mu.Unlock()
	}
	return t.rt.RoundTrip(req)
}

// capturedBearerToken exercises the real transport built from cfg against the API server it
// points at, capturing the bearer token that client-go attaches. A SelfSubjectReview create is
// used as the "lightweight authenticated request": it is always permitted for any authenticated
// identity (via the built-in system:basic-user ClusterRole), has no side effects, and its response
// is irrelevant — only that the request was sent with a token attached. The error of the request
// is only reported when no token was captured, since it is then the likely reason.
func capturedBearerToken(ctx context.Context, cfg *rest.Config) (string, error) {
	capture := &tokenCapturingRoundTripper{}
	wrapped := rest.CopyConfig(cfg)
	wrapped.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		capture.rt = rt
		return capture
	}
	clientset, err := kubernetes.NewForConfig(wrapped)
	if err != nil {
		return "", err
	}
	_, reqErr := clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.token == "" {
		const unsupported = "no bearer token observed on an authenticated API server request; " +
			"only a bearer token or a client certificate in the kubeconfig is supported"
		if reqErr != nil {
			return "", fmt.Errorf("%s (the request failed with: %w)", unsupported, reqErr)
		}
		return "", errors.New(unsupported)
	}
	return capture.token, nil
}

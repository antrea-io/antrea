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

// authorizationMetadataKey, clientCertMetadataKey and clientKeyMetadataKey must match the gRPC
// metadata keys FlowStreamService's StreamServerAuthenticator reads, in
// pkg/flowaggregator/flowstreamservice/authenticator.go (PR #8191).
const (
	authorizationMetadataKey = "authorization"
	bearerTokenPrefix        = "Bearer "
	clientCertMetadataKey    = "client-cert-bin"
	clientKeyMetadataKey     = "client-key-bin"
)

// credentialForFlowAggregator derives the gRPC metadata observe presents to FlowStreamService, by
// reusing whatever credential the caller's own kubeconfig already resolves to for talking to the
// Kubernetes API server, rather than minting a new one. This deliberately forwards the caller's
// own identity end to end, so the server's TokenReview/SelfSubjectReview resolves who they really
// are — the opposite choice from pkg/antctl/raw/token.go's ServiceAccountTokenSource, which exists
// specifically to avoid forwarding a caller's real credentials to an Agent. Here, forwarding the
// caller's real identity is the point.
func credentialForFlowAggregator(ctx context.Context, cfg *rest.Config) (metadata.MD, error) {
	switch {
	case cfg.BearerToken != "":
		return metadata.Pairs(authorizationMetadataKey, bearerTokenPrefix+cfg.BearerToken), nil
	case cfg.BearerTokenFile != "":
		tok, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token file %s: %w", cfg.BearerTokenFile, err)
		}
		return metadata.Pairs(authorizationMetadataKey, bearerTokenPrefix+strings.TrimSpace(string(tok))), nil
	case len(cfg.CertData) > 0 || cfg.CertFile != "":
		certPEM, keyPEM, err := loadCertAndKey(cfg)
		if err != nil {
			return nil, err
		}
		return metadata.Pairs(clientCertMetadataKey, string(certPEM), clientKeyMetadataKey, string(keyPEM)), nil
	default:
		// NOTE: This code path at the moment is not exercised by any e2e test due to lack of test
		// harness lacking the ability of specifying exec-plugins for authentication
		// exec/auth-provider kubeconfig (OIDC via kubelogin, cloud IAM, etc.): there is no
		// static credential to read directly off cfg. Build the same transport client-go would
		// use for a real API server call, capture the Authorization header it attaches to one
		// lightweight authenticated request, and forward that token instead. This generalizes to
		// any auth mode client-go supports, without observe needing to special-case each one.
		token, err := capturedBearerToken(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain a bearer token from the configured kubeconfig credential: %w", err)
		}
		return metadata.Pairs(authorizationMetadataKey, bearerTokenPrefix+token), nil
	}
}

func loadCertAndKey(cfg *rest.Config) ([]byte, []byte, error) {
	certPEM := cfg.CertData
	if len(certPEM) == 0 {
		data, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read client certificate file %s: %w", cfg.CertFile, err)
		}
		certPEM = data
	}
	keyPEM := cfg.KeyData
	if len(keyPEM) == 0 {
		data, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read client key file %s: %w", cfg.KeyFile, err)
		}
		keyPEM = data
	}
	return certPEM, keyPEM, nil
}

// tokenCapturingRoundTripper records the bearer token from the Authorization header of the first
// request it sees, then forwards the request unmodified. It never sets or replays a header
// itself; it only observes what an outer, already-configured auth/exec transport wrapper attached
// before the request reached this, the innermost transport.
type tokenCapturingRoundTripper struct {
	rt    http.RoundTripper
	mu    sync.Mutex
	token string
}

func (t *tokenCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if auth := req.Header.Get("Authorization"); auth != "" {
		t.mu.Lock()
		t.token = strings.TrimPrefix(auth, bearerTokenPrefix)
		t.mu.Unlock()
	}
	return t.rt.RoundTrip(req)
}

// capturedBearerToken exercises the real transport built from cfg against the API server it
// points at, capturing whatever bearer token client-go's exec/auth-provider plugin attaches. A
// SelfSubjectReview create is used as the "lightweight authenticated request": it is always
// permitted for any authenticated identity (via the built-in system:basic-user ClusterRole), has
// no side effects, and its response is irrelevant — only that the request was sent with a token
// attached.
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
	_, _ = clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.token == "" {
		return "", fmt.Errorf("no bearer token observed on an authenticated API server request; the configured credential type is not supported")
	}
	return capture.token, nil
}

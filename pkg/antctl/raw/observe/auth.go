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
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/metadata"
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
// from files) are supported. Any other kind of credential, such as an exec plugin or an auth
// provider, is rejected rather than approximated: a token such as the OAuth access token of a
// cloud provider can be valid well beyond the cluster, and is not one observe should hand to the
// Flow Aggregator.
func credentialForFlowAggregator(cfg *rest.Config) (*flowAggregatorCredential, error) {
	cred := &flowAggregatorCredential{}
	if token, err := bearerTokenFor(cfg); err != nil {
		return nil, err
	} else if token != "" {
		cred = bearerCredential(token)
	}
	if len(cfg.CertData) > 0 || cfg.CertFile != "" {
		getClientCertificate, err := clientCertificateCallback(cfg)
		if err != nil {
			return nil, err
		}
		cred.getClientCertificate = getClientCertificate
	}
	if cred.metadata == nil && cred.getClientCertificate == nil {
		return nil, errors.New("the kubeconfig does not provide a static bearer token (token or tokenFile) " +
			"or a client certificate, which are the only supported ways of authenticating: " +
			"an exec plugin, an auth provider and basic authentication are not supported")
	}
	return cred, nil
}

// bearerTokenFor resolves the bearer token of cfg with the precedence client-go applies to requests
// to the API server (see transport.NewBearerAuthWithRefreshRoundTripper): the token file, read now
// so that a rotated token is honored, wins over BearerToken, which is only the fallback when the
// file cannot be read or is empty. When BearerTokenFile is set, clientcmd also copies the file's
// content at load time into BearerToken, so BearerToken alone may be stale. It returns an empty
// token when cfg has neither.
func bearerTokenFor(cfg *rest.Config) (string, error) {
	if cfg.BearerTokenFile == "" {
		return cfg.BearerToken, nil
	}
	tok, err := os.ReadFile(cfg.BearerTokenFile)
	if err == nil && strings.TrimSpace(string(tok)) == "" {
		err = errors.New("the file is empty")
	}
	if err != nil {
		if cfg.BearerToken != "" {
			return cfg.BearerToken, nil
		}
		return "", fmt.Errorf("failed to read bearer token file %s: %w", cfg.BearerTokenFile, err)
	}
	return string(tok), nil
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

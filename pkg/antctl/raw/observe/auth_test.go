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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// writeClientCert writes a self-signed client certificate and its key under dir, and returns the PEM
// encodings and the paths. The certificate does not need to chain to anything: nothing here verifies it.
func writeClientCert(t *testing.T, dir string) (certPEM, keyPEM []byte, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "observe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	return certPEM, keyPEM, certPath, keyPath
}

func TestCredentialForFlowAggregator_BearerToken(t *testing.T) {
	cred, err := credentialForFlowAggregator(context.Background(), &rest.Config{BearerToken: "tok-abc"})
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer tok-abc"}, cred.metadata.Get(authorizationMetadataKey))
	assert.Nil(t, cred.getClientCertificate)
}

func TestCredentialForFlowAggregator_BearerTokenFile(t *testing.T) {
	t.Run("valid file, whitespace is trimmed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("tok-from-file\n"), 0o600))
		cred, err := credentialForFlowAggregator(context.Background(), &rest.Config{BearerTokenFile: path})
		require.NoError(t, err)
		assert.Equal(t, []string{"Bearer tok-from-file"}, cred.metadata.Get(authorizationMetadataKey))
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{BearerTokenFile: filepath.Join(t.TempDir(), "missing")})
		require.Error(t, err)
	})
}

// A client certificate must reach the server in the TLS handshake. FlowStreamService reads it from
// the connection's peer certificates, and does not read it from gRPC metadata at all.
func TestCredentialForFlowAggregator_ClientCert(t *testing.T) {
	assertPresents := func(t *testing.T, cred *flowAggregatorCredential, wantCertPEM []byte) {
		t.Helper()
		assert.Empty(t, cred.metadata, "a certificate is not sent as metadata")
		require.NotNil(t, cred.getClientCertificate)
		got, err := cred.getClientCertificate(&tls.CertificateRequestInfo{})
		require.NoError(t, err)
		block, _ := pem.Decode(wantCertPEM)
		require.NotNil(t, block)
		require.NotEmpty(t, got.Certificate)
		assert.Equal(t, block.Bytes, got.Certificate[0])
	}

	t.Run("CertData/KeyData provided directly", func(t *testing.T) {
		certPEM, keyPEM, _, _ := writeClientCert(t, t.TempDir())
		cred, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertData: certPEM, KeyData: keyPEM},
		})
		require.NoError(t, err)
		assertPresents(t, cred, certPEM)
	})

	t.Run("CertFile/KeyFile read from disk", func(t *testing.T) {
		certPEM, _, certPath, keyPath := writeClientCert(t, t.TempDir())
		cred, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertFile: certPath, KeyFile: keyPath},
		})
		require.NoError(t, err)
		assertPresents(t, cred, certPEM)
	})

	t.Run("the certificate is presented in a real TLS handshake", func(t *testing.T) {
		certPEM, keyPEM, _, _ := writeClientCert(t, t.TempDir())
		cred, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertData: certPEM, KeyData: keyPEM},
		})
		require.NoError(t, err)

		var presented int
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented = len(r.TLS.PeerCertificates)
		}))
		// The same posture as FlowStreamService's listener: ask for a certificate, do not require one.
		server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		server.StartTLS()
		defer server.Close()

		// Verification of the server is not what is under test; the client's certificate is.
		clientTLS := &tls.Config{InsecureSkipVerify: true, GetClientCertificate: cred.getClientCertificate} //nolint:gosec
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
		resp, err := client.Get(server.URL)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, 1, presented)
	})

	t.Run("missing cert file", func(t *testing.T) {
		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertFile: filepath.Join(t.TempDir(), "missing")},
		})
		require.Error(t, err)
	})

	t.Run("missing key file", func(t *testing.T) {
		_, _, certPath, _ := writeClientCert(t, t.TempDir())
		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{
				CertFile: certPath,
				KeyFile:  filepath.Join(t.TempDir(), "missing-key"),
			},
		})
		require.Error(t, err)
	})

	t.Run("certificate that does not match its key", func(t *testing.T) {
		certPEM, _, _, _ := writeClientCert(t, t.TempDir())
		_, otherKeyPEM, _, _ := writeClientCert(t, t.TempDir())
		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertData: certPEM, KeyData: otherKeyPEM},
		})
		require.Error(t, err)
	})
}

// TestCredentialForFlowAggregator_Default exercises the best-effort fallback branch
// (capturedBearerToken), reached when cfg holds no static bearer token or client certificate. This
// harness cannot configure an exec plugin, and none is covered by an e2e test, so only what the
// branch must refuse is tested here.
func TestCredentialForFlowAggregator_Default(t *testing.T) {
	t.Run("basic auth is not forwarded as a bearer token", func(t *testing.T) {
		var seenAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{
			Host:     server.URL,
			Username: "user",
			Password: "pass",
		})
		require.Error(t, err)
		assert.ErrorContains(t, err, "only a bearer token or a client certificate in the kubeconfig is supported")
		assert.NotEmpty(t, seenAuth, "the credential must have been used for the API server request, or this test proves nothing")
	})

	t.Run("no auth mechanism attaches any header at all", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{Host: server.URL})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no bearer token observed")
	})

	t.Run("the failure of the request is reported along with the missing token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		server.Close() // nothing listens at its address any more

		_, err := credentialForFlowAggregator(context.Background(), &rest.Config{Host: server.URL})
		require.Error(t, err)
		assert.ErrorContains(t, err, "no bearer token observed")
		assert.ErrorContains(t, err, "the request failed with")
	})
}

// TestCapturedBearerToken tests the mechanism the default branch of credentialForFlowAggregator
// relies on. It does not make any kind of credential beyond a bearer token or a client certificate
// supported: see the comment on TestCredentialForFlowAggregator_Default.
func TestCapturedBearerToken(t *testing.T) {
	// selfSubjectReview answers as the API server does to the request that capturedBearerToken makes.
	selfSubjectReview := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`))
	})

	t.Run("captures the bearer token that is attached to the request", func(t *testing.T) {
		server := httptest.NewServer(selfSubjectReview)
		defer server.Close()

		token, err := capturedBearerToken(context.Background(), &rest.Config{Host: server.URL, BearerToken: "tok-captured"})
		require.NoError(t, err)
		assert.Equal(t, "tok-captured", token)
	})

	t.Run("a request that succeeds without a token has nothing to capture", func(t *testing.T) {
		server := httptest.NewServer(selfSubjectReview)
		defer server.Close()

		_, err := capturedBearerToken(context.Background(), &rest.Config{Host: server.URL})
		require.Error(t, err)
		assert.ErrorContains(t, err, "no bearer token observed")
		assert.NotContains(t, err.Error(), "the request failed with", "the request did not fail")
	})

	t.Run("a configuration that cannot make a client", func(t *testing.T) {
		_, err := capturedBearerToken(context.Background(), &rest.Config{
			Host:            "http://127.0.0.1:1",
			TLSClientConfig: rest.TLSClientConfig{Insecure: true, CAFile: "/does/not/matter"},
		})
		require.Error(t, err)
	})
}

func TestTokenCapturingRoundTripper(t *testing.T) {
	t.Run("captures the token and forwards the request unmodified", func(t *testing.T) {
		var seenAuth string
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenAuth = req.Header.Get("Authorization")
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		rt := &tokenCapturingRoundTripper{rt: inner}
		req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", bearerTokenPrefix+"secret-token")

		resp, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "secret-token", rt.token)
		assert.Equal(t, bearerTokenPrefix+"secret-token", seenAuth, "the request must reach the inner transport unmodified")
	})

	t.Run("an Authorization header that is not a bearer token is forwarded but not captured", func(t *testing.T) {
		var seenAuth string
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenAuth = req.Header.Get("Authorization")
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		rt := &tokenCapturingRoundTripper{rt: inner}
		req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		_, err = rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Empty(t, rt.token, "a Basic credential must not be mistaken for a bearer token")
		assert.Equal(t, "Basic dXNlcjpwYXNz", seenAuth, "the request must still reach the inner transport unmodified")
	})

	t.Run("no Authorization header, nothing captured", func(t *testing.T) {
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		rt := &tokenCapturingRoundTripper{rt: inner}
		req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		require.NoError(t, err)

		_, err = rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Empty(t, rt.token)
	})

	t.Run("propagates the inner transport's error", func(t *testing.T) {
		wantErr := errors.New("boom")
		inner := roundTripFunc(func(req *http.Request) (*http.Response, error) { return nil, wantErr })
		rt := &tokenCapturingRoundTripper{rt: inner}
		req, err := http.NewRequest(http.MethodGet, "http://example.invalid", nil)
		require.NoError(t, err)

		_, err = rt.RoundTrip(req)
		assert.ErrorIs(t, err, wantErr)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

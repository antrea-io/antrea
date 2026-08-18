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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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
	cred, err := credentialForFlowAggregator(&rest.Config{BearerToken: "tok-abc"})
	require.NoError(t, err)
	assert.Equal(t, []string{"Bearer tok-abc"}, cred.metadata.Get(authorizationMetadataKey))
	assert.Nil(t, cred.getClientCertificate)
}

func TestCredentialForFlowAggregator_BearerTokenFile(t *testing.T) {
	t.Run("valid file, whitespace is trimmed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("tok-from-file\n"), 0o600))
		cred, err := credentialForFlowAggregator(&rest.Config{BearerTokenFile: path})
		require.NoError(t, err)
		assert.Equal(t, []string{"Bearer tok-from-file"}, cred.metadata.Get(authorizationMetadataKey))
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := credentialForFlowAggregator(&rest.Config{BearerTokenFile: filepath.Join(t.TempDir(), "missing")})
		require.Error(t, err)
	})

	// These follow client-go, which sends the content of the file and only falls back to the
	// inline token when the file cannot be used. clientcmd sets both fields whenever a kubeconfig
	// has a tokenFile, with BearerToken holding the content of the file at load time.
	missing := filepath.Join(t.TempDir(), "missing")
	writeToken := func(t *testing.T, content string) string {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	tests := []struct {
		name    string
		cfg     func(t *testing.T) *rest.Config
		want    string
		wantErr string
	}{
		{
			name: "the file wins over a different inline token",
			cfg: func(t *testing.T) *rest.Config {
				return &rest.Config{BearerToken: "inline", BearerTokenFile: writeToken(t, "from-file\n")}
			},
			want: "Bearer from-file",
		},
		{
			name: "a token file rotated after the kubeconfig was loaded wins over its snapshot",
			cfg: func(t *testing.T) *rest.Config {
				path := writeToken(t, "old\n")
				cfg := &rest.Config{BearerToken: "old\n", BearerTokenFile: path}
				require.NoError(t, os.WriteFile(path, []byte("rotated\n"), 0o600))
				return cfg
			},
			want: "Bearer rotated",
		},
		{
			name: "an unreadable file falls back to the inline token",
			cfg: func(t *testing.T) *rest.Config {
				return &rest.Config{BearerToken: "inline", BearerTokenFile: missing}
			},
			want: "Bearer inline",
		},
		{
			name: "an empty file falls back to the inline token",
			cfg: func(t *testing.T) *rest.Config {
				return &rest.Config{BearerToken: "inline", BearerTokenFile: writeToken(t, " \n")}
			},
			want: "Bearer inline",
		},
		{
			name: "an empty file without an inline token fails",
			cfg: func(t *testing.T) *rest.Config {
				return &rest.Config{BearerTokenFile: writeToken(t, "\n")}
			},
			wantErr: "the file is empty",
		},
		{
			name: "an unreadable file without an inline token fails",
			cfg: func(t *testing.T) *rest.Config {
				return &rest.Config{BearerTokenFile: missing}
			},
			wantErr: "failed to read bearer token file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := credentialForFlowAggregator(tt.cfg(t))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{tt.want}, cred.metadata.Get(authorizationMetadataKey))
		})
	}
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
		cred, err := credentialForFlowAggregator(&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertData: certPEM, KeyData: keyPEM},
		})
		require.NoError(t, err)
		assertPresents(t, cred, certPEM)
	})

	t.Run("CertFile/KeyFile read from disk", func(t *testing.T) {
		certPEM, _, certPath, keyPath := writeClientCert(t, t.TempDir())
		cred, err := credentialForFlowAggregator(&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertFile: certPath, KeyFile: keyPath},
		})
		require.NoError(t, err)
		assertPresents(t, cred, certPEM)
	})

	t.Run("the certificate is presented in a real TLS handshake", func(t *testing.T) {
		certPEM, keyPEM, _, _ := writeClientCert(t, t.TempDir())
		cred, err := credentialForFlowAggregator(&rest.Config{
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
		_, err := credentialForFlowAggregator(&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertFile: filepath.Join(t.TempDir(), "missing")},
		})
		require.Error(t, err)
	})

	t.Run("missing key file", func(t *testing.T) {
		_, _, certPath, _ := writeClientCert(t, t.TempDir())
		_, err := credentialForFlowAggregator(&rest.Config{
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
		_, err := credentialForFlowAggregator(&rest.Config{
			TLSClientConfig: rest.TLSClientConfig{CertData: certPEM, KeyData: otherKeyPEM},
		})
		require.Error(t, err)
	})
}

// TestCredentialForFlowAggregator_Unsupported checks that a kubeconfig whose credential is not a
// static bearer token or a static client certificate is rejected, rather than approximated with a
// token captured from an API server request.
func TestCredentialForFlowAggregator_Unsupported(t *testing.T) {
	tests := []struct {
		name string
		cfg  *rest.Config
	}{
		{name: "no credential at all", cfg: &rest.Config{Host: "https://127.0.0.1:6443"}},
		{name: "basic auth", cfg: &rest.Config{Username: "user", Password: "pass"}},
		{name: "exec plugin", cfg: &rest.Config{ExecProvider: &clientcmdapi.ExecConfig{
			Command:         "gke-gcloud-auth-plugin",
			APIVersion:      "client.authentication.k8s.io/v1",
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		}}},
		{name: "auth provider", cfg: &rest.Config{AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "oidc"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := credentialForFlowAggregator(tc.cfg)
			require.Error(t, err)
			assert.Nil(t, cred)
			assert.ErrorContains(t, err, "does not provide a static bearer token (token or tokenFile) or a client certificate")
		})
	}
}

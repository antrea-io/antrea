// Copyright 2025 Antrea Authors.
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

package certificate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
)

func TestProvider_shouldRotateCertificate(t *testing.T) {
	tests := []struct {
		name string
		cert []byte
		want bool
	}{
		{
			name: "no certificate - empty",
			cert: []byte{},
			want: true,
		}, {
			name: "no certificate - nil",
			cert: nil,
			want: true,
		}, {
			name: "expired certificate",
			cert: generateTestCert(time.Time{}),
			want: true,
		}, {
			name: "valid certificate",
			cert: generateTestCert(time.Now().Add(-5 * time.Hour)),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider(nil, "")
			got := p.shouldRotateCertificate(tt.cert)
			assert.Equal(t, tt.want, got)
		})
	}
}

func generateTestCert(validFrom time.Time) []byte {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil
	}

	// generate rootCA
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("flow-aggregator-ca@%d", time.Now().Unix()),
		},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(maxAge),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// generate CA certificate
	caCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil
	}
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  certutil.CertificateBlockType,
		Bytes: caCert,
	})

	return caPEM.Bytes()
}

func TestProvider_getSecret(t *testing.T) {
	secretName := "tls-secret"

	tests := []struct {
		name               string
		secretCertContent  []byte
		secretKeyContent   []byte
		overrideSecretName string

		expectedCert []byte
		expectedKey  []byte
		expectError  bool
	}{
		{
			name:               "secret does not exist",
			overrideSecretName: "foo",
			expectError:        true,
		}, {
			name:              "has content",
			secretCertContent: []byte("cert"),
			secretKeyContent:  []byte("key"),
			expectedCert:      []byte("cert"),
			expectedKey:       []byte("key"),
			expectError:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existingSecret := createSecret(secretName, []byte("cert"), []byte("key"))
			client := fake.NewClientset(existingSecret)

			p := NewProvider(client, "")

			name := tt.overrideSecretName
			if name == "" {
				name = secretName
			}
			certBytes, certKeyBytes, secret, gotErr := p.getSecret(name)
			require.Equal(t, tt.expectError, gotErr != nil)
			if tt.overrideSecretName == "" {
				assert.Equal(t, existingSecret, secret)
			}
			assert.Equal(t, tt.expectedCert, certBytes)
			assert.Equal(t, tt.expectedKey, certKeyBytes)
		})
	}
}

func TestProvider_processNextWorkItem(t *testing.T) {
	namespace := "flow-aggregator"
	caCert, caKey, err := GenerateCACertKey(time.Now().Add(-1 * time.Hour))
	require.NoError(t, err)

	tests := []struct {
		name                    string
		existingSecrets         []runtime.Object
		expectedCACertPEM       []byte
		expectCASecretCreated   bool
		expectCASecretValid     bool
		expectClientSecretValid bool
		expectCAConfigMapMatch  bool
		expectRequeue           bool
	}{
		{
			name:                  "no certs",
			expectCASecretCreated: true,
		}, {
			name: "ca cert is invalid",
			existingSecrets: []runtime.Object{
				createSecret(caSecretName, []byte("caCert"), []byte("caKey")),
			},
		}, {
			name: "ca cert is valid - client cert does not exist",
			existingSecrets: []runtime.Object{
				createSecret(caSecretName, caCert, caKey),
			},
			expectClientSecretValid: true,
			expectCAConfigMapMatch:  true,
			expectedCACertPEM:       caCert,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(tt.existingSecrets...)
			p := NewProvider(client, "")

			p.queue.Add("key")
			require.True(t, p.processNextWorkItem())

			numRequeues := p.queue.NumRequeues("key")
			if tt.expectRequeue {
				assert.Equal(t, 1, numRequeues)
			} else {
				assert.Equal(t, 0, numRequeues)
				if tt.expectCASecretCreated {
					secret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), caSecretName, metav1.GetOptions{})
					require.NoError(t, err)
					require.NotNil(t, secret)
				}

				if tt.expectCASecretValid {
					secret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), caSecretName, metav1.GetOptions{})
					require.NoError(t, err)
					assert.Equal(t, caCert, secret.Data[secretCertKey])
					assert.Equal(t, caKey, secret.Data[secretKeyKey])
				}

				if tt.expectCAConfigMapMatch {
					cm, err := client.CoreV1().ConfigMaps(namespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
					require.NoError(t, err)
					assert.Equal(t, cm.Data[caConfigMapKey], string(caCert))
				}

				if tt.expectClientSecretValid {
					secret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), clientSecretName, metav1.GetOptions{})
					require.NoError(t, err)
					assert.NoError(t, verifyCertificate(caCert, secret.Data[secretCertKey]))
				}

				assert.Equal(t, tt.expectedCACertPEM, p.caCertPEM)
			}
		})
	}
}

func TestProvider_GetServerCertKey(t *testing.T) {
	client := fake.NewClientset()
	p := NewProvider(client, "")

	p.caCertPEM = []byte("caCert")
	p.serverCertPEM = []byte("serverCert")
	p.serverKeyPEM = []byte("serverKey")

	caCert, serverCert, serverKey := p.GetTLSConfig()

	assert.Equal(t, []byte("caCert"), caCert)
	assert.Equal(t, []byte("serverCert"), serverCert)
	assert.Equal(t, []byte("serverKey"), serverKey)
}

func startProviderWithClient(client kubernetes.Interface, stopCh chan struct{}) (*Provider, chan struct{}) {
	p := NewProvider(client, "flow-aggregator.svc")
	exitCh := make(chan struct{})
	go func() {
		p.Run(stopCh)
		close(exitCh)
	}()

	return p, exitCh
}

func TestProvider_Run(t *testing.T) {
	namespace := "flow-aggregator"
	t.Setenv("POD_NAMESPACE", namespace)

	client := fake.NewClientset()

	stopCh := make(chan struct{})
	provider1, provider1ExitCh := startProviderWithClient(client, stopCh)
	provider2, provider2ExitCh := startProviderWithClient(client, stopCh)

	require.True(t, cache.WaitForCacheSync(stopCh, provider1.HasSynced, provider2.HasSynced))

	// Both providers ran at least once.
	close(stopCh)

	select {
	case <-provider1ExitCh:
	case <-time.After(1 * time.Second):
		require.Fail(t, "provider1 did not shutdown in time")
	}

	select {
	case <-provider2ExitCh:
	case <-time.After(1 * time.Second):
		require.Fail(t, "provider2 did not shutdown in time")
	}

	require.NotEmpty(t, provider1.caCertPEM)
	require.NotEmpty(t, provider1.serverCertPEM)
	require.NotEmpty(t, provider1.serverKeyPEM)
	require.NotEmpty(t, provider2.caCertPEM)
	require.NotEmpty(t, provider2.serverCertPEM)
	require.NotEmpty(t, provider2.serverKeyPEM)

	caSecret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), caSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, provider1.caCertPEM, caSecret.Data[secretCertKey])
	assert.Equal(t, provider2.caCertPEM, caSecret.Data[secretCertKey])

	caConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), caConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, caConfigMap.Data[caConfigMapKey], string(caSecret.Data[secretCertKey]))

	assert.NoError(t, verifyCertificate(caSecret.Data[secretCertKey], provider1.serverCertPEM))
	assert.NoError(t, verifyCertificate(caSecret.Data[secretCertKey], provider2.serverCertPEM))

	clientSecret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), clientSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caSecret.Data[secretCertKey], clientSecret.Data[secretCertKey]))

}

func createSecret(name string, certPEMBytes, keyPEMBytes []byte) *v1.Secret {
	if len(certPEMBytes) == 0 || len(keyPEMBytes) == 0 {
		return nil
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "flow-aggregator",
		},
		Data: map[string][]byte{
			secretCertKey: certPEMBytes,
			secretKeyKey:  keyPEMBytes,
		},
		Type: v1.SecretTypeTLS,
	}
}

func Test_verifyCertificate(t *testing.T) {
	validFrom := time.Now().Add(-time.Hour)
	caCertPEM, caKeyPEM, err := GenerateCACertKey(validFrom)
	require.NoError(t, err)

	caCert, caKey, err := pemToCertKey(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	clientCertPEM, _, err := GenerateCertKey(caCert, caKey, validFrom, false, "")
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caCertPEM, clientCertPEM))

	serverCertPEM, _, err := GenerateCertKey(caCert, caKey, validFrom, true, "foo.bar.xyz")
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caCertPEM, serverCertPEM))
}

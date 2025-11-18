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
	"k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
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
			p := NewProvider(nil, "").(*provider)
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
			client := fake.NewClientset(createSecret(secretName, []byte("cert"), []byte("key")))

			p := NewProvider(client, "").(*provider)

			name := tt.overrideSecretName
			if name == "" {
				name = secretName
			}
			certBytes, certKeyBytes, gotErr := p.getSecret(name)
			require.Equal(t, tt.expectError, gotErr != nil)
			assert.Equal(t, tt.expectedCert, certBytes)
			assert.Equal(t, tt.expectedKey, certKeyBytes)
		})
	}
}

func TestProvider_generateCertsAndSync(t *testing.T) {
	tests := []struct {
		name                  string
		existingSecrets       []runtime.Object
		flowAggregatorAddress string
	}{
		{
			name:                  "creates and syncs",
			flowAggregatorAddress: "addr",
		}, {
			name: "creates and update",
			existingSecrets: []runtime.Object{
				createSecret(CASecretName, []byte("caCert"), []byte("caKey")),
				createSecret(ServerSecretName, []byte("serverCert"), []byte("serverKey")),
				createSecret(ClientSecretName, []byte("clientCert"), []byte("clientKey")),
			},
			flowAggregatorAddress: "addr",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(tt.existingSecrets...)
			p := NewProvider(client, tt.flowAggregatorAddress).(*provider)
			require.NoError(t, p.generateCertsAndSync())

			caSecret, _ := client.CoreV1().Secrets("flow-aggregator").Get(context.TODO(), CASecretName, metav1.GetOptions{})
			validateCertificate(t, caSecret.Data[SecretCertKey], caSecret.Data[SecretKeyKey])
			serverSecret, _ := client.CoreV1().Secrets("flow-aggregator").Get(context.TODO(), ServerSecretName, metav1.GetOptions{})
			validateCertificate(t, serverSecret.Data[SecretCertKey], serverSecret.Data[SecretKeyKey])
			clientSecret, _ := client.CoreV1().Secrets("flow-aggregator").Get(context.TODO(), ClientSecretName, metav1.GetOptions{})
			validateCertificate(t, clientSecret.Data[SecretCertKey], clientSecret.Data[SecretKeyKey])

			// caConfigMap, _ := client.CoreV1().ConfigMaps("flow-aggregator").Get(context.TODO(), CAConfigMapName, metav1.GetOptions{})
		})
	}
}

func TestProvider_processNextWorkItem(t *testing.T) {
	tests := []struct {
		name                  string
		existingSecrets       []runtime.Object
		expectedCACertPEM     []byte
		expectedServerCertPEM []byte
		expectedServerKeyPEM  []byte
		expectRequeue         bool
	}{
		{
			name:          "no certs ready",
			expectRequeue: true,
		}, {
			name: "only ca cert ready",
			existingSecrets: []runtime.Object{
				createSecret(CASecretName, []byte("caCert"), []byte("caKey")),
			},
			expectRequeue: true,
		}, {
			name: "all certs ready",
			existingSecrets: []runtime.Object{
				createSecret(CASecretName, []byte("caCert"), []byte("caKey")),
				createSecret(ServerSecretName, []byte("serverCert"), []byte("serverKey")),
			},
			expectedCACertPEM:     []byte("caCert"),
			expectedServerCertPEM: []byte("serverCert"),
			expectedServerKeyPEM:  []byte("serverKey"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(tt.existingSecrets...)
			p := NewProvider(client, "").(*provider)

			p.queue.Add("key")
			require.True(t, p.processNextWorkItem())

			numRequeues := p.queue.NumRequeues("key")
			if tt.expectRequeue {
				assert.Equal(t, 1, numRequeues)
			} else {
				assert.Equal(t, 0, numRequeues)
				assert.Equal(t, tt.expectedCACertPEM, p.caCertPEM)
				assert.Equal(t, tt.expectedServerCertPEM, p.serverCertPEM)
				assert.Equal(t, tt.expectedServerKeyPEM, p.serverKeyPEM)
			}

		})
	}
}

func TestProvider_GetServerCertKey(t *testing.T) {
	client := fake.NewClientset()
	p := NewProvider(client, "").(*provider)

	successCh := make(chan struct{})
	go func() {
		caCert, serverCert, serverKey := p.GetServerCertKey()

		assert.Equal(t, []byte("caCert"), caCert)
		assert.Equal(t, []byte("serverCert"), serverCert)
		assert.Equal(t, []byte("serverKey"), serverKey)
		close(successCh)
	}()

	p.certsReadyCond.L.Lock()
	p.caCertPEM = []byte("caCert")
	p.serverCertPEM = []byte("serverCert")
	p.serverKeyPEM = []byte("serverKey")
	p.serverCertsSynced = true
	p.serverCertsUpdated = true
	p.certsReadyCond.Broadcast()
	p.certsReadyCond.L.Unlock()

	select {
	case <-successCh:
	case <-time.After(time.Second):
		require.Fail(t, "server certs never became available after successful update")
	}
}

func TestProvider_Run(t *testing.T) {
	client := fake.NewClientset()

	stopCh := make(chan struct{})
	provider1FinishedCh := make(chan struct{})
	provider1 := NewProvider(client, "flow-aggregator.svc").(*provider)

	t.Setenv("POD_NAME", "pod1")
	go func() {
		provider1.Run(stopCh)
		close(provider1FinishedCh)
	}()

	provider2FinishedCh := make(chan struct{})
	provider2 := NewProvider(client, "flow-aggregator.svc").(*provider)

	t.Setenv("POD_NAME", "pod2")
	go func() {
		provider2.Run(stopCh)
		close(provider2FinishedCh)
	}()

	// This waits until the certs have synced which means it has run at least once and done leader election
	provider1.GetServerCertKey()
	provider2.GetServerCertKey()

	// Both providers ran at least once.
	close(stopCh)

	select {
	case <-provider1FinishedCh:
	case <-time.After(1 * time.Second):
		require.Fail(t, "provider1 did not shutdown in time")
	}

	select {
	case <-provider2FinishedCh:
	case <-time.After(1 * time.Second):
		require.Fail(t, "provider2 did not shutdown in time")
	}

	leases, _ := client.CoordinationV1().Leases("flow-aggregator").List(context.TODO(), metav1.ListOptions{})
	require.Len(t, leases.Items, 1)
	require.NotEmpty(t, provider1.caCertPEM)
	require.NotEmpty(t, provider1.serverCertPEM)
	require.NotEmpty(t, provider1.serverKeyPEM)
	assert.Equal(t, provider1.caCertPEM, provider2.caCertPEM)
	assert.Equal(t, provider1.serverCertPEM, provider2.serverCertPEM)
	assert.Equal(t, provider1.serverKeyPEM, provider2.serverKeyPEM)
}

func validateCertificate(t *testing.T, certPEM, keyPEM []byte) {
	require.NotNil(t, certPEM)
	require.NotNil(t, keyPEM)

	caCerts, err := certutil.ParseCertsPEM(certPEM)
	require.NoError(t, err)
	require.Len(t, caCerts, 1)

	_, err = keyutil.ParsePrivateKeyPEM(keyPEM)
	require.NoError(t, err)
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
			SecretCertKey: certPEMBytes,
			SecretKeyKey:  keyPEMBytes,
		},
		Type: v1.SecretTypeTLS,
	}
}

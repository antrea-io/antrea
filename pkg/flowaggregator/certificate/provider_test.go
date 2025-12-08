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
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestProvider_shouldRotateCertificate(t *testing.T) {
	validCert, validCertKey, err := GenerateCACertKey(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	invalidCert, invalidCertKey, err := GenerateCACertKey(time.Time{})
	require.NoError(t, err)

	tests := []struct {
		name string
		cert []byte
		key  []byte
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
			cert: invalidCert,
			key:  invalidCertKey,
			want: true,
		}, {
			name: "valid certificate",
			cert: validCert,
			key:  validCertKey,
			want: false,
		}, {
			name: "valid certificate - non-matching key",
			cert: validCert,
			key:  invalidCertKey,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider(nil, "")
			got := p.shouldRotateCertificate(tt.cert, tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProvider_getSecret(t *testing.T) {
	secretName := "tls-secret"

	tests := []struct {
		name         string
		createSecret bool

		expectedCert []byte
		expectedKey  []byte
		expectError  bool
	}{
		{
			name:        "secret does not exist",
			expectError: true,
		}, {
			name:         "has content",
			createSecret: true,
			expectedCert: []byte("cert"),
			expectedKey:  []byte("key"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existingObjects := []runtime.Object{}
			if tt.createSecret {
				existingObjects = append(existingObjects, createSecret(secretName, []byte("cert"), []byte("key")))
			}

			client := fake.NewClientset(existingObjects...)

			p := createTestProvider(t, client)

			certBytes, certKeyBytes, secret, err := p.getSecret(t.Context(), secretName)
			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, existingObjects[0], secret)
			assert.Equal(t, tt.expectedCert, certBytes)
			assert.Equal(t, tt.expectedKey, certKeyBytes)
		})
	}
}

func TestProvider_rotateCertificates(t *testing.T) {
	client := fake.NewClientset()
	clock := clocktesting.NewFakeClock(time.Now())
	provider := createTestProviderWithClock(t, client, clock)

	verifySecret := func(t *testing.T, name string) *v1.Secret {
		secret, err := client.CoreV1().Secrets(defaultNamespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		cert, _, err := pemToCertKey(secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey])
		require.NoError(t, err)
		assert.True(t, cert.NotAfter.After(clock.Now()))
		assert.True(t, cert.NotBefore.Before(clock.Now()))
		return secret
	}

	rotateAndCheck := func(t *testing.T) (*v1.Secret, *v1.Secret) {
		retry, err := provider.rotateCertificates(t.Context())
		require.NoError(t, err)
		assert.False(t, retry)

		caSecret := verifySecret(t, caSecretName)
		clientSecret := verifySecret(t, clientSecretName)

		caConfigMap, err := client.CoreV1().ConfigMaps(defaultNamespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, string(caSecret.Data[v1.TLSCertKey]), caConfigMap.Data[caConfigMapKey])

		return caSecret, clientSecret
	}

	t.Run("rotate is idempotent if certs are valid", func(t *testing.T) {
		prevCASecret, prevClientSecret := rotateAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		time.Sleep(200 * time.Millisecond) // Wait for lister to update
		newCASecret, newClientSecret := rotateAndCheck(t)
		assert.Equal(t, prevCASecret.Data, newCASecret.Data)
		assert.Equal(t, prevClientSecret.Data, newClientSecret.Data)
		assert.Equal(t, prevProviderCACert, provider.caCertPEM)
		assert.Equal(t, prevServerCert, provider.serverCertPEM)
		assert.Equal(t, prevServerKey, provider.serverKeyPEM)
	})

	t.Run("recreate deleted client certs - nothing else changes", func(t *testing.T) {
		prevCASecret, prevClientSecret := rotateAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().Secrets(defaultNamespace).Delete(t.Context(), clientSecretName, metav1.DeleteOptions{}))
		time.Sleep(200 * time.Millisecond) // Wait for lister to update
		newCASecret, newClientSecret := rotateAndCheck(t)
		assert.Equal(t, prevCASecret.Data, newCASecret.Data)
		assert.NotEqual(t, prevClientSecret.Data, newClientSecret.Data)
		assert.Equal(t, prevProviderCACert, provider.caCertPEM)
		assert.Equal(t, prevServerCert, provider.serverCertPEM)
		assert.Equal(t, prevServerKey, provider.serverKeyPEM)

		caConfigMap, err := client.CoreV1().ConfigMaps(defaultNamespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, string(prevCASecret.Data[v1.TLSCertKey]), caConfigMap.Data[caConfigMapKey])
	})

	t.Run("recreate deleted ca configmap - nothing else changes", func(t *testing.T) {
		prevCASecret, prevClientSecret := rotateAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().ConfigMaps(defaultNamespace).Delete(t.Context(), caConfigMapName, metav1.DeleteOptions{}))
		time.Sleep(200 * time.Millisecond) // Wait for lister to update
		newCASecret, newClientSecret := rotateAndCheck(t)
		assert.Equal(t, prevCASecret.Data, newCASecret.Data)
		assert.Equal(t, prevClientSecret.Data, newClientSecret.Data)
		assert.Equal(t, prevProviderCACert, provider.caCertPEM)
		assert.Equal(t, prevServerCert, provider.serverCertPEM)
		assert.Equal(t, prevServerKey, provider.serverKeyPEM)

		caConfigMap, err := client.CoreV1().ConfigMaps(defaultNamespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, string(prevCASecret.Data[v1.TLSCertKey]), caConfigMap.Data[caConfigMapKey])
	})

	t.Run("recreate all resources - ca secret deleted", func(t *testing.T) {
		prevCASecret, prevClientSecret := rotateAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().Secrets(defaultNamespace).Delete(t.Context(), caSecretName, metav1.DeleteOptions{}))
		time.Sleep(200 * time.Millisecond) // Wait for lister to update
		newCASecret, newClientSecret := rotateAndCheck(t)
		assert.NotEqual(t, prevCASecret.Data, newCASecret.Data)
		assert.NotEqual(t, prevClientSecret.Data, newClientSecret.Data)
		assert.NotEqual(t, prevProviderCACert, provider.caCertPEM)
		assert.NotEqual(t, prevServerCert, provider.serverCertPEM)
		assert.NotEqual(t, prevServerKey, provider.serverKeyPEM)

		caConfigMap, err := client.CoreV1().ConfigMaps(defaultNamespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.NotEqual(t, string(prevCASecret.Data[v1.TLSCertKey]), caConfigMap.Data[caConfigMapKey])
	})

	t.Run("expired certs get rotated", func(t *testing.T) {
		prevCASecret, prevClientSecret := rotateAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		time.Sleep(200 * time.Millisecond) // Wait for lister to update
		clock.Step(2 * maxAge)
		newCASecret, newClientSecret := rotateAndCheck(t)
		assert.NotEqual(t, prevCASecret.Data, newCASecret.Data)
		assert.NotEqual(t, prevClientSecret.Data, newClientSecret.Data)
		assert.NotEqual(t, prevProviderCACert, provider.caCertPEM)
		assert.NotEqual(t, prevServerCert, provider.serverCertPEM)
		assert.NotEqual(t, prevServerKey, provider.serverKeyPEM)
	})
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

	caSecret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), caSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, provider1.caCertPEM, caSecret.Data[v1.TLSCertKey])
	assert.Equal(t, provider2.caCertPEM, caSecret.Data[v1.TLSCertKey])

	caConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, caConfigMap.Data[caConfigMapKey], string(caSecret.Data[v1.TLSCertKey]))

	assert.NoError(t, verifyCertificate(caSecret.Data[v1.TLSCertKey], provider1.serverCertPEM, time.Now()))
	assert.NoError(t, verifyCertificate(caSecret.Data[v1.TLSCertKey], provider2.serverCertPEM, time.Now()))

	clientSecret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), clientSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caSecret.Data[v1.TLSCertKey], clientSecret.Data[v1.TLSCertKey], time.Now()))
}

func Test_verifyCertificate(t *testing.T) {
	validFrom := time.Now().Add(-time.Hour)
	caCertPEM, caKeyPEM, err := GenerateCACertKey(validFrom)
	require.NoError(t, err)

	caCert, caKey, err := pemToCertKey(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	clientCertPEM, _, err := GenerateCertKey(caCert, caKey, validFrom, false, "")
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caCertPEM, clientCertPEM, time.Now()))

	serverCertPEM, _, err := GenerateCertKey(caCert, caKey, validFrom, true, "foo.bar.xyz")
	require.NoError(t, err)
	assert.NoError(t, verifyCertificate(caCertPEM, serverCertPEM, time.Now()))
}

func createTestProvider(t *testing.T, client kubernetes.Interface) *Provider {
	return createTestProviderWithClock(t, client, clock.RealClock{})
}

func createTestProviderWithClock(t *testing.T, client kubernetes.Interface, clock clock.Clock) *Provider {
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })

	p := &Provider{
		namespace: defaultNamespace,
		k8sClient: client,
		clock:     clock,
	}

	return p
}

func createSecret(name string, certPEMBytes, keyPEMBytes []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "flow-aggregator",
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       certPEMBytes,
			v1.TLSPrivateKeyKey: keyPEMBytes,
		},
		Type: v1.SecretTypeTLS,
	}
}

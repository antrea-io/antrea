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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/util/wait"
)

func TestProvider_shouldUpdateCACertificate(t *testing.T) {
	now := time.Now()
	validCert, validCertKey, err := generateCACertKey(now.Add(-time.Hour))
	require.NoError(t, err)
	invalidCert, invalidCertKey, err := generateCACertKey(now.Add(-maxAge))
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
			got := shouldUpdateCACertificate(tt.cert, tt.key, now)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_generateCertKey(t *testing.T) {
	now := time.Now()
	validFrom := now.Add(-time.Hour)
	caCertPEM, caKeyPEM, err := generateCACertKey(validFrom)
	require.NoError(t, err)

	ca, err := parseKeyPair(caCertPEM, caKeyPEM)
	require.NoError(t, err)
	caCert := ca.Leaf
	caKey := ca.PrivateKey

	t.Run("server", func(t *testing.T) {
		serverCertPEM, serverKeyPEM, err := generateCertKey(caCert, caKey, validFrom, true, "foo.bar.xyz")
		require.NoError(t, err)

		serverTLS, err := parseKeyPair(serverCertPEM, serverKeyPEM)
		require.NoError(t, err)

		assert.NoError(t, verifyServerCertificate(caCert, serverTLS.Leaf, now))
	})

	t.Run("client", func(t *testing.T) {
		clientCertPEM, clientKeyPEM, err := generateCertKey(caCert, caKey, validFrom, false, "")
		require.NoError(t, err)

		clientTLS, err := parseKeyPair(clientCertPEM, clientKeyPEM)
		require.NoError(t, err)

		assert.NoError(t, verifyClientCertificate(caCert, clientTLS.Leaf, now))
	})
}

func TestProvider_getSecret(t *testing.T) {
	t.Run("ca secret does not exist", func(t *testing.T) {
		client := fake.NewClientset()
		p := createTestProvider(t, client)
		_, _, _, err := p.getSecret(caSecretName)
		assert.True(t, errors.IsNotFound(err))
	})

	t.Run("client secret does not exist", func(t *testing.T) {
		client := fake.NewClientset()
		p := createTestProvider(t, client)
		_, _, _, err := p.getSecret(clientSecretName)
		assert.True(t, errors.IsNotFound(err))
	})

	t.Run("secret name not supported", func(t *testing.T) {
		client := fake.NewClientset()
		p := createTestProvider(t, client)
		_, _, _, err := p.getSecret("unknown")
		assert.ErrorContains(t, err, "secret \"unknown\" not managed by flow aggregator")
	})

	t.Run("secret exists", func(t *testing.T) {
		existingSecret := createSecret(caSecretName, []byte("cert"), []byte("key"))
		client := fake.NewClientset(existingSecret)
		p := createTestProvider(t, client)
		certBytes, certKeyBytes, secret, err := p.getSecret(caSecretName)
		require.NoError(t, err)
		assert.Equal(t, existingSecret, secret)
		assert.Equal(t, []byte("cert"), certBytes)
		assert.Equal(t, []byte("key"), certKeyBytes)
	})
}

func TestProvider_syncCertificates(t *testing.T) {
	var client *fake.Clientset
	var clock *clocktesting.FakeClock
	var provider *Provider

	initialize := func() {
		client = fake.NewClientset()
		clock = clocktesting.NewFakeClock(time.Now())
		provider = createTestProviderWithClock(t, client, clock)
	}

	verifySecret := func(t *testing.T, name string) *v1.Secret {
		secret, err := client.CoreV1().Secrets(defaultNamespace).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		tlsCert, err := parseKeyPair(secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey])
		require.NoError(t, err)
		cert := tlsCert.Leaf
		assert.True(t, cert.NotAfter.After(clock.Now()))
		assert.True(t, cert.NotBefore.Before(clock.Now()))
		return secret
	}

	syncAndCheck := func(t *testing.T) (*v1.Secret, *v1.Secret) {
		retry, err := provider.syncCertificates(t.Context())
		require.NoError(t, err)
		assert.False(t, retry)

		caSecret := verifySecret(t, caSecretName)
		clientSecret := verifySecret(t, clientSecretName)

		caConfigMap, err := client.CoreV1().ConfigMaps(defaultNamespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, string(caSecret.Data[v1.TLSCertKey]), caConfigMap.Data[caConfigMapKey])

		return caSecret, clientSecret
	}

	checkCASecretInformerSynced := func(t require.TestingT, shouldExist bool) {
		_, exist, err := provider.caSecretInformer.GetIndexer().GetByKey(fmt.Sprintf("%s/%s", defaultNamespace, caSecretName))
		require.NoError(t, err)
		require.Equal(t, shouldExist, exist)
	}

	checkClientSecretInformerSynced := func(t require.TestingT, shouldExist bool) {
		_, exist, err := provider.clientSecretInformer.GetIndexer().GetByKey(fmt.Sprintf("%s/%s", defaultNamespace, clientSecretName))
		require.NoError(t, err)
		require.Equal(t, shouldExist, exist)
	}

	checkCAConfigMapInformerSynced := func(t require.TestingT, shouldExist bool) {
		_, exist, err := provider.caConfigMapInformer.GetIndexer().GetByKey(fmt.Sprintf("%s/%s", defaultNamespace, caConfigMapName))
		require.NoError(t, err)
		require.Equal(t, shouldExist, exist)
	}

	t.Run("sync is idempotent if certs are valid", func(t *testing.T) {
		initialize()
		prevCASecret, prevClientSecret := syncAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		assert.EventuallyWithT(t, func(c *assert.CollectT) { // Wait for indexer to update.
			checkCASecretInformerSynced(c, true)
			checkClientSecretInformerSynced(c, true)
			checkCAConfigMapInformerSynced(c, true)
		}, 5*time.Second, 100*time.Millisecond)

		newCASecret, newClientSecret := syncAndCheck(t)
		assert.Equal(t, prevCASecret.Data, newCASecret.Data)
		assert.Equal(t, prevClientSecret.Data, newClientSecret.Data)
		assert.Equal(t, prevProviderCACert, provider.caCertPEM)
		assert.Equal(t, prevServerCert, provider.serverCertPEM)
		assert.Equal(t, prevServerKey, provider.serverKeyPEM)
	})

	t.Run("recreate deleted client certs - nothing else changes", func(t *testing.T) {
		initialize()
		prevCASecret, prevClientSecret := syncAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().Secrets(defaultNamespace).Delete(t.Context(), clientSecretName, metav1.DeleteOptions{}))
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			checkCASecretInformerSynced(c, true)
			checkClientSecretInformerSynced(c, false)
			checkCAConfigMapInformerSynced(c, true)
		}, 5*time.Second, 100*time.Millisecond)

		newCASecret, newClientSecret := syncAndCheck(t)
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
		initialize()
		prevCASecret, prevClientSecret := syncAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().ConfigMaps(defaultNamespace).Delete(t.Context(), caConfigMapName, metav1.DeleteOptions{}))
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			checkCASecretInformerSynced(c, true)
			checkClientSecretInformerSynced(c, true)
			checkCAConfigMapInformerSynced(c, false)
		}, 5*time.Second, 100*time.Millisecond)

		newCASecret, newClientSecret := syncAndCheck(t)
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
		initialize()
		prevCASecret, prevClientSecret := syncAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		require.NoError(t, client.CoreV1().Secrets(defaultNamespace).Delete(t.Context(), caSecretName, metav1.DeleteOptions{}))
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			checkCASecretInformerSynced(c, false)
			checkClientSecretInformerSynced(c, true)
			checkCAConfigMapInformerSynced(c, true)
		}, 5*time.Second, 100*time.Millisecond)

		newCASecret, newClientSecret := syncAndCheck(t)
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
		initialize()
		prevCASecret, prevClientSecret := syncAndCheck(t)
		prevProviderCACert, prevServerCert, prevServerKey := provider.caCertPEM, provider.serverCertPEM, provider.serverKeyPEM
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			checkCASecretInformerSynced(c, true)
			checkClientSecretInformerSynced(c, true)
			checkCAConfigMapInformerSynced(c, true)
		}, 5*time.Second, 100*time.Millisecond)

		clock.Step(2 * maxAge)
		newCASecret, newClientSecret := syncAndCheck(t)
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

func startProviderWithClient(client kubernetes.Interface, wg *wait.Group, stopCh chan struct{}) *Provider {
	p := NewProvider(client, "flow-aggregator.svc")
	wg.Go(func() {
		p.Run(stopCh)
	})

	return p
}

func verifyServerCertificate(caCert, cert *x509.Certificate, now time.Time) error {
	return verifyCertificate(caCert, cert, x509.ExtKeyUsageServerAuth, now)
}

func pemToCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || len(block.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate failed: %w", err)
	}
	return cert, nil
}

func TestProvider_Run(t *testing.T) {
	namespace := "flow-aggregator"
	t.Setenv("POD_NAMESPACE", namespace)

	client := fake.NewClientset()

	wg := wait.NewGroup()
	stopCh := make(chan struct{})
	provider1 := startProviderWithClient(client, wg, stopCh)
	provider2 := startProviderWithClient(client, wg, stopCh)

	require.True(t, cache.WaitForCacheSync(stopCh, provider1.HasSynced, provider2.HasSynced))

	// Both providers ran at least once, as guaranteed by the cache.WaitForCacheSync call above.
	close(stopCh)

	require.NoError(t, wg.WaitWithTimeout(time.Second))

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
	caCert, err := pemToCert(caSecret.Data[v1.TLSCertKey])
	require.NoError(t, err)

	caConfigMap, err := client.CoreV1().ConfigMaps(namespace).Get(t.Context(), caConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, caConfigMap.Data[caConfigMapKey], string(caSecret.Data[v1.TLSCertKey]))

	serverCert1, err := pemToCert(provider1.serverCertPEM)
	require.NoError(t, err)
	assert.NoError(t, verifyServerCertificate(caCert, serverCert1, time.Now()))
	serverCert2, err := pemToCert(provider2.serverCertPEM)
	require.NoError(t, err)
	assert.NoError(t, verifyServerCertificate(caCert, serverCert2, time.Now()))

	clientSecret, err := client.CoreV1().Secrets(namespace).Get(t.Context(), clientSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	clientCert, err := pemToCert(clientSecret.Data[v1.TLSCertKey])
	require.NoError(t, err)
	assert.NoError(t, verifyClientCertificate(caCert, clientCert, time.Now()))
}

func TestProvider_shouldUpdateClientCertificate(t *testing.T) {
	now := time.Now()
	validFrom := now.Add(-time.Hour)
	caCertPEM, caKeyPEM, err := generateCACertKey(validFrom)
	require.NoError(t, err)

	ca, err := parseKeyPair(caCertPEM, caKeyPEM)
	require.NoError(t, err)
	caCert := ca.Leaf
	caKey := ca.PrivateKey

	validClientCertPEM, validClientKeyPEM, err := generateCertKey(caCert, caKey, validFrom, false, "")
	require.NoError(t, err)

	expiredClientCertPEM, expiredClientKeyPEM, err := generateCertKey(caCert, caKey, now.Add(-maxAge), false, "")
	require.NoError(t, err)

	tests := []struct {
		name          string
		clientCertPEM []byte
		clientKeyPEM  []byte
		caCert        *x509.Certificate
		now           time.Time
		want          bool
	}{
		{
			name:          "no certificate - empty",
			clientCertPEM: []byte{},
			clientKeyPEM:  []byte{},
			caCert:        caCert,
			now:           now,
			want:          true,
		},
		{
			name:          "no certificate - nil",
			clientCertPEM: nil,
			clientKeyPEM:  nil,
			caCert:        caCert,
			now:           now,
			want:          true,
		},
		{
			name:          "expired certificate",
			clientCertPEM: expiredClientCertPEM,
			clientKeyPEM:  expiredClientKeyPEM,
			caCert:        caCert,
			now:           now,
			want:          true,
		},
		{
			name:          "valid certificate",
			clientCertPEM: validClientCertPEM,
			clientKeyPEM:  validClientKeyPEM,
			caCert:        caCert,
			now:           now,
			want:          false,
		},
		{
			name:          "valid certificate - non-matching key",
			clientCertPEM: validClientCertPEM,
			clientKeyPEM:  expiredClientKeyPEM,
			caCert:        caCert,
			now:           now,
			want:          true,
		},
		{
			name:          "certificate past time to rotate",
			clientCertPEM: validClientCertPEM,
			clientKeyPEM:  validClientKeyPEM,
			caCert:        caCert,
			now:           validFrom.Add(maxAge - minValidDuration + time.Minute),
			want:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUpdateClientCertificate(tt.clientCertPEM, tt.clientKeyPEM, tt.caCert, tt.now)
			assert.Equal(t, tt.want, got)
		})
	}
}

func createTestProvider(t *testing.T, client kubernetes.Interface) *Provider {
	return createTestProviderWithClock(t, client, clock.RealClock{})
}

func createTestProviderWithClock(t *testing.T, client kubernetes.Interface, clock clock.Clock) *Provider {
	secretInformer := coreinformers.NewSecretInformer(client, defaultNamespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	configMapInformer := coreinformers.NewConfigMapInformer(client, defaultNamespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	go secretInformer.Run(t.Context().Done())
	go configMapInformer.Run(t.Context().Done())
	secretLister := corelisters.NewSecretLister(secretInformer.GetIndexer())
	configMapLister := corelisters.NewConfigMapLister(configMapInformer.GetIndexer())

	cache.WaitForCacheSync(t.Context().Done(), secretInformer.HasSynced, configMapInformer.HasSynced)

	p := &Provider{
		namespace:            defaultNamespace,
		k8sClient:            client,
		clock:                clock,
		caSecretInformer:     secretInformer,
		clientSecretInformer: secretInformer,
		caConfigMapInformer:  configMapInformer,

		caSecretLister:     secretLister,
		clientSecretLister: secretLister,
		caConfigMapLister:  configMapLister,
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

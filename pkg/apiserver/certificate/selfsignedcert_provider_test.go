// Copyright 2024 Antrea Authors
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
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/util/env"
)

const (
	testServiceName     = "svc-foo"
	testPairName        = "foo"
	testSecretName      = "secret-foo"
	testSecretNamespace = "ns-foo"
)

var (
	// self-signed certs valid for one year.
	testOneYearCert, testOneYearKey, _   = certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", loopbackAddresses, nil, "")
	testOneYearCert2, testOneYearKey2, _ = certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", loopbackAddresses, nil, "")
	testOneYearCert3, testOneYearKey3, _ = certutil.GenerateSelfSignedCertKeyWithFixtures("localhost", loopbackAddresses, nil, "")
)

func newTestSelfSignedCertProvider(t *testing.T, client *fakeclientset.Clientset, tlsSecretName string, minValidDuration time.Duration, options ...providerOption) *selfSignedCertProvider {
	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	caConfig := &CAConfig{
		TLSSecretName:     tlsSecretName,
		SelfSignedCertDir: t.TempDir(),
		MinValidDuration:  minValidDuration,
		ServiceName:       testServiceName,
		PairName:          testPairName,
	}
	p, err := newSelfSignedCertProvider(client, secureServing, caConfig, options...)
	require.NoError(t, err)
	return p
}

func TestSelfSignedCertProviderShouldRotateCertificate(t *testing.T) {
	tests := []struct {
		name             string
		certBytes        []byte
		minValidDuration time.Duration
		shouldRotate     bool
	}{
		{
			name:             "empty cert should rotate",
			minValidDuration: time.Hour,
			shouldRotate:     true,
		},
		{
			name:             "invalid cert should rotate",
			minValidDuration: time.Hour,
			certBytes:        []byte("invalid cert"),
			shouldRotate:     true,
		},
		{
			name:             "minValidDuration greater than maxAge",
			minValidDuration: time.Hour * 24 * 366,
			certBytes:        testOneYearCert,
			shouldRotate:     true,
		},
		{
			name:             "maxAge greater than minValidDuration",
			minValidDuration: time.Hour * 24 * 300,
			certBytes:        testOneYearCert,
			shouldRotate:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestSelfSignedCertProvider(t, fakeclientset.NewSimpleClientset(), "", tt.minValidDuration)
			assert.Equal(t, tt.shouldRotate, p.shouldRotateCertificate(tt.certBytes))
		})
	}
}

func TestSelfSignedCertProviderRotate(t *testing.T) {
	t.Setenv(env.PodNamespaceEnvKey, testSecretNamespace)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := fakeclientset.NewSimpleClientset()
	fakeClock := clocktesting.NewFakeClock(time.Now())
	p := newTestSelfSignedCertProvider(t, client, testSecretName, time.Hour*24*90, withClock(fakeClock))
	certInFile, err := os.ReadFile(p.secureServing.ServerCert.CertKey.CertFile)
	require.NoError(t, err)
	keyInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.KeyFile)
	require.NoError(t, err)
	gotSecret, err := client.CoreV1().Secrets(testSecretNamespace).Get(ctx, testSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testSecretNamespace, Name: testSecretName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certInFile,
			corev1.TLSPrivateKeyKey: keyInFile,
		},
	}, gotSecret, "Secret doesn't match")

	go p.Run(ctx, 1)

	// Update the Secret, it should update the serving one.
	gotSecret.Data[corev1.TLSCertKey] = testOneYearCert
	gotSecret.Data[corev1.TLSPrivateKeyKey] = testOneYearKey
	client.CoreV1().Secrets(gotSecret.Namespace).Update(ctx, gotSecret, metav1.UpdateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, testOneYearCert, p.CurrentCABundleContent())
		certInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.CertFile)
		keyInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.KeyFile)
		assert.Equal(c, testOneYearCert, certInFile)
		assert.Equal(c, testOneYearKey, keyInFile)
	}, 2*time.Second, 50*time.Millisecond)

	// Trigger a resync, nothing should change.
	p.enqueue()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, testOneYearCert, p.CurrentCABundleContent())
	certInFile, _ = os.ReadFile(p.secureServing.ServerCert.CertKey.CertFile)
	keyInFile, _ = os.ReadFile(p.secureServing.ServerCert.CertKey.KeyFile)
	assert.Equal(t, testOneYearCert, certInFile)
	assert.Equal(t, testOneYearKey, keyInFile)

	// Step 280 days, the cert should be rotated.
	fakeClock.Step(time.Hour * 24 * 280)
	p.enqueue()
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotEqual(c, testOneYearCert, p.CurrentCABundleContent())
		certInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.CertFile)
		keyInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.KeyFile)
		assert.NotEqual(c, testOneYearCert, certInFile)
		assert.NotEqual(c, testOneYearKey, keyInFile)
		gotSecret, err := client.CoreV1().Secrets(testSecretNamespace).Get(ctx, testSecretName, metav1.GetOptions{})
		require.NoError(c, err)
		assert.NotEqual(c, map[string][]byte{
			corev1.TLSCertKey:       testOneYearCert,
			corev1.TLSPrivateKeyKey: testOneYearKey,
		}, gotSecret.Data, "Secret should not match")
	}, 2*time.Second, 50*time.Millisecond)
}

func TestSelfSignedCertProviderRun(t *testing.T) {
	t.Setenv(env.PodNamespaceEnvKey, testSecretNamespace)
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testSecretNamespace, Name: testSecretName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       testOneYearCert,
			corev1.TLSPrivateKeyKey: testOneYearKey,
		},
	}
	testSecret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testSecretNamespace, Name: testSecretName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       testOneYearCert2,
			corev1.TLSPrivateKeyKey: testOneYearKey2,
		},
	}
	testSecret3 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testSecretNamespace, Name: testSecretName},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       testOneYearCert3,
			corev1.TLSPrivateKeyKey: testOneYearKey3,
		},
	}

	tests := []struct {
		name             string
		tlsSecretName    string
		existingSecret   *corev1.Secret
		updatedSecret    *corev1.Secret
		expectedSecret   *corev1.Secret
		expectedCert     []byte
		expectedKey      []byte
		minValidDuration time.Duration
		shouldRotate     bool
	}{
		{
			name:             "should use TLS from secret",
			tlsSecretName:    testSecretName,
			existingSecret:   testSecret,
			expectedSecret:   testSecret,
			minValidDuration: time.Hour * 24 * 90,
			expectedCert:     testOneYearCert,
			expectedKey:      testOneYearKey,
		},
		{
			name:             "should rotate TLS and update secret",
			tlsSecretName:    testSecretName,
			existingSecret:   testSecret,
			expectedSecret:   testSecret2,
			minValidDuration: time.Hour * 24 * 370,
			expectedCert:     testOneYearCert2,
			expectedKey:      testOneYearKey2,
		},
		{
			name:             "should generate TLS and update secret when secret is empty",
			tlsSecretName:    testSecretName,
			expectedSecret:   testSecret2,
			minValidDuration: time.Hour * 24 * 90,
			expectedCert:     testOneYearCert2,
			expectedKey:      testOneYearKey2,
		},
		{
			name:          "should generate TLS and update secret when secret is invalid",
			tlsSecretName: testSecretName,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testSecretNamespace, Name: testSecretName},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("invalid-cert"),
					corev1.TLSPrivateKeyKey: []byte("invalid-key"),
				},
			},
			expectedSecret:   testSecret2,
			minValidDuration: time.Hour * 24 * 90,
			expectedCert:     testOneYearCert2,
			expectedKey:      testOneYearKey2,
		},
		{
			name:             "should use updated secret after it's updated",
			tlsSecretName:    testSecretName,
			existingSecret:   testSecret,
			updatedSecret:    testSecret3,
			minValidDuration: time.Hour * 24 * 90,
			expectedSecret:   testSecret3,
			expectedCert:     testOneYearCert3,
			expectedKey:      testOneYearKey3,
		},
		{
			name:             "should generate TLS",
			minValidDuration: time.Hour * 24 * 90,
			expectedCert:     testOneYearCert2,
			expectedKey:      testOneYearKey2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var objs []runtime.Object
			if tt.existingSecret != nil {
				objs = append(objs, tt.existingSecret)
			}
			client := fakeclientset.NewSimpleClientset(objs...)
			// mock the generateSelfSignedCertKey fuction
			generateSelfSignedCertKey := func(_ string, _ []net.IP, _ []string) ([]byte, []byte, error) {
				return testOneYearCert2, testOneYearKey2, nil
			}
			p := newTestSelfSignedCertProvider(t, client, tt.tlsSecretName, tt.minValidDuration, withGenerateSelfSignedCertKeyFn(generateSelfSignedCertKey))
			go p.Run(ctx, 1)
			if tt.updatedSecret != nil {
				client.CoreV1().Secrets(tt.updatedSecret.Namespace).Update(ctx, tt.updatedSecret, metav1.UpdateOptions{})
			}
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				if tt.expectedSecret != nil {
					gotSecret, _ := client.CoreV1().Secrets(tt.expectedSecret.Namespace).Get(ctx, tt.expectedSecret.Name, metav1.GetOptions{})
					assert.Equal(c, tt.expectedSecret, gotSecret, "Secret doesn't match")
				}
				assert.Equal(c, tt.expectedCert, p.CurrentCABundleContent(), "CA bundle doesn't match")
				certInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.CertFile)
				keyInFile, _ := os.ReadFile(p.secureServing.ServerCert.CertKey.KeyFile)
				assert.Equal(c, tt.expectedCert, certInFile)
				assert.Equal(c, tt.expectedKey, keyInFile)
			}, 2*time.Second, 50*time.Millisecond)
		})
	}
}

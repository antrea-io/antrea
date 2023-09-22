// Copyright 2022 Antrea Authors
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

package ipseccertificate

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"
	testingclock "k8s.io/utils/clock/testing"

	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

const fakeNodeName = "fake-node-1"

type fakeController struct {
	*Controller
	mockController   *gomock.Controller
	mockBridgeClient *ovsconfigtest.MockOVSBridgeClient
	rawCAcert        []byte
	caCert           *x509.Certificate
	caKey            crypto.Signer
}

func newFakeController(t *testing.T, clock clock.WithTicker) *fakeController {
	mockController := gomock.NewController(t)
	mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(mockController)
	fakeClient := fake.NewSimpleClientset()
	listCSRAction := k8stesting.NewRootListAction(certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), certificatesv1.SchemeGroupVersion.WithKind("CertificateSigningRequest"), metav1.ListOptions{})

	// add an reactor to fill the Name and UID in the Create request.
	fakeClient.PrependReactor("create", "certificatesigningrequests", k8stesting.ReactionFunc(
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			csr := action.(k8stesting.CreateAction).GetObject().(*certificatesv1.CertificateSigningRequest)
			if csr.ObjectMeta.GenerateName != "" {
				csr.ObjectMeta.Name = fmt.Sprintf("%s%s", csr.ObjectMeta.GenerateName, utilrand.String(8))
				csr.ObjectMeta.GenerateName = ""
				csr.UID = uuid.NewUUID()
			}
			return false, csr, nil
		}),
	)
	// add an reactor to honor the fieldsSelector in the List request.
	fakeClient.PrependReactor("list", "certificatesigningrequests", func(action k8stesting.Action) (bool, runtime.Object, error) {
		var csrList *certificatesv1.CertificateSigningRequestList
		// list CSRs using the original reactors.
		for _, reactor := range fakeClient.Fake.ReactionChain[1:] {
			if !reactor.Handles(listCSRAction) {
				continue
			}
			handled, ret, err := reactor.React(listCSRAction)
			if !handled {
				continue
			}
			if err != nil {
				return false, nil, err
			}
			csrList = ret.(*certificatesv1.CertificateSigningRequestList)
		}
		actionList, ok := action.(k8stesting.ListActionImpl)
		if !ok {
			return true, nil, fmt.Errorf("unexpected action type, expected %T, got %T", k8stesting.ListActionImpl{}, action)
		}
		listFieldsSelector := actionList.GetListRestrictions().Fields
		var filtered []certificatesv1.CertificateSigningRequest
		for _, c := range csrList.Items {
			csrSpecificFieldsSet := make(fields.Set)
			csrSpecificFieldsSet["metadata.name"] = c.Name
			if listFieldsSelector.Matches(csrSpecificFieldsSet) {
				filtered = append(filtered, c)
			}
		}
		return true, &certificatesv1.CertificateSigningRequestList{
			Items: filtered,
		}, nil
	})

	originDefaultPath := defaultCertificatesPath
	cfg := certutil.Config{
		CommonName:   "antrea-ipsec-ca",
		Organization: []string{"antrea.io"},
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCA, err := certutil.NewSelfSignedCACert(cfg, key)
	require.NoError(t, err)
	tempDir, err := os.MkdirTemp("", "antrea-ipsec-test")
	require.NoError(t, err)
	defaultCertificatesPath = tempDir
	defer func() {
		defaultCertificatesPath = originDefaultPath
	}()
	caData, err := certutil.EncodeCertificates(rootCA)
	require.NoError(t, err)
	err = certutil.WriteCert(filepath.Join(defaultCertificatesPath, "ca", "ca.crt"), caData)
	require.NoError(t, err)

	c := newIPSecCertificateControllerWithCustomClock(fakeClient, mockOVSBridgeClient, fakeNodeName, clock)
	return &fakeController{
		Controller:       c,
		mockController:   mockController,
		mockBridgeClient: mockOVSBridgeClient,
		rawCAcert:        caData,
		caCert:           rootCA,
		caKey:            key,
	}
}

func TestController_syncConfigurations(t *testing.T) {
	t.Run("rotate certificate if current certificates are empty", func(t *testing.T) {
		fakeController := newFakeController(t, clock.RealClock{})
		ch := make(chan struct{})
		fakeController.rotateCertificate = func() (*certificateKeyPair, error) {
			close(ch)
			return nil, fmt.Errorf("unable to rotate certificate")
		}
		err := fakeController.syncConfigurations()
		assert.Error(t, err)
		assert.Nil(t, fakeController.certificateKeyPair)
		<-ch
	})
	t.Run("should not touch existing certificate if rotate certificate failed", func(t *testing.T) {
		fakeController := newFakeController(t, clock.RealClock{})
		defer fakeController.mockController.Finish()
		fakeController.certificateKeyPair = &certificateKeyPair{
			certificatePath: "cert.crt",
			privateKeyPath:  "key.key",
		}
		ch := make(chan struct{})
		fakeController.rotateCertificate = func() (*certificateKeyPair, error) {
			close(ch)
			return nil, fmt.Errorf("unable to rotate certificate")
		}
		err := fakeController.syncConfigurations()
		assert.Error(t, err)
		assert.NotNil(t, fakeController.certificateKeyPair)
		assert.Equal(t, "cert.crt", fakeController.certificateKeyPair.certificatePath)
		assert.Equal(t, "key.key", fakeController.certificateKeyPair.privateKeyPath)
		<-ch
	})
	t.Run("should clean up new certificate if it is not valid", func(t *testing.T) {
		fakeController := newFakeController(t, clock.RealClock{})
		defer fakeController.mockController.Finish()
		certPath := filepath.Join(fakeController.certificateFolderPath, "cert-1.crt")
		keyPath := filepath.Join(fakeController.certificateFolderPath, "key-1.key")
		ch := make(chan struct{})
		fakeController.rotateCertificate = func() (*certificateKeyPair, error) {
			close(ch)
			require.NoError(t, os.WriteFile(certPath, nil, 0600))
			require.NoError(t, os.WriteFile(keyPath, nil, 0400))
			return &certificateKeyPair{
				certificatePath: certPath,
				privateKeyPath:  keyPath,
			}, nil
		}
		err := fakeController.syncConfigurations()
		assert.Error(t, err)
		_, err = os.Stat(certPath)
		assert.True(t, os.IsNotExist(err))
		_, err = os.Stat(keyPath)
		assert.True(t, os.IsNotExist(err))
		<-ch
	})
	t.Run("request and configure new certificates", func(t *testing.T) {
		ch := make(chan struct{})
		defer close(ch)
		fakeController := newFakeController(t, clock.RealClock{})
		defer fakeController.mockController.Finish()
		assert.Equal(t, 0, fakeController.queue.Len())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signCh := make(chan struct{})
		watcher, err := fakeController.kubeClient.CertificatesV1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		defer func() {
			<-signCh
		}()
		defer watcher.Stop()
		// start a fake signer in background to sign CSRs.
		go func() {
			defer close(signCh)
			for ev := range watcher.ResultChan() {
				switch ev.Type {
				case watch.Added:
					csr, ok := ev.Object.(*certificatesv1.CertificateSigningRequest)
					assert.True(t, ok)
					signCSR(t, fakeController, csr, time.Hour*24)
				}
			}
		}()
		originalRotateCertificate := fakeController.rotateCertificate
		newCertDst := filepath.Join(fakeController.certificateFolderPath, "newcert.crt")
		newKeyDst := filepath.Join(fakeController.certificateFolderPath, "newkey.key")
		fakeController.rotateCertificate = func() (*certificateKeyPair, error) {
			pair, err := originalRotateCertificate()
			assert.NoError(t, err)
			os.Link(pair.certificatePath, newCertDst)
			os.Link(pair.privateKeyPath, newKeyDst)
			pair.certificatePath = newCertDst
			pair.privateKeyPath = newKeyDst
			return pair, nil
		}
		// should configure OVS properly in syncConfigurations()
		expectedOVSConfig := map[string]interface{}{
			"certificate": newCertDst,
			"private_key": newKeyDst,
			"ca_cert":     caCertificatePath,
		}
		fakeController.mockBridgeClient.EXPECT().UpdateOVSOtherConfig(expectedOVSConfig)
		// syncConfigurations should not block and get signed certificates from CSR successfully.
		err = fakeController.syncConfigurations()
		assert.NoError(t, err)
		list, err := fakeController.kubeClient.CertificatesV1().CertificateSigningRequests().List(context.TODO(), metav1.ListOptions{})
		require.NoError(t, err)
		assert.Len(t, list.Items, 1)
		assert.NotEmpty(t, fakeController.caPath)

		rotationDeadline := fakeController.certificateKeyPair.nextRotationDeadline()
		assert.False(t, rotationDeadline.IsZero())
		fakeController.rotateCertificate = func() (*certificateKeyPair, error) {
			t.Error("unexpected call rotateCertificate")
			return nil, nil
		}
		fakeController.mockBridgeClient.EXPECT().UpdateOVSOtherConfig(expectedOVSConfig)
		// syncConfigurations again should not request new certificates.
		err = fakeController.syncConfigurations()
		assert.NoError(t, err)
		// rotation deadline should not be changed.
		assert.Equal(t, fakeController.certificateKeyPair.nextRotationDeadline(), rotationDeadline)
	})
}

func TestController_RotateCertificates(t *testing.T) {
	// It is important to truncate to the second, because the accuracy of notAfter in the
	// certificate is at the second level. If we don't, the certificate may actually be rotated
	// before 7s.
	// We use a time in the future (1 hour), because newFakeController will create self-signed
	// root certificates using the wall-clock time. We want to make sure that the root
	// certificates are valid for this virtual time.
	now := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	fakeClock := testingclock.NewFakeClock(now)
	fakeController := newFakeController(t, fakeClock)
	defer fakeController.mockController.Finish()
	assert.Equal(t, 0, fakeController.queue.Len())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher, err := fakeController.kubeClient.CertificatesV1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	defer watcher.Stop()
	require.NoError(t, err)
	// start a fake signer in background to sign CSRs.
	signCh := make(chan struct{})
	go func() {
		defer close(signCh)
		counter := 0
		for ev := range watcher.ResultChan() {
			switch ev.Type {
			case watch.Added:
				csr, ok := ev.Object.(*certificatesv1.CertificateSigningRequest)
				assert.True(t, ok)
				// issue a certificate with lifetime of 10 seconds.
				signCSR(t, fakeController, csr, time.Second*10)
				signCh <- struct{}{}
				counter++
				if counter == 2 {
					return
				}
			}
		}
	}()
	fakeController.mockBridgeClient.EXPECT().GetOVSOtherConfig().Times(1)
	fakeController.mockBridgeClient.EXPECT().UpdateOVSOtherConfig(gomock.Any()).MinTimes(1)
	stopCh := make(chan struct{})
	defer close(stopCh)
	go fakeController.Run(stopCh)
	<-signCh
	// the rotation interval is determined by nextRotationDeadline as notBefore + (notAfter -
	// notBefore) * k, where k is >= 0.7 and <= 0.9. We would therefore expect the rotation
	// interval to be between [7, 9] seconds.
	fakeClock.SetTime(now.Add(time.Millisecond * 6999))
	select {
	case <-signCh:
		t.Fatal("CSR should not be signed before the rotation deadline")
	case <-time.After(2 * time.Second):
	}
	fakeClock.SetTime(now.Add(time.Second * 9))
	// wait for the signer to finish signing two CSRs.
	select {
	case <-signCh:
		break
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout while waiting for second CSR to be signed")
	}
	list, err := fakeController.kubeClient.CertificatesV1().CertificateSigningRequests().List(context.TODO(), metav1.ListOptions{})
	assert.NoError(t, err)
	assert.Len(t, list.Items, 2)
}

func newIPsecCertTemplate(t *testing.T, nodeName string, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   nodeName,
			Organization: []string{"antrea.io"},
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SerialNumber:          big.NewInt(12345),
		DNSNames:              []string{nodeName},
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageIPSECTunnel,
		},
	}
}

func createCertificate(
	t *testing.T,
	nodeName string,
	caCert *x509.Certificate,
	caKey crypto.Signer,
	publicKey crypto.PublicKey,
	currentTime time.Time,
	expirationDuration time.Duration,
) []byte {
	template := newIPsecCertTemplate(t, nodeName, currentTime, currentTime.Add(expirationDuration))
	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	require.NoError(t, err)
	certs, err := x509.ParseCertificates(derBytes)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	encoded, err := certutil.EncodeCertificates(certs...)
	require.NoError(t, err)
	return encoded
}

func signCSR(
	t *testing.T,
	controller *fakeController,
	csr *certificatesv1.CertificateSigningRequest,
	expirationDuration time.Duration,
) {
	assert.Empty(t, csr.Status.Certificate)
	block, remain := pem.Decode(csr.Spec.Request)
	assert.Empty(t, remain)
	req, err := x509.ParseCertificateRequest(block.Bytes)
	assert.NoError(t, err)

	// Wait one second as the fake clientset doesn't support watching with specific resourceVersion.
	// Otherwise the update event would be missed by the watcher used in csrutil.WaitForCertificate()
	// if it happens to be generated in-between the List and Watch calls.
	time.Sleep(1 * time.Second)

	newCert := createCertificate(t, req.Subject.CommonName, controller.caCert,
		controller.caKey, req.PublicKey, controller.clock.Now(), expirationDuration)
	toUpdate := csr.DeepCopy()
	toUpdate.Status.Conditions = append(toUpdate.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:   certificatesv1.CertificateApproved,
		Status: corev1.ConditionTrue,
	})
	toUpdate, err = controller.kubeClient.CertificatesV1().CertificateSigningRequests().
		UpdateApproval(context.TODO(), csr.Name, toUpdate, metav1.UpdateOptions{})
	assert.NoError(t, err)

	toUpdate = toUpdate.DeepCopy()
	toUpdate.Status.Certificate = newCert
	_, err = controller.kubeClient.CertificatesV1().CertificateSigningRequests().
		UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	assert.NoError(t, err)
	t.Logf("Sign CSR %q successfully", csr.Name)
}

func Test_jitteryDuration(t *testing.T) {
	tests := []struct {
		name                                   string
		duration                               time.Duration
		expectedLowerBound, expectedUpperBound time.Duration
	}{
		{
			name:               "10 seconds",
			duration:           10 * time.Second,
			expectedLowerBound: 7 * time.Second,
			expectedUpperBound: 9 * time.Second,
		}, {
			name:               "10 minutes",
			duration:           10 * time.Minute,
			expectedLowerBound: 7 * time.Minute,
			expectedUpperBound: 9 * time.Minute,
		},
		{
			name:               "10 hours",
			duration:           10 * time.Hour,
			expectedLowerBound: 7 * time.Hour,
			expectedUpperBound: 9 * time.Hour,
		},
		{
			name:               "10 days",
			duration:           10 * time.Hour * 24,
			expectedLowerBound: 7 * time.Hour * 24,
			expectedUpperBound: 9 * time.Hour * 24,
		},
		{
			name:               "100 days",
			duration:           100 * time.Hour * 24,
			expectedLowerBound: 70 * time.Hour * 24,
			expectedUpperBound: 90 * time.Hour * 24,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := jitteryDuration(tt.duration)
			assert.LessOrEqual(t, tt.expectedLowerBound, d)
			assert.LessOrEqual(t, d, tt.expectedUpperBound)
		})
	}
}

func Test_certificateKeyPair_nextRotationDeadline(t *testing.T) {
	tests := []struct {
		name                       string
		notBefore, notAfter        string
		deadlineStart, deadlineEnd string
	}{
		{
			name:          "10 hours certificate should be rotated at [notBefore + 7h, notBefore + 9h]",
			notBefore:     "2022-05-20T00:00:00Z",
			notAfter:      "2022-05-20T10:00:00Z",
			deadlineStart: "2022-05-20T07:00:00Z",
			deadlineEnd:   "2022-05-20T09:00:00Z",
		},
		{
			name:          "10 days certificate should be rotated at [notBefore + 7d, notBefore + 9d]",
			notBefore:     "2022-05-20T00:00:00Z",
			notAfter:      "2022-05-30T00:00:00Z",
			deadlineStart: "2022-05-27T00:00:00Z",
			deadlineEnd:   "2022-05-29T00:00:00Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, err := time.Parse(time.RFC3339, tt.notBefore)
			require.NoError(t, err)
			after, err := time.Parse(time.RFC3339, tt.notAfter)
			require.NoError(t, err)
			pair := &certificateKeyPair{
				certificate: []*x509.Certificate{{
					NotBefore: before,
					NotAfter:  after,
				}},
			}
			deadline := pair.nextRotationDeadline()
			expectedDeadlineStart, err := time.Parse(time.RFC3339, tt.deadlineStart)
			require.NoError(t, err)
			expectedDeadlineEnd, err := time.Parse(time.RFC3339, tt.deadlineEnd)
			require.NoError(t, err)
			assert.False(t, deadline.Before(expectedDeadlineStart))
			assert.False(t, expectedDeadlineEnd.Before(deadline))
			newDeadline := pair.nextRotationDeadline()
			assert.Equal(t, deadline, newDeadline, "rotation deadline should not change")
		})
	}
}

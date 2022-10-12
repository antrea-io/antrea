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

package certificatesigningrequest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"sync/atomic"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1informers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	csrlister "k8s.io/client-go/listers/certificates/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/util/env"
)

const (
	ipsecRootCAName               = "antrea-ipsec-ca"
	ipsecCSRSigningControllerName = "IPsecCertificateSigningRequestSigningController"
	workerItemKey                 = "key"
	rootCACertKey                 = "ca.crt"

	duration365d = time.Hour * 24 * 365
	duration10y  = duration365d * 10
)

// IPsecCSRSigningController is responsible for signing CertificateSigningRequests.
type IPsecCSRSigningController struct {
	client          clientset.Interface
	csrInformer     cache.SharedIndexInformer
	csrLister       csrlister.CertificateSigningRequestLister
	csrListerSynced cache.InformerSynced

	configMapInformer     cache.SharedIndexInformer
	configMapLister       corev1listers.ConfigMapLister
	configMapListerSynced cache.InformerSynced

	selfSignedCA bool

	// saved CertificateAuthority
	certificateAuthority atomic.Value

	queue         workqueue.RateLimitingInterface
	fixturesQueue workqueue.RateLimitingInterface
}

// certificateAuthority implements a certificate authority and used by the signing controller.
type certificateAuthority struct {
	// RawCert is an optional field to determine if signing cert/key pairs have changed
	RawCert []byte
	// RawKey is an optional field to determine if signing cert/key pairs have changed
	RawKey []byte

	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
}

func (c *certificateAuthority) signCSR(template *x509.Certificate, requestKey crypto.PublicKey) (*x509.Certificate, error) {
	if len(c.RawCert) == 0 || len(c.RawKey) == 0 {
		return nil, fmt.Errorf("certificate authority is not valid")
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, c.Certificate, requestKey, c.PrivateKey)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(derBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("expect a single certificate, got %d", len(certs))
	}
	return certs[0], nil
}

// NewIPsecCSRSigningController returns a new *IPsecCSRSigningController.
func NewIPsecCSRSigningController(client clientset.Interface, csrInformer cache.SharedIndexInformer, csrLister csrlister.CertificateSigningRequestLister, selfSignedCA bool) *IPsecCSRSigningController {

	caConfigMapInformer := corev1informers.NewFilteredConfigMapInformer(client, env.GetAntreaNamespace(), resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, func(listOptions *metav1.ListOptions) {
		listOptions.FieldSelector = fields.OneTermEqualSelector("metadata.name", ipsecRootCAName).String()
	})

	configMapLister := corev1listers.NewConfigMapLister(caConfigMapInformer.GetIndexer())

	c := &IPsecCSRSigningController{
		client:                client,
		csrInformer:           csrInformer,
		csrLister:             csrLister,
		csrListerSynced:       csrInformer.HasSynced,
		configMapInformer:     caConfigMapInformer,
		configMapLister:       configMapLister,
		configMapListerSynced: caConfigMapInformer.HasSynced,
		selfSignedCA:          selfSignedCA,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "certificateSigningRequest"),
		fixturesQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "certificateSigningRequest"),
	}

	csrInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueCertificateSigningRequest,
			UpdateFunc: func(old, cur interface{}) {
				c.enqueueCertificateSigningRequest(cur)
			},
		},
		resyncPeriod,
	)

	caConfigMapInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				c.fixturesQueue.Add(workerItemKey)
			},
			UpdateFunc: func(old, cur interface{}) {
				c.fixturesQueue.Add(workerItemKey)
			},
			DeleteFunc: func(obj interface{}) {
				c.fixturesQueue.Add(workerItemKey)
			},
		},
		resyncPeriod,
	)

	return c
}

// Run begins watching and syncing of the IPsecCSRSigningController.
func (c *IPsecCSRSigningController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", ipsecCSRSigningControllerName)
	defer klog.Infof("Shutting down %s", ipsecCSRSigningControllerName)

	go c.configMapInformer.Run(stopCh)

	cacheSyncs := []cache.InformerSynced{c.csrListerSynced, c.configMapListerSynced}
	if !cache.WaitForNamedCacheSync(ipsecCSRSigningControllerName, stopCh, cacheSyncs...) {
		return
	}
	c.fixturesQueue.Add(workerItemKey)

	go wait.Until(c.fixturesWorker, time.Second, stopCh)

	go wait.NonSlidingUntil(func() {
		if err := c.watchSecretChanges(stopCh); err != nil {
			klog.ErrorS(err, "Watch Secret error", "secret", ipsecRootCAName)
		}
	}, time.Second*10, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.csrWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *IPsecCSRSigningController) syncRootCertificateAndKey() error {
	var caBytes, caKeyBytes []byte
	caSecret, err := c.client.CoreV1().Secrets(env.GetAntreaNamespace()).Get(context.TODO(), ipsecRootCAName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		if !c.selfSignedCA {
			klog.InfoS("Self-signed CA is disabled. Ensure CA Secret exists", "name", ipsecRootCAName, "namespace", env.GetAntreaNamespace())
			return nil
		}
		caBytes, caKeyBytes, err = generateSelfSignedRootCertificate(ipsecRootCAName)
		if err != nil {
			return err
		}
		caSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ipsecRootCAName,
				Namespace: env.GetAntreaNamespace(),
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				corev1.TLSCertKey:       caBytes,
				corev1.TLSPrivateKeyKey: caKeyBytes,
			},
		}
		caSecret, err = c.client.CoreV1().Secrets(env.GetAntreaNamespace()).Create(context.TODO(), caSecret, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		klog.Info("Created Secret for self-signed IPsec root CA")
	}
	caCertificate, err := certutil.ParseCertsPEM(caSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}
	if len(caCertificate) == 0 {
		return fmt.Errorf("CA certificate is empty")
	}
	privateKey, err := keyutil.ParsePrivateKeyPEM(caSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return err
	}
	priv, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("error reading CA: key did not implement crypto.Signer")
	}
	ca := &certificateAuthority{
		RawCert:     caSecret.Data[corev1.TLSCertKey],
		RawKey:      caSecret.Data[corev1.TLSPrivateKeyKey],
		Certificate: caCertificate[0],
		PrivateKey:  priv,
	}
	c.certificateAuthority.Store(ca)
	desiredConfigMapData := map[string]string{
		rootCACertKey: string(caSecret.Data[corev1.TLSCertKey]),
	}
	caConfigMap, err := c.configMapLister.ConfigMaps(env.GetAntreaNamespace()).Get(ipsecRootCAName)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		caConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ipsecRootCAName,
				Namespace: env.GetAntreaNamespace(),
			},
			Data: desiredConfigMapData,
		}
		caConfigMap, err = c.client.CoreV1().ConfigMaps(env.GetAntreaNamespace()).Create(context.TODO(), caConfigMap, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		klog.InfoS("Created ConfigMap for self-signed IPsec root CA")
	}
	if !reflect.DeepEqual(desiredConfigMapData, caConfigMap.Data) {
		toUpdate := caConfigMap.DeepCopy()
		toUpdate.Data = desiredConfigMapData
		_, err = c.client.CoreV1().ConfigMaps(env.GetAntreaNamespace()).Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *IPsecCSRSigningController) csrWorker() {
	for c.processNextWorkItem() {
	}
}

// watchSecretChanges uses watch API directly to watch for Secret changes.
// Antrea Controller should not have List permission for Secrets.
func (c *IPsecCSRSigningController) watchSecretChanges(endCh <-chan struct{}) error {
	watcher, err := c.client.CoreV1().Secrets(env.GetAntreaNamespace()).Watch(context.TODO(), metav1.SingleObject(metav1.ObjectMeta{
		Namespace: env.GetAntreaNamespace(),
		Name:      ipsecRootCAName,
	}))
	if err != nil {
		return fmt.Errorf("failed to create Secret watcher: %v", err)
	}
	// re-queue in case of missing events before watcher starts.
	c.fixturesQueue.Add(workerItemKey)
	ch := watcher.ResultChan()
	defer watcher.Stop()
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return nil
			}
			// we do not care the actual Event.
			c.fixturesQueue.Add(workerItemKey)
		case <-endCh:
			return nil
		}
	}
}

func (c *IPsecCSRSigningController) fixturesWorker() {
	for c.processNextFixtureWorkItem() {
	}
}

func (c *IPsecCSRSigningController) enqueueCertificateSigningRequest(obj interface{}) {
	csr, ok := obj.(*certificatesv1.CertificateSigningRequest)
	if !ok {
		return
	}
	c.queue.Add(csr.Name)
}

func (c *IPsecCSRSigningController) syncCSR(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).InfoS("Finished syncing CertificateSigningRequest", "name", key, "duration", d)
	}()
	csr, err := c.csrLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if csr.Spec.SignerName != antreaapis.AntreaIPsecCSRSignerName {
		return nil
	}
	if len(csr.Status.Certificate) != 0 {
		klog.V(2).InfoS("CertificateSigningRequest is already signed", "CertificateSigningRequest", csr.Name)
		return nil
	}
	if !isCertificateRequestApproved(csr) {
		klog.V(2).InfoS("CertificateSigningRequest is not approved", "CertificateSigningRequest", csr.Name)
		return nil
	}
	req, err := decodeCertificateRequest(csr.Spec.Request)
	if err != nil {
		klog.ErrorS(err, "Failed to decode CertificateSigningRequest", "CertificateSigningRequest", csr.Name)
		return nil
	}
	template, err := newCertificateTemplate(req, csr.Spec.Usages)
	if err != nil {
		return err
	}
	currCA, ok := c.certificateAuthority.Load().(*certificateAuthority)
	if !ok || currCA == nil {
		return fmt.Errorf("certificate authority is not initialized")
	}
	signed, err := currCA.signCSR(template, req.PublicKey)
	if err != nil {
		return err
	}
	bs, err := certutil.EncodeCertificates(signed)
	if err != nil {
		return err
	}
	toUpdate := csr.DeepCopy()
	toUpdate.Status.Certificate = bs
	_, err = c.client.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func newCertificateTemplate(certReq *x509.CertificateRequest, usage []certificatesv1.KeyUsage) (*x509.Certificate, error) {
	var sn big.Int
	snBytes := make([]byte, 18)
	_, err := rand.Read(snBytes)
	if err != nil {
		return nil, err
	}
	sn.SetBytes(snBytes)
	keyUsage, extKeyUsage, err := keyUsagesFromStrings(usage)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject:               certReq.Subject,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(duration365d), // defaults to 1 year
		SerialNumber:          &sn,
		DNSNames:              certReq.DNSNames,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
	}
	return template, nil
}

func (c *IPsecCSRSigningController) processNextFixtureWorkItem() bool {
	key, quit := c.fixturesQueue.Get()
	if quit {
		return false
	}
	defer c.fixturesQueue.Done(key)
	err := c.syncRootCertificateAndKey()
	if err != nil {
		c.fixturesQueue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync root CA and private key")
		return true
	}
	c.fixturesQueue.Forget(key)
	return true
}

func (c *IPsecCSRSigningController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	err := c.syncCSR(key.(string))
	if err != nil {
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync CertificateSigningRequest", "CertificateSigningRequest", key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// generateSelfSignedRootCertificate creates self-signed CA certificates and returns the PEM encoded
// certificates and private key.
func generateSelfSignedRootCertificate(commonName string) ([]byte, []byte, error) {
	validFrom := time.Now().Add(-time.Hour) // valid an hour earlier to avoid flakes due to clock skew
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{antreaapis.AntreaOrganizationName},
		},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(duration10y),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDERBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: certutil.CertificateBlockType, Bytes: caDERBytes}); err != nil {
		return nil, nil, err
	}
	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return nil, nil, err
	}
	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}

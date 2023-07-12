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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	certutil "k8s.io/client-go/util/cert"
	csrutil "k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	controllerName = "AntreaAgentIPsecCertificateController"
	workerItemKey  = "key"
	minRetryDelay  = 5 * time.Second
	maxRetryDelay  = 60 * time.Second

	// the mount path for CA certificate in antrea-ipsec container.
	// StrongSwan will never reads CA certificates from folders other than `/etc/ipsec.d/cacerts`.
	// Though StrongSwan will automatically load CA certificates from the folder, we set the ca_path in other_configs
	// to the correct path for better consistency.
	caCertificatePath = "/etc/ipsec.d/cacerts/ca.crt"

	ovsConfigCACertificateKey = "ca_cert"
	ovsConfigPrivateKeyKey    = "private_key"
	ovsConfigCertificateKey   = "certificate"

	// certificateWaitTimeout controls the amount of time we wait for certificate approval in
	// one iteration.
	certificateWaitTimeout = 15 * time.Minute
)

var defaultCertificatesPath = "/var/run/openvswitch"

// Controller is responsible for requesting certificates by CertificateSigningRequest and configure them to OVS
type Controller struct {
	kubeClient      clientset.Interface
	ovsBridgeClient ovsconfig.OVSBridgeClient
	nodeName        string
	queue           workqueue.RateLimitingInterface

	rotateCertificate  func() (*certificateKeyPair, error)
	certificateKeyPair *certificateKeyPair

	clock clock.WithTicker

	// caPath and is initialized with NewIPSecCertificateController and should not
	// be changed once Controller starts.
	caPath string
	// certificateFolderPath is the folder to store private keys and issued certificates.
	// defaults to defaultCertificatesPath.
	certificateFolderPath string

	syncedOnce uint32
}

// Manager is an interface to track the status of the IPsec certificate controller.
type Manager interface {
	HasSynced() bool
}

var _ Manager = (*Controller)(nil)

func NewIPSecCertificateController(
	kubeClient clientset.Interface,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	nodeName string,
) *Controller {
	return newIPSecCertificateControllerWithCustomClock(kubeClient, ovsBridgeClient, nodeName, clock.RealClock{})
}

func newIPSecCertificateControllerWithCustomClock(kubeClient clientset.Interface,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	nodeName string, clock clock.WithTicker) *Controller {
	controller := &Controller{
		kubeClient:      kubeClient,
		ovsBridgeClient: ovsBridgeClient,
		nodeName:        nodeName,
		queue: workqueue.NewRateLimitingQueueWithDelayingInterface(workqueue.NewDelayingQueueWithCustomClock(clock, "IPsecCertificateController"),
			workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay)),
		clock:                 clock,
		caPath:                filepath.Join(defaultCertificatesPath, "ca", "ca.crt"),
		certificateFolderPath: defaultCertificatesPath,
	}
	controller.rotateCertificate = controller.newCertificateKeyPair
	return controller
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)
	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.ErrorS(nil, "Unexpected object in work queue", "object", obj)
		return true
	} else if err := c.syncConfigurations(); err == nil {
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing IPSec certificates, requeuing")
	}
	return true
}

type certificateKeyPair struct {
	caCertificate    []*x509.Certificate
	certificate      []*x509.Certificate
	privateKey       crypto.Signer
	certificatePath  string
	privateKeyPath   string
	rotationDeadline time.Time
}

func (pair *certificateKeyPair) validate(clock clock.Clock) error {
	if pair == nil {
		return fmt.Errorf("certificate and key pair is nil")
	}
	if len(pair.caCertificate) == 0 {
		return fmt.Errorf("CA certificate is empty")
	}
	if len(pair.certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}
	if pair.privateKey == nil {
		return fmt.Errorf("private key is empty")
	}
	roots := x509.NewCertPool()
	for _, r := range pair.caCertificate {
		roots.AddCert(r)
	}
	certificate := pair.certificate[0]
	verifyOptions := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageIPSECTunnel,
		},
		CurrentTime: clock.Now(),
	}
	if _, err := certificate.Verify(verifyOptions); err != nil {
		return err
	}
	switch pub := certificate.PublicKey.(type) {
	//TODO: support key types other than RSA such as *ecdsa.PublicKey.
	case *rsa.PublicKey:
		priv, ok := pair.privateKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fmt.Errorf("private key does not match public key")
		}
	default:
		return fmt.Errorf("unrecognized certificate public key type")
	}
	return nil
}

// cleanup deletes the files of certificate and private key.
func (pair *certificateKeyPair) cleanup() {
	if pair.certificatePath != "" {
		// Delete the old certificate file.
		if err := os.Remove(pair.certificatePath); err != nil && !os.IsNotExist(err) {
			klog.ErrorS(err, "Failed to delete old certificate", "file", pair.certificatePath)
		}
	}
	if pair.privateKeyPath != "" {
		// Delete the old private key file.
		if err := os.Remove(pair.privateKeyPath); err != nil && !os.IsNotExist(err) {
			klog.ErrorS(err, "Failed to delete old private key", "file", pair.privateKeyPath)
		}
	}
}

// jitteryDuration returns a duration in [totalDuration * 0.7, totalDuration * 0.9].
func jitteryDuration(totalDuration time.Duration) time.Duration {
	// wait.Jitter returns a duration in [totalDuration, totalDuration * 1.2].
	return wait.Jitter(time.Duration(totalDuration), 0.2) - time.Duration(float64(totalDuration)*0.3)
}

// nextRotationDeadline returns a value for the threshold at which the
// current certificate should be rotated, 80%+/-10% of the expiration of the
// certificate. The deadline will not change once calculated.
// This function is not thread-safe.
func (pair *certificateKeyPair) nextRotationDeadline() time.Time {
	// Return the previous calculated rotation deadline if applicable.
	if !pair.rotationDeadline.IsZero() {
		return pair.rotationDeadline
	}
	notAfter := pair.certificate[0].NotAfter
	totalDuration := notAfter.Sub(pair.certificate[0].NotBefore)
	deadline := pair.certificate[0].NotBefore.Add(jitteryDuration(totalDuration))
	klog.InfoS("Calculated certificate rotation deadline", "expiration", notAfter, "deadline", deadline)
	pair.rotationDeadline = deadline
	return deadline
}

func loadCertAndKeyFromFiles(caPath, certPath, keyPath string) (*certificateKeyPair, error) {
	ca, err := loadRootCA(caPath)
	if err != nil {
		return nil, err
	}
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
	}
	pair := &certificateKeyPair{
		certificatePath: certPath,
		privateKeyPath:  keyPath,
		caCertificate:   ca,
		certificate:     cert,
		privateKey:      key,
	}
	return pair, nil
}

func (c *Controller) syncConfigurations() error {
	startTime := c.clock.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).InfoS("Finished syncing IPsec certificate configurations", "duration", d)
	}()

	var deadline time.Time
	// Validate the existing certificate and key pair.
	if err := c.certificateKeyPair.validate(c.clock); err != nil {
		klog.ErrorS(err, "Verifying current certificate configurations failed")
		deadline = c.clock.Now()
	} else {
		deadline = c.certificateKeyPair.nextRotationDeadline()
	}
	// Current certificate is about to expire.
	if sleepInterval := deadline.Sub(c.clock.Now()); sleepInterval <= 0 {
		klog.InfoS("Start rotating IPsec certificate")
		newCertKeyPair, err := c.rotateCertificate()
		if err != nil {
			return fmt.Errorf("failed to rotate certificate: %w", err)
		}
		if err := newCertKeyPair.validate(c.clock); err != nil {
			newCertKeyPair.cleanup()
			return fmt.Errorf("failed to validate new certificate: %w", err)
		}
		// Clean up old certificate and key pair.
		if c.certificateKeyPair != nil {
			c.certificateKeyPair.cleanup()
		}
		// Save the known good certificate and key pair.
		c.certificateKeyPair = newCertKeyPair
		// Calculate the rotation deadline of new certificate.
		deadline = c.certificateKeyPair.nextRotationDeadline()
	}
	// Re-queue after the interval to renew the certificate.
	addAfter := deadline.Sub(c.clock.Now())
	c.queue.AddAfter(workerItemKey, addAfter)
	// Sync OVS bridge configurations.
	if err := c.syncOVSConfigurations(c.certificateKeyPair.certificatePath,
		c.certificateKeyPair.privateKeyPath, caCertificatePath); err != nil {
		return err
	}
	atomic.StoreUint32(&c.syncedOnce, 1)
	return nil
}

// HasSynced implements the Manager interface.
func (c *Controller) HasSynced() bool {
	// returns true if the controller has configured certificate successfully
	// at least once.
	return atomic.LoadUint32(&c.syncedOnce) == 1
}

func loadRootCA(caPath string) ([]*x509.Certificate, error) {
	pemBlock, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	certs, err := certutil.ParseCertsPEM(pemBlock)
	if err != nil {
		return nil, fmt.Errorf("error reading root CA %s: %w", caPath, err)
	}
	return certs, nil
}

func newRSAPrivateKey() (crypto.Signer, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new RSA private key: %v", err)
	}
	bs, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	return key, bs, nil
}

func loadPrivateKey(privateKeyPath string) (crypto.Signer, error) {
	var keyPEMBytes []byte
	_, err := os.Stat(privateKeyPath)
	if err == nil {
		// Load the private key contents from file.
		keyPEMBytes, err = os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %v", privateKeyPath, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat key file %s: %v", privateKeyPath, err)
	}
	if len(keyPEMBytes) > 0 {
		// Try to parse private key from existing file.
		parsed, err := keyutil.ParsePrivateKeyPEM(keyPEMBytes)
		privateKey, ok := parsed.(crypto.Signer)
		if err != nil || !ok {
			klog.ErrorS(err, "Parse key from file error", "file", privateKeyPath)
		} else {
			return privateKey, nil
		}
	}
	return nil, nil
}

func loadCertificate(certPath string) ([]*x509.Certificate, error) {
	var certPEMBytes []byte
	_, err := os.Stat(certPath)
	if err == nil {
		// Load the certificate from file.
		certPEMBytes, err = os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to stat certificate file %s: %w", certPath, err)
	}
	if len(certPEMBytes) > 0 {
		// Try to parse the certificate from the existing file.
		certificates, err := certutil.ParseCertsPEM(certPEMBytes)
		if err != nil {
			klog.ErrorS(err, "Parse certificate from file error", "file", certPath)
		} else {
			return certificates, nil
		}
	}
	return nil, nil
}

func (c *Controller) syncOVSConfigurations(certPath, keyPath, caPath string) error {
	ovsConfig := map[string]interface{}{
		ovsConfigCertificateKey:   certPath,
		ovsConfigPrivateKeyKey:    keyPath,
		ovsConfigCACertificateKey: caPath,
	}
	klog.InfoS("Updating OVS configurations for IPsec certificates")
	return c.ovsBridgeClient.UpdateOVSOtherConfig(ovsConfig)
}

func newCSR(csrNamePrefix, commonName string, privateKey crypto.Signer) (*certificatesv1.CertificateSigningRequest, error) {
	subject := &pkix.Name{
		CommonName:   commonName,
		Organization: []string{antreaapis.AntreaOrganizationName},
	}
	csrBytes, err := certutil.MakeCSR(privateKey, subject, []string{commonName}, nil)
	if err != nil {
		return nil, err
	}
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: csrNamePrefix,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrBytes,
			SignerName: antreaapis.AntreaIPsecCSRSignerName,
			Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageIPsecTunnel},
		},
	}, nil
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting " + controllerName)
	defer klog.InfoS("Shutting down " + controllerName)

	// Load the previous configured certificate path from OVS database.
	config, ovsErr := c.ovsBridgeClient.GetOVSOtherConfig()
	if ovsErr != nil {
		klog.ErrorS(ovsErr, "Failed to get OVS bridge other configs")
	}

	certificatePath := config[ovsConfigCertificateKey]
	privateKeyPath := config[ovsConfigPrivateKeyKey]
	if certificatePath != "" && privateKeyPath != "" {
		pair, err := loadCertAndKeyFromFiles(c.caPath, certificatePath, privateKeyPath)
		if err != nil {
			klog.ErrorS(err, "Failed to load IPsec certificate and private key from existing files",
				"ca", c.caPath, "cert", certificatePath, "key", privateKeyPath)
		} else {
			c.certificateKeyPair = pair
		}
	}

	c.queue.Add(workerItemKey)
	go wait.Until(c.worker, time.Second, stopCh)
	<-stopCh
}

func (c *Controller) newCertificateKeyPair() (*certificateKeyPair, error) {
	key, rawKey, err := newRSAPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new private key: %w", err)
	}
	// Always create a new CSR for certificate rotation. The old ones will be GCed automatically.
	csrNamePrefix := fmt.Sprintf("%s-", c.nodeName)
	csr, err := newCSR(csrNamePrefix, c.nodeName, key)
	if err != nil {
		return nil, err
	}
	csr, err = c.kubeClient.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csr, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), certificateWaitTimeout)
	defer cancel()
	rawCert, err := csrutil.WaitForCertificate(ctx, c.kubeClient, csr.Name, csr.UID)
	if err != nil {
		return nil, err
	}
	// Use the hash of new certificate and key as the filename suffix.
	hasher := sha256.New()
	hasher.Write(rawCert)
	hasher.Write(rawKey)
	hash := hasher.Sum(nil)
	certPath := filepath.Join(c.certificateFolderPath, fmt.Sprintf("%s-%x.crt", c.nodeName, hash[:5]))
	keyPath := filepath.Join(c.certificateFolderPath, fmt.Sprintf("%s-%x.key", c.nodeName, hash[:5]))
	if err := certutil.WriteCert(certPath, rawCert); err != nil {
		return nil, err
	}
	if err := keyutil.WriteKey(keyPath, rawKey); err != nil {
		return nil, err
	}
	klog.InfoS("Created new certificate and key for IPSec", "cert", certPath, "key", keyPath)

	return loadCertAndKeyFromFiles(c.caPath, certPath, keyPath)
}

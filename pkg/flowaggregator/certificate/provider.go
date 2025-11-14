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
	"net"
	"sync"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	clockutils "k8s.io/utils/clock"

	"antrea.io/antrea/pkg/util/env"
)

const (
	defaultNamespace = "flow-aggregator"

	maxAge           = time.Hour * 24 * 365 // one year self-signed certs
	minValidDuration = time.Hour * 24 * 90

	caConfigMapName = "flow-aggregator-ca"
	caConfigMapKey  = "ca.crt"

	// #nosec G101: false positive triggered by variable name which includes "Secret"
	caSecretName = "flow-aggregator-ca"

	// #nosec G101: false positive triggered by variable name which includes "Secret"
	clientSecretName = "flow-aggregator-client-tls"
	serviceName      = "flow-aggregator"

	secretCertKey = "tls.crt"
	secretKeyKey  = "tls.key"
)

type Provider struct {
	k8sClient      kubernetes.Interface
	clock          clockutils.Clock
	queue          workqueue.TypedRateLimitingInterface[string]
	secretInformer cache.SharedIndexInformer

	certsReadyMutex    sync.Mutex
	serverCertsSynced  atomic.Bool
	serverCertsUpdated bool

	caCertPEM     []byte
	serverCertPEM []byte
	serverKeyPEM  []byte

	flowAggregatorAddress string

	listeners []CertificateUpdateListener
}

func NewProvider(k8sClient kubernetes.Interface, flowAggregatorAddress string) *Provider {
	provider := &Provider{
		k8sClient: k8sClient,
		clock:     clockutils.RealClock{},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowAggregator",
			},
		),
	}
	namespace := getFlowAggregatorNamespace()

	// TODO: Use a shared informer with a cache.FilteringResourceEventHandler{}.
	provider.secretInformer = coreinformers.NewFilteredSecretInformer(k8sClient, namespace, 12*time.Hour,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", caSecretName).String()
		},
	)

	// We are only watching for one resource to change. As long as the CA secret changes we will
	// update both CA and server cert/key.
	provider.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { provider.queue.Add("key") },
		UpdateFunc: func(_ any, _ any) { provider.queue.Add("key") },
		DeleteFunc: func(_ any) { provider.queue.Add("key") },
	})

	return provider
}

func (p *Provider) AddListener(listener CertificateUpdateListener) {
	p.listeners = append(p.listeners, listener)
}

func (p *Provider) worker() {
	for p.processNextWorkItem() {
	}
}

func (p *Provider) processNextWorkItem() bool {
	key, quit := p.queue.Get()
	if quit {
		return false
	}
	defer p.queue.Done(key)

	p.certsReadyMutex.Lock()
	unlock := sync.OnceFunc(func() {
		p.certsReadyMutex.Unlock()
	})
	defer unlock()

	p.serverCertsUpdated = false

	caRotated, err := p.rotateCACertificate()
	if err != nil {
		klog.ErrorS(err, "failed to rotate CA certificate")
		p.queue.AddRateLimited(key)
		return true
	}

	// CA was rotated, let the informer requeue.
	if caRotated {
		klog.V(2).InfoS("CA certificate was rotated.")
		return true
	}

	caCertPEM, caKeyPEM, _, err := p.getSecret(caSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get CA secret")
			p.queue.AddRateLimited(key)
			return true
		}
	}

	if err := p.rotateClientCertificate(caCertPEM, caKeyPEM); err != nil {
		p.queue.AddRateLimited(key)
		return true
	}

	if err := syncCAConfigMap(caConfigMapName, caCertPEM, p.k8sClient); err != nil {
		if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
			klog.ErrorS(err, "failed to sync CA ConfigMap")
			p.queue.AddRateLimited(key)
			return true
		}
	}

	caCert, caKey, err := pemToCertKey(caCertPEM, caKeyPEM)
	if err != nil {
		klog.ErrorS(err, "failed to parse CA cert/key PEM")
		p.queue.AddRateLimited(key)
		return true
	}
	// The CA cert has changed, generate a new server certificate.
	serverCertPEM, serverKeyPEM, err := GenerateCertKey(caCert, caKey, p.validFrom(), true, p.flowAggregatorAddress)
	if err != nil {
		klog.ErrorS(err, "failed to generate server certs")
		p.queue.Add(key)
		return true
	}

	p.caCertPEM = caCertPEM
	p.serverCertPEM = serverCertPEM
	p.serverKeyPEM = serverKeyPEM

	klog.InfoS("Certificates and keys cached locally, notifying")
	p.serverCertsSynced.Store(true)
	p.serverCertsUpdated = true
	p.queue.Forget(key)
	unlock()

	for _, listener := range p.listeners {
		listener.CertificateUpdated()
	}
	return true
}

func (p *Provider) GetTLSConfig() (caCertPEM []byte, serverCertPEM []byte, serverKeyPEM []byte) {
	p.certsReadyMutex.Lock()
	defer p.certsReadyMutex.Unlock()
	return p.caCertPEM, p.serverCertPEM, p.serverKeyPEM
}

func (p *Provider) Run(stopCh <-chan struct{}) {
	go p.secretInformer.Run(stopCh)

	if !cache.WaitForNamedCacheSync("certificateProvider", stopCh, p.secretInformer.HasSynced) {
		return
	}

	go wait.Until(p.worker, time.Second, stopCh)
	go wait.Until(func() { p.queue.Add("key") }, 1*time.Hour, stopCh) // Check certificates every hour
	<-stopCh
}

func (p *Provider) HasSynced() bool {
	return p.serverCertsSynced.Load()
}

func (p *Provider) rotateCACertificate() (bool, error) {
	caCertPEM, _, caSecret, err := p.getSecret(caSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get CA secret")
			return false, err
		}
	}

	if !p.shouldRotateCertificate(caCertPEM) {
		return false, nil
	}

	caCertPEM, caKeyPEM, err := GenerateCACertKey(p.validFrom())
	if err != nil {
		klog.ErrorS(err, "failed to generate CA certificate")
		return false, err
	}

	err = syncCertificateSecrets(p.k8sClient, caSecretName, caCertPEM, caKeyPEM, caSecret)
	if err != nil {
		if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
			klog.ErrorS(err, "failed to sync CA Secret")
			return false, err
		}
		// Someone else updated the secret, informer will requeue.
	}

	return true, nil
}

func (p *Provider) rotateClientCertificate(caCertPEM []byte, caKeyPEM []byte) error {
	clientCertPEM, _, clientSecret, err := p.getSecret(clientSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.ErrorS(err, "failed to get client Secret")
			return err
		}
	}

	if err := verifyCertificate(caCertPEM, clientCertPEM); err != nil {
		// Client cert could not be validated by the CA, regenerate client based on CA.
		caCert, caKey, err := pemToCertKey(caCertPEM, caKeyPEM)
		if err != nil {
			return err
		}
		// The CA cert has changed, generate a client certificate.
		clientCertPEM, clientKeyPEM, err := GenerateCertKey(caCert, caKey, p.validFrom(), false, "")
		if err != nil {
			return fmt.Errorf("failed to generate client cert: %w", err)
		}
		if err := syncCertificateSecrets(p.k8sClient, clientSecretName, clientCertPEM, clientKeyPEM, clientSecret); err != nil {
			if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
				return fmt.Errorf("failed to sync client Secret: %w", err)
			}
		}

		klog.V(2).Info("Client certificates were rotated")
	}
	return nil
}

func (p *Provider) validFrom() time.Time {
	return p.clock.Now().Add(-time.Hour)
}

func (p *Provider) shouldRotateCertificate(cert []byte) bool {
	if len(cert) == 0 {
		return true
	}

	certs, err := certutil.ParseCertsPEM(cert)
	if err != nil {
		klog.ErrorS(err, "Failed to parse certificate")
		return true
	}
	remainingDuration := certs[0].NotAfter.Sub(p.clock.Now())
	if remainingDuration < minValidDuration {
		klog.InfoS("The remaining duration of the TLS certificate and key is less than min valid duration", "remaining", remainingDuration, "min", minValidDuration)
		return true
	}
	return false
}

func (p *Provider) getSecret(name string) (certPEM []byte, keyPEM []byte, secret *v1.Secret, err error) {
	namespace := getFlowAggregatorNamespace()
	res, err := p.k8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error getting Secret %s: %w", caConfigMapName, err)
	}

	certPEM, ok := res.Data[secretCertKey]
	if !ok || string(certPEM) == "" {
		return nil, nil, res, nil
	}

	keyPEM, ok = res.Data[secretKeyKey]
	if !ok || string(keyPEM) == "" {
		return nil, nil, res, nil
	}

	return certPEM, keyPEM, res, nil
}

// GenerateCACertKey creates a self-signed CA and private key pair
// encoded in PEM format. The self-signed CA can be used to generate
// leaf certificates, authenticate server and clients.
func GenerateCACertKey(validFrom time.Time) ([]byte, []byte, error) {
	// generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key for CA: %w", err)
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
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  certutil.CertificateBlockType,
		Bytes: caCert,
	})

	certBuffer := bytes.Buffer{}
	if err := pem.Encode(&certBuffer, &pem.Block{Type: certutil.CertificateBlockType, Bytes: caCert}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode CA cert to PEM format: %w", err)
	}

	keyBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyBuffer, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode CA key to PEM format: %w", err)
	}

	return certBuffer.Bytes(), keyBuffer.Bytes(), nil
}

func getFlowAggregatorNamespace() string {
	namespace := env.GetPodNamespace()
	if namespace == "" {
		namespace = defaultNamespace
	}
	return namespace
}

func getFlowAggregatorServerNames() []string {
	namespace := getFlowAggregatorNamespace()
	return []string{serviceName + "." + namespace + ".svc"}
}

func GenerateCertKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, validFrom time.Time, isServer bool, flowAggregatorAddress string) ([]byte, []byte, error) {
	var cert *x509.Certificate
	if isServer {
		cert = &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("flow-aggregator-server-certificate@%d", time.Now().Unix()),
			},
			NotBefore:   validFrom,
			NotAfter:    validFrom.Add(maxAge),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			DNSNames:    getFlowAggregatorServerNames(),
		}
		if flowAggregatorAddress != "" {
			if ip := net.ParseIP(flowAggregatorAddress); ip != nil {
				cert.IPAddresses = []net.IP{ip}
			} else {
				cert.DNSNames = append(cert.DNSNames, flowAggregatorAddress)
			}
		}
	} else {
		cert = &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("flow-aggregator-client-certificate@%d", time.Now().Unix()),
			},
			NotBefore:   validFrom,
			NotAfter:    validFrom.Add(maxAge),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}
	}
	// generate private key for certificate
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// sign the certificate using CA certificate and key
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  certutil.CertificateBlockType,
		Bytes: certBytes,
	})

	certKeyPEM := new(bytes.Buffer)
	pem.Encode(certKeyPEM, &pem.Block{
		Type:  keyutil.RSAPrivateKeyBlockType,
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM.Bytes(), certKeyPEM.Bytes(), nil
}

func syncCertificateSecrets(k8sClient kubernetes.Interface, name string, cert, key []byte, secret *v1.Secret) error {
	klog.InfoS("Syncing Secret", "name", name)
	namespace := getFlowAggregatorNamespace()

	var res *v1.Secret
	if secret == nil {
		res = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: v1.SecretTypeTLS,
		}
	} else {
		res = secret.DeepCopy()
	}

	res.Data = map[string][]byte{
		"tls.crt": cert,
		"tls.key": key,
	}
	if secret != nil {
		if _, err := k8sClient.CoreV1().Secrets(namespace).Update(context.TODO(), res, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update Secret %s: %v", clientSecretName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().Secrets(namespace).Create(context.TODO(), res, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create Secret %s: %v", clientSecretName, err)
		}
	}
	return nil
}

func syncCAConfigMap(name string, cert []byte, k8sClient kubernetes.Interface) error {
	klog.InfoS("Syncing ConfigMap", "name", name)
	namespace := getFlowAggregatorNamespace()

	var caConfigMap *v1.ConfigMap
	res, err := k8sClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), caConfigMapName, metav1.GetOptions{})
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error getting ConfigMap %s: %v", caConfigMapName, err)
		}
		exists = false
		caConfigMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      caConfigMapName,
				Namespace: namespace,
				Labels: map[string]string{
					"app": "flow-aggregator",
				},
			},
		}
	} else {
		caConfigMap = res.DeepCopy()
	}

	caConfigMap.Data = map[string]string{
		caConfigMapKey: string(cert),
	}

	if exists {
		if res.Data[caConfigMapKey] == string(cert) {
			return nil
		}
		if _, err := k8sClient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), caConfigMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating ConfigMap %s: %v", caConfigMapName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().ConfigMaps(namespace).Create(context.TODO(), caConfigMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating ConfigMap %s: %v", caConfigMapName, err)
		}
	}
	return nil
}

func verifyCertificate(caCertPEM []byte, certPEM []byte) error {
	if len(caCertPEM) == 0 || len(certPEM) == 0 {
		return fmt.Errorf("caCertPEM or certPEM missing data")
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertPEM); !ok {
		return fmt.Errorf("failed to append CA cert to pool")
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing certificate failed: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:     caCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = cert.Verify(opts)
	return err
}

func pemToCertKey(certPEM []byte, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var cert *x509.Certificate
	var key *rsa.PrivateKey

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		klog.Error(err, "failed to parse certificate")
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		klog.ErrorS(err, "failed to parse key")
		return nil, nil, err
	}

	return cert, key, nil
}

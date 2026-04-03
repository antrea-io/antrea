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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"antrea.io/antrea/v2/pkg/util/env"
)

const (
	controllerName   = "flowAggregatorCertificateProvider"
	defaultNamespace = "flow-aggregator"
	serviceName      = "flow-aggregator"

	resyncPeriod     = time.Hour * 12
	maxAge           = time.Hour * 24 * 365 // one year self-signed certs
	minValidDuration = time.Hour * 24 * 90

	caConfigMapName = "flow-aggregator-ca"
	caConfigMapKey  = "ca.crt"

	// #nosec G101: false positive triggered by variable name which includes "Secret"
	caSecretName = "flow-aggregator-ca-tls"

	// #nosec G101: false positive triggered by variable name which includes "Secret"
	clientSecretName = "flow-aggregator-client-tls"
)

type Provider struct {
	namespace string

	k8sClient kubernetes.Interface
	clock     clock.Clock
	queue     workqueue.TypedRateLimitingInterface[string]

	caSecretInformer     cache.SharedIndexInformer
	clientSecretInformer cache.SharedIndexInformer
	caConfigMapInformer  cache.SharedIndexInformer
	caSecretLister       corelisters.SecretLister
	clientSecretLister   corelisters.SecretLister
	caConfigMapLister    corelisters.ConfigMapLister

	serverTLSConfigSynced atomic.Bool
	serverTLSConfigMutex  sync.Mutex
	caCertPEM             []byte
	serverCertPEM         []byte
	serverKeyPEM          []byte

	flowAggregatorAddress string

	listeners []CertificateUpdateListener
}

func NewProvider(k8sClient kubernetes.Interface, flowAggregatorAddress string) *Provider {
	namespace := getFlowAggregatorNamespace()

	provider := &Provider{
		k8sClient: k8sClient,
		clock:     clock.RealClock{},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: controllerName,
			},
		),
		namespace: namespace,
	}

	informerHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { provider.enqueue() },
		UpdateFunc: func(_ any, _ any) { provider.enqueue() },
		DeleteFunc: func(_ any) { provider.enqueue() },
	}

	provider.caSecretInformer = coreinformers.NewFilteredSecretInformer(k8sClient, namespace, resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", caSecretName).String()
		},
	)
	provider.caSecretInformer.AddEventHandler(informerHandler)
	provider.caSecretLister = corelisters.NewSecretLister(provider.caSecretInformer.GetIndexer())

	provider.clientSecretInformer = coreinformers.NewFilteredSecretInformer(k8sClient, namespace, resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", clientSecretName).String()
		},
	)
	provider.clientSecretInformer.AddEventHandler(informerHandler)
	provider.clientSecretLister = corelisters.NewSecretLister(provider.clientSecretInformer.GetIndexer())

	provider.caConfigMapInformer = coreinformers.NewFilteredConfigMapInformer(k8sClient, namespace, resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", caConfigMapName).String()
		},
	)
	provider.caConfigMapInformer.AddEventHandler(informerHandler)
	provider.caConfigMapLister = corelisters.NewConfigMapLister(provider.caConfigMapInformer.GetIndexer())

	return provider
}

func (p *Provider) enqueue() {
	klog.V(3).InfoS("Certificate event, enqueuing for sync")
	p.queue.Add("key")
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

	if retry, err := p.syncCertificates(context.TODO()); err != nil {
		klog.ErrorS(err, "Failed to sync certificates")
		p.queue.AddRateLimited(key)
	} else if retry {
		p.queue.AddRateLimited(key)
	} else {
		p.queue.Forget(key)
	}

	return true
}

func (p *Provider) syncCertificates(ctx context.Context) (bool, error) {
	klog.V(2).InfoS("Syncing certificates")
	caCertPEM, caKeyPEM, err := p.syncCACertificate(ctx)
	if err != nil {
		if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
			return false, fmt.Errorf("failed to sync CA certificate: %w", err)
		}
		klog.InfoS("Conflict when syncing CA certificate, will requeue")
		return true, nil
	}

	ca, err := parseKeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		// should not happen: either the certificate and key were read from the Secret and
		// already validated, or they were generated by us.
		return false, fmt.Errorf("failed to parse CA cert/key PEM: %w", err)
	}
	caCert := ca.Leaf
	caKey := ca.PrivateKey

	if err := p.syncClientCertificate(ctx, caCertPEM, caKeyPEM, caCert, caKey); err != nil {
		if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
			return false, fmt.Errorf("failed to sync client certificate: %w", err)
		}
		klog.InfoS("Conflict when syncing client certificate, will requeue")
		return true, nil
	}

	if err := p.syncCAConfigMap(ctx, caConfigMapName, caCertPEM); err != nil {
		if !errors.IsAlreadyExists(err) && !errors.IsConflict(err) {
			return false, fmt.Errorf("failed to sync CA ConfigMap: %w", err)
		}
		klog.InfoS("Conflict when syncing CA ConfigMap, will requeue")
		return true, nil
	}
	p.serverTLSConfigMutex.Lock()
	defer p.serverTLSConfigMutex.Unlock()

	// Skip regenerating server certs if CA cert did not change.
	// We don't need to check the expiry time of the server cert as it will always expire
	// *after* the CA cert.
	if bytes.Equal(caCertPEM, p.caCertPEM) {
		return false, nil
	}

	serverCertPEM, serverKeyPEM, err := generateCertKey(caCert, caKey, p.validFrom(), true, p.flowAggregatorAddress)
	if err != nil {
		return false, fmt.Errorf("failed to generate server certs: %w", err)
	}

	p.caCertPEM = caCertPEM
	p.serverCertPEM = serverCertPEM
	p.serverKeyPEM = serverKeyPEM

	klog.InfoS("Certificates and keys stored locally")
	p.serverTLSConfigSynced.Store(true)

	for _, listener := range p.listeners {
		listener.CertificateUpdated()
	}

	return false, nil
}

func (p *Provider) GetTLSConfig() (caCertPEM []byte, serverCertPEM []byte, serverKeyPEM []byte) {
	p.serverTLSConfigMutex.Lock()
	defer p.serverTLSConfigMutex.Unlock()
	return p.caCertPEM, p.serverCertPEM, p.serverKeyPEM
}

func (p *Provider) Run(stopCh <-chan struct{}) {
	go p.caSecretInformer.Run(stopCh)
	go p.caConfigMapInformer.Run(stopCh)
	go p.clientSecretInformer.Run(stopCh)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, p.caSecretInformer.HasSynced, p.clientSecretInformer.HasSynced, p.caConfigMapInformer.HasSynced) {
		return
	}

	go wait.Until(p.worker, time.Second, stopCh)
	go wait.Until(func() { p.queue.Add("key") }, 1*time.Hour, stopCh) // Check certificates every hour
	<-stopCh
}

func (p *Provider) HasSynced() bool {
	return p.serverTLSConfigSynced.Load()
}

func shouldUpdateCACertificate(caCertPEM, caKeyPEM []byte, now time.Time) bool {
	caCert, err := parseKeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		klog.ErrorS(err, "Invalid CA certificate")
		return true
	}
	return shouldRotateCertificate(caCert.Leaf, "CA certificate", now)
}

func (p *Provider) syncCACertificate(ctx context.Context) ([]byte, []byte, error) {
	caCertPEM, caKeyPEM, caSecret, err := p.getSecret(caSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("failed to get CA Secret: %w", err)
		}
		klog.V(2).InfoS("CA Secret not found")
	}

	needsUpdate := caSecret == nil || shouldUpdateCACertificate(caCertPEM, caKeyPEM, p.clock.Now())
	if !needsUpdate {
		klog.V(2).InfoS("CA certificate does not need to be updated")
		return caCertPEM, caKeyPEM, nil
	}

	klog.InfoS("Updating CA certificate")
	caCertPEM, caKeyPEM, err = generateCACertKey(p.validFrom())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}
	if err := p.syncCertificateSecrets(ctx, caSecretName, caCertPEM, caKeyPEM, caSecret); err != nil {
		return nil, nil, fmt.Errorf("failed to sync CA secret: %w", err)
	}
	klog.InfoS("Updated CA certificate")

	return caCertPEM, caKeyPEM, nil
}

func shouldUpdateClientCertificate(clientCertPEM, clientKeyPEM []byte, caCert *x509.Certificate, now time.Time) bool {
	clientCert, err := parseKeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		klog.ErrorS(err, "Invalid client certificate")
		return true
	}
	// There are no intermediates in the client certificate.
	if err := verifyClientCertificate(caCert, clientCert.Leaf, now); err != nil {
		klog.ErrorS(err, "Failed to verify client certificate")
		return true
	}
	return shouldRotateCertificate(clientCert.Leaf, "client certificate", now)
}

func (p *Provider) syncClientCertificate(ctx context.Context, caCertPEM []byte, caKeyPEM []byte, caCert *x509.Certificate, caKey crypto.PrivateKey) error {
	clientCertPEM, clientKeyPEM, clientSecret, err := p.getSecret(clientSecretName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get client Secret: %w", err)
		}
		klog.V(2).InfoS("Client Secret not found")
	}

	needsUpdate := (clientSecret == nil) || shouldUpdateClientCertificate(clientCertPEM, clientKeyPEM, caCert, p.clock.Now())
	if !needsUpdate {
		klog.V(2).InfoS("Client certificate does not need to be updated")
		return nil
	}

	klog.InfoS("Updating client certificate")
	clientCertPEM, clientKeyPEM, err = generateCertKey(caCert, caKey, p.validFrom(), false, "")
	if err != nil {
		return fmt.Errorf("failed to generate client cert: %w", err)
	}
	if err := p.syncCertificateSecrets(ctx, clientSecretName, clientCertPEM, clientKeyPEM, clientSecret); err != nil {
		return fmt.Errorf("failed to sync client Secret: %w", err)
	}
	klog.InfoS("Updated client certificate")

	return nil
}

func (p *Provider) validFrom() time.Time {
	// We set certificates as valid starting a hour earlier due to potential time skew on nodes.
	return p.clock.Now().Add(-time.Hour)
}

func (p *Provider) getSecret(name string) ([]byte, []byte, *v1.Secret, error) {
	var secret *v1.Secret
	var err error
	switch name {
	case caSecretName:
		secret, err = p.caSecretLister.Secrets(p.namespace).Get(caSecretName)
	case clientSecretName:
		secret, err = p.clientSecretLister.Secrets(p.namespace).Get(clientSecretName)
	default:
		return nil, nil, nil, fmt.Errorf("secret %q not managed by flow aggregator", name)
	}

	if err != nil {
		return nil, nil, nil, fmt.Errorf("error getting Secret %q: %w", name, err)
	}

	return secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey], secret, nil
}

func (p *Provider) syncCertificateSecrets(ctx context.Context, name string, cert, key []byte, currentSecret *v1.Secret) error {
	klog.InfoS("Syncing Secret", "name", name)

	var desiredSecret *v1.Secret
	if currentSecret == nil {
		desiredSecret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: p.namespace,
			},
			Type: v1.SecretTypeTLS,
		}
	} else {
		desiredSecret = currentSecret.DeepCopy()
	}

	desiredSecret.Data = map[string][]byte{
		v1.TLSCertKey:       cert,
		v1.TLSPrivateKeyKey: key,
	}
	if currentSecret != nil {
		if _, err := p.k8sClient.CoreV1().Secrets(p.namespace).Update(ctx, desiredSecret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update Secret %q: %w", clientSecretName, err)
		}
	} else {
		if _, err := p.k8sClient.CoreV1().Secrets(p.namespace).Create(ctx, desiredSecret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create Secret %q: %w", clientSecretName, err)
		}
	}
	return nil
}

func (p *Provider) syncCAConfigMap(ctx context.Context, name string, cert []byte) error {
	var desiredConfigMap *v1.ConfigMap
	currentConfigMap, err := p.caConfigMapLister.ConfigMaps(p.namespace).Get(caConfigMapName)
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error getting CA ConfigMap %q: %w", caConfigMapName, err)
		}
		klog.V(2).InfoS("CA ConfigMap not found")
		exists = false
		desiredConfigMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      caConfigMapName,
				Namespace: p.namespace,
				Labels: map[string]string{
					"app": "flow-aggregator",
				},
			},
			Data: make(map[string]string),
		}
	} else {
		desiredConfigMap = currentConfigMap.DeepCopy()
	}

	if desiredConfigMap.Data[caConfigMapKey] == string(cert) {
		return nil
	}

	desiredConfigMap.Data = map[string]string{
		caConfigMapKey: string(cert),
	}

	klog.InfoS("Syncing ConfigMap", "name", name)

	if exists {
		if _, err := p.k8sClient.CoreV1().ConfigMaps(p.namespace).Update(ctx, desiredConfigMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating ConfigMap %q: %w", caConfigMapName, err)
		}
	} else {
		if _, err := p.k8sClient.CoreV1().ConfigMaps(p.namespace).Create(ctx, desiredConfigMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating ConfigMap %q: %w", caConfigMapName, err)
		}
	}
	return nil
}

func generateSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}

// generateCACertKey creates a self-signed CA and private key pair
// encoded in PEM format. The self-signed CA can be used to generate
// leaf certificates, authenticate server and clients.
func generateCACertKey(validFrom time.Time) ([]byte, []byte, error) {
	// generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key for CA: %w", err)
	}

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new serial number for CA certificate: %w", err)
	}

	// generate rootCA
	cert := &x509.Certificate{
		SerialNumber: serial,
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

	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: certutil.CertificateBlockType, Bytes: caCert}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode CA cert to PEM format: %w", err)
	}

	var keyPEM bytes.Buffer
	if err := pem.Encode(&keyPEM, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode CA key to PEM format: %w", err)
	}

	return certPEM.Bytes(), keyPEM.Bytes(), nil
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

func generateCertKey(caCert *x509.Certificate, caKey crypto.PrivateKey, validFrom time.Time, isServer bool, flowAggregatorAddress string) ([]byte, []byte, error) {
	var cert *x509.Certificate

	serial, err := generateSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new serial number for certificate: %w", err)
	}

	if isServer {
		cert = &x509.Certificate{
			SerialNumber: serial,
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
			SerialNumber: serial,
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

	var certPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: certutil.CertificateBlockType, Bytes: certBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode cert to PEM format: %w", err)
	}

	var keyPEM bytes.Buffer
	if err := pem.Encode(&keyPEM, &pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(certKey)}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode key to PEM format: %w", err)
	}

	return certPEM.Bytes(), keyPEM.Bytes(), nil
}

func parseKeyPair(certPEM []byte, keyPEM []byte) (*tls.Certificate, error) {
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("empty cert")
	}
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("empty private key")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid cert / private key pair: %w", err)
	}
	return &cert, nil
}

func shouldRotateCertificate(cert *x509.Certificate, name string, now time.Time) bool {
	remainingDuration := cert.NotAfter.Sub(now)
	if remainingDuration < minValidDuration {
		klog.InfoS("Certificate will expire soon, needs rotation", "cert", name, "remaining", remainingDuration, "min", minValidDuration)
		return true
	}
	return false
}

func verifyCertificate(caCert, cert *x509.Certificate, keyUsage x509.ExtKeyUsage, now time.Time) error {
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:       caCertPool,
		KeyUsages:   []x509.ExtKeyUsage{keyUsage},
		CurrentTime: now,
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func verifyClientCertificate(caCert, cert *x509.Certificate, now time.Time) error {
	return verifyCertificate(caCert, cert, x509.ExtKeyUsageClientAuth, now)
}

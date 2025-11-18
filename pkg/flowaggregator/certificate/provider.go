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
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	clockutils "k8s.io/utils/clock"

	"antrea.io/antrea/pkg/util/env"
)

const (
	DefaultNamespace = "flow-aggregator"

	minValidDuration = time.Hour * 24 * 90

	CAConfigMapName = "flow-aggregator-ca"
	CAConfigMapKey  = "ca.crt"

	// #nosec G101: false positive triggered by variable name which includes "Secret"
	CASecretName = "flow-aggregator-ca"
	// #nosec G101: false positive triggered by variable name which includes "Secret"
	ServerSecretName = "flow-aggregator-server-tls"
	// #nosec G101: false positive triggered by variable name which includes "Secret"
	ClientSecretName = "flow-aggregator-client-tls"
	ServiceName      = "flow-aggregator"

	SecretCertKey = "tls.crt"
	SecretKeyKey  = "tls.key"
)

var (
	maxAge = time.Hour * 24 * 365 // one year self-signed certs
)

type Provider interface {
	Run(stopCh <-chan struct{})
	GetServerCertKey() (caCertPEM []byte, serverCertPEM []byte, serverKeyPEM []byte)
	HasSynced() bool
}

type provider struct {
	k8sClient      kubernetes.Interface
	clock          clockutils.Clock
	queue          workqueue.TypedRateLimitingInterface[string]
	secretInformer cache.SharedIndexInformer

	certsReadyCond     *sync.Cond
	serverCertsUpdated bool
	serverCertsSynced  bool

	caCertPEM     []byte
	serverCertPEM []byte
	serverKeyPEM  []byte

	flowAggregatorAddress string
}

func NewProvider(k8sClient kubernetes.Interface, flowAggregatorAddress string) Provider {
	provider := &provider{
		k8sClient: k8sClient,
		clock:     clockutils.RealClock{},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "flowAggregator",
			},
		),
		certsReadyCond: sync.NewCond(&sync.Mutex{}),
	}
	namespace := getFlowAggregatorNamespace()

	provider.secretInformer = coreinformers.NewFilteredSecretInformer(k8sClient, namespace, 12*time.Hour,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("metadata.name", CASecretName).String()
		},
	)
	provider.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ any) { provider.queue.Add("key") },
		UpdateFunc: func(_ any, _ any) { provider.queue.Add("key") },
		DeleteFunc: func(_ any) { provider.queue.Add("key") },
	})

	return provider
}

func (p *provider) worker() {
	for p.processNextWorkItem() {
	}
}

func (p *provider) processNextWorkItem() bool {
	key, quit := p.queue.Get()
	if quit {
		return false
	}
	defer p.queue.Done(key)

	p.certsReadyCond.L.Lock()
	defer p.certsReadyCond.L.Unlock()
	p.serverCertsUpdated = false

	caCertPEM, _, err := p.getSecret(CASecretName)
	if err != nil {
		p.queue.AddRateLimited(key)
		return true
	}

	serverCertPEM, serverKeyPEM, err := p.getSecret(ServerSecretName)
	if err != nil {
		p.queue.AddRateLimited(key)
		return true
	}

	p.caCertPEM = caCertPEM
	p.serverCertPEM = serverCertPEM
	p.serverKeyPEM = serverKeyPEM

	klog.Info("Certificates and keys cached locally, notifying")
	p.serverCertsSynced = true
	p.serverCertsUpdated = true
	p.certsReadyCond.Broadcast()
	p.queue.Forget(key)
	return true
}

func (p *provider) GetServerCertKey() (caCertPEM []byte, serverCertPEM []byte, serverKeyPEM []byte) {
	p.certsReadyCond.L.Lock()
	defer p.certsReadyCond.L.Unlock()

	for !p.serverCertsUpdated {
		p.certsReadyCond.Wait()
	}

	return p.caCertPEM, p.serverCertPEM, p.serverKeyPEM
}

func (p *provider) Run(stopCh <-chan struct{}) {
	go p.secretInformer.Run(stopCh)

	if !cache.WaitForNamedCacheSync("certificateProvider", stopCh, p.secretInformer.HasSynced) {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go p.doLeaderWork(ctx)
	go wait.Until(p.worker, time.Second, stopCh)
	<-stopCh
}

func (p *provider) HasSynced() bool {
	p.certsReadyCond.L.Lock()
	defer p.certsReadyCond.L.Unlock()

	for !p.serverCertsSynced {
		p.certsReadyCond.Wait()
	}

	return p.serverCertsSynced
}

// Returns the CA cert, server cert and server private key
func (p *provider) doLeaderWork(ctx context.Context) {
	// Create a Lease lock
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      "flow-aggregator",
			Namespace: getFlowAggregatorNamespace(),
		},
		Client: p.k8sClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: env.GetPodName(),
		},
	}

	// Configure leader election
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}

					caCertPEM, _, err := p.getSecret(CASecretName)
					if err != nil && !errors.IsNotFound(err) {
						klog.ErrorS(err, "failed to get root CA certificate and key")
						time.Sleep(1 * time.Second)
						continue // Retry after 1 second
					}

					// Certs need to be rotated?
					if p.shouldRotateCertificate(caCertPEM) {
						if err := p.generateCertsAndSync(); err != nil {
							klog.ErrorS(err, "failed to generate/sync certificates and keys")
						}
					}

					// We select here to ensure we run at least once unless we were started with a cancelled context.
					select {
					case <-ctx.Done():
					case <-p.clock.After(24 * time.Hour): // Check again after 24h
					}
				}
			},
			OnStoppedLeading: func() {},
			OnNewLeader: func(identity string) {
				klog.InfoS("New leader elected", "isLeader", identity == env.GetPodName(), "leader", identity)
			},
		},
	})
}

func (p *provider) shouldRotateCertificate(cert []byte) bool {
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

func (p *provider) getSecret(name string) (certPEM []byte, keyPEM []byte, err error) {
	namespace := getFlowAggregatorNamespace()

	secret, err := p.k8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Secret %s: %w", CAConfigMapName, err)
	}

	certPEM, ok := secret.Data[SecretCertKey]
	if !ok {
		return nil, nil, nil
	}

	keyPEM, ok = secret.Data[SecretKeyKey]
	if !ok {
		return nil, nil, nil
	}

	return certPEM, keyPEM, nil
}

// generateCertsAndSync generates new certificates for the Flow Aggregator and the Flow Exporter (client),
// and syncs the certificates and keys for the root CA, server and client.
func (p *provider) generateCertsAndSync() error {
	validFrom := time.Now().Add(-time.Hour)

	caCertPEM, caKeyPEM, err := GenerateCACertKey(validFrom)
	if err != nil {
		return fmt.Errorf("failed to generate CA cert and key: %w", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	caKeyBlock, _ := pem.Decode(caKeyPEM)

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	serverCert, serverKey, err := GenerateCertKey(caCert, caKey, validFrom, true, p.flowAggregatorAddress)
	if err != nil {
		return fmt.Errorf("error when creating server certificate: %w", err)
	}

	clientCert, clientKey, err := GenerateCertKey(caCert, caKey, validFrom, false, "")
	if err != nil {
		return fmt.Errorf("error when creating client certificate: %w", err)
	}

	if err := syncCertsAndKeys(caCertPEM, caKeyPEM, serverCert, serverKey, clientCert, clientKey, p.k8sClient); err != nil {
		return fmt.Errorf("error when synchronizing cert: %w", err)
	}

	return nil
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
		namespace = DefaultNamespace
	}
	return namespace
}

func getFlowAggregatorServerNames() []string {
	namespace := getFlowAggregatorNamespace()
	return []string{ServiceName + "." + namespace + ".svc"}
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

func syncCertificateSecrets(name string, cert, key []byte, k8sClient kubernetes.Interface) error {
	klog.InfoS("Syncing Secret", "name", name)
	namespace := getFlowAggregatorNamespace()

	secret, err := k8sClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	exists := true
	if err != nil {
		exists = false
		secret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: v1.SecretTypeTLS,
		}
	}
	secret.Data = map[string][]byte{
		"tls.crt": cert,
		"tls.key": key,
	}
	if exists {
		if _, err := k8sClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update Secret %s: %v", ClientSecretName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create Secret %s: %v", ClientSecretName, err)
		}
	}
	return nil
}

func syncCAConfigMap(name string, cert []byte, k8sClient kubernetes.Interface) error {
	klog.InfoS("Syncing ConfigMap", "name", name)
	namespace := getFlowAggregatorNamespace()

	caConfigMap, err := k8sClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), CAConfigMapName, metav1.GetOptions{})
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error getting ConfigMap %s: %v", CAConfigMapName, err)
		}
		exists = false
		caConfigMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      CAConfigMapName,
				Namespace: namespace,
				Labels: map[string]string{
					"app": "flow-aggregator",
				},
			},
		}
	}
	caConfigMap.Data = map[string]string{
		CAConfigMapKey: string(cert),
	}
	if exists {
		if _, err := k8sClient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), caConfigMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating ConfigMap %s: %v", CAConfigMapName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().ConfigMaps(namespace).Create(context.TODO(), caConfigMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating ConfigMap %s: %v", CAConfigMapName, err)
		}
	}
	return nil
}

func syncCertsAndKeys(caCert, caKey, serverCert, serverKey, clientCert, clientKey []byte, k8sClient kubernetes.Interface) error {
	if err := syncCAConfigMap(CAConfigMapName, caCert, k8sClient); err != nil {
		return err
	}

	if err := syncCertificateSecrets(ServerSecretName, serverCert, serverKey, k8sClient); err != nil {
		return err
	}

	if err := syncCertificateSecrets(ClientSecretName, clientCert, clientKey, k8sClient); err != nil {
		return err
	}

	// We check whether we need to rotate based on the CA secret. We want to ensure it
	// is the last to be synced because if it's bad or failed we should regenerate it.
	return syncCertificateSecrets(CASecretName, caCert, caKey, k8sClient)
}

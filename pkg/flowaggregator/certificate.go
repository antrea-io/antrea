// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowaggregator

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
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	CAConfigMapName       = "flow-aggregator-ca"
	CAConfigMapKey        = "ca.crt"
	CAConfigMapNamespace  = "flow-aggregator"
	ClientSecretNamespace = "flow-aggregator"
	// #nosec G101: false positive triggered by variable name which includes "Secret"
	ClientSecretName = "flow-aggregator-client-tls"
)

var (
	validFrom = time.Now().Add(-time.Hour) // valid an hour earlier to avoid flakes due to clock skew
	maxAge    = time.Hour * 24 * 365       // one year self-signed certs
)

func generateCACertKey() (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("flow-aggregator-ca@%d", time.Now().Unix()),
		},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(maxAge),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	// generate CA certificate
	caCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert,
	})

	return cert, caKey, caPEM.Bytes(), err
}

func generateCertKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, isServer bool, flowAggregatorAddress string) ([]byte, []byte, error) {
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
		}
		if ip := net.ParseIP(flowAggregatorAddress); ip != nil {
			cert.IPAddresses = []net.IP{ip}
		} else {
			cert.DNSNames = []string{flowAggregatorAddress}
			// add IP in certicate since flow exporter on Windows Node can't resolve DNS name
			flowAggregatorIPs, err := net.LookupIP(flowAggregatorAddress)
			if err != nil {
				return nil, nil, err
			}
			cert.IPAddresses = flowAggregatorIPs
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
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certKeyPEM := new(bytes.Buffer)
	pem.Encode(certKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM.Bytes(), certKeyPEM.Bytes(), nil
}

func syncCAAndClientCert(caCert, clientCert, clientKey []byte, k8sClient kubernetes.Interface) error {
	klog.Info("Syncing CA certificate, client certificate and client key with ConfigMap")
	caConfigMap, err := k8sClient.CoreV1().ConfigMaps(CAConfigMapNamespace).Get(context.TODO(), CAConfigMapName, metav1.GetOptions{})
	exists := true
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("error getting ConfigMap %s: %v", CAConfigMapName, err)
		}
		exists = false
		caConfigMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      CAConfigMapName,
				Namespace: CAConfigMapNamespace,
				Labels: map[string]string{
					"app": "flow-aggregator",
				},
			},
		}
	}
	caConfigMap.Data = map[string]string{
		CAConfigMapKey: string(caCert),
	}
	if exists {
		if _, err := k8sClient.CoreV1().ConfigMaps(CAConfigMapNamespace).Update(context.TODO(), caConfigMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating ConfigMap %s: %v", CAConfigMapName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().ConfigMaps(CAConfigMapNamespace).Create(context.TODO(), caConfigMap, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("error creating ConfigMap %s: %v", CAConfigMapName, err)
		}
	}

	secret, err := k8sClient.CoreV1().Secrets(ClientSecretNamespace).Get(context.TODO(), ClientSecretName, metav1.GetOptions{})
	exists = true
	if err != nil {
		exists = false
		secret = &v1.Secret{
			Data: map[string][]byte{
				"tls.crt": clientCert,
				"tls.key": clientKey,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      ClientSecretName,
				Namespace: ClientSecretNamespace,
			},
			Type: v1.SecretTypeTLS,
		}
	}
	secret.Data = map[string][]byte{
		"tls.crt": clientCert,
		"tls.key": clientKey,
	}
	if exists {
		if _, err := k8sClient.CoreV1().Secrets(ClientSecretNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update Secret %s: %v", ClientSecretName, err)
		}
	} else {
		if _, err := k8sClient.CoreV1().Secrets(ClientSecretNamespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create Secret %s: %v", ClientSecretName, err)
		}
	}
	return nil
}

// Copyright 2020 Antrea Authors
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
	"fmt"
	"os"
	"path/filepath"
	"time"

	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	// The names of the files that should contain the CA certificate and the TLS key pair.
	CACertFile  = "ca.crt"
	TLSCertFile = "tls.crt"
	TLSKeyFile  = "tls.key"
)

func ApplyServerCert(selfSignedCert bool,
	client kubernetes.Interface,
	aggregatorClient clientset.Interface,
	apiExtensionClient apiextensionclientset.Interface,
	secureServing *options.SecureServingOptionsWithLoopback,
	caConfig *CAConfig) (*CACertController, error) {
	var err error
	var caContentProvider dynamiccertificates.CAContentProvider
	if selfSignedCert {
		caContentProvider, err = newSelfSignedCertProvider(client, secureServing, caConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize self-signed certificate: %w", err)
		}
	} else {
		caCertPath := filepath.Join(caConfig.CertDir, CACertFile)
		tlsCertPath := filepath.Join(caConfig.CertDir, TLSCertFile)
		tlsKeyPath := filepath.Join(caConfig.CertDir, TLSKeyFile)
		// The secret may be created after the Pod is created, for example, when cert-manager is used the secret
		// is created asynchronously. It waits for a while before it's considered to be failed.
		if err = wait.PollUntilContextTimeout(context.TODO(), 2*time.Second, caConfig.CertReadyTimeout, true,
			func(ctx context.Context) (bool, error) {
				for _, path := range []string{caCertPath, tlsCertPath, tlsKeyPath} {
					f, err := os.Open(path)
					if err != nil {
						klog.Warningf("Couldn't read %s when applying server certificate, retrying", path)
						return false, nil
					}
					f.Close()
				}
				return true, nil
			}); err != nil {
			return nil, fmt.Errorf("error reading TLS certificate and/or key. Please make sure the TLS CA (%s), cert (%s), and key (%s) files are present in \"%s\", when selfSignedCert is set to false", CACertFile, TLSCertFile, TLSKeyFile, caConfig.CertDir)
		}
		// Since 1.17.0 (https://github.com/kubernetes/kubernetes/commit/3f5fbfbfac281f40c11de2f57d58cc332affc37b),
		// apiserver reloads certificate cert and key file from disk every minute, allowing serving tls config to be updated.
		secureServing.ServerCert.CertKey.CertFile = tlsCertPath
		secureServing.ServerCert.CertKey.KeyFile = tlsKeyPath

		caContentProvider, err = dynamiccertificates.NewDynamicCAContentFromFile("user-provided CA cert", caCertPath)
		if err != nil {
			return nil, fmt.Errorf("error reading user-provided CA certificate: %v", err)
		}
	}

	caCertController := newCACertController(caContentProvider, client, aggregatorClient, apiExtensionClient, caConfig)
	return caCertController, nil
}

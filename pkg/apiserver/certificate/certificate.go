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
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

var (
	// certDir is the directory that the TLS Secret should be mounted to. Declaring it as a variable for testing.
	certDir = "/var/run/antrea/antrea-controller-tls"
	// certReadyTimeout is the timeout we will wait for the TLS Secret being ready. Declaring it as a variable for testing.
	certReadyTimeout = 2 * time.Minute
	// The DNS names that the TLS certificate will be signed with.
	// TODO: Although antrea-agent and kube-aggregator only verify the server name "antrea.kube-system.svc",
	// We should add the whole FQDN "antrea.kube-system.svc.<Cluster Domain>" as an alternate DNS name when
	// other clients need to access it directly with that name.
	AntreaServerNames = []string{
		"antrea.kube-system.svc",
	}
)

const (
	// The namespace and name of the Secret that holds user-provided TLS certificate.
	TLSSecretNamespace = "kube-system"
	TLSSecretName      = "antrea-controller-tls"
	// The names of the files that should contain the CA certificate and the TLS key pair.
	CACertFile  = "ca.crt"
	TLSCertFile = "tls.crt"
	TLSKeyFile  = "tls.key"
)

func ApplyServerCert(selfSignedCert bool, client kubernetes.Interface, aggregatorClient clientset.Interface, secureServing *options.SecureServingOptionsWithLoopback) (*CACertController, error) {
	var err error
	var caContentProvider dynamiccertificates.CAContentProvider
	if selfSignedCert {
		// Set the PairName but leave certificate directory blank to generate in-memory by default.
		secureServing.ServerCert.CertDirectory = ""
		secureServing.ServerCert.PairName = "antrea-controller"

		if err := secureServing.MaybeDefaultWithSelfSignedCerts("antrea", AntreaServerNames, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
			return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
		}

		certPEMBlock, _ := secureServing.ServerCert.GeneratedCert.CurrentCertKeyContent()
		caContentProvider, err = dynamiccertificates.NewStaticCAContent("self-signed cert", certPEMBlock)
		if err != nil {
			return nil, fmt.Errorf("error reading self-signed CA certificate: %v", err)
		}
	} else {
		caCertPath := path.Join(certDir, CACertFile)
		tlsCertPath := path.Join(certDir, TLSCertFile)
		tlsKeyPath := path.Join(certDir, TLSKeyFile)
		// The secret may be created after the Pod is created, for example, when cert-manager is used the secret
		// is created asynchronously. It waits for a while before it's considered to be failed.
		if err = wait.PollImmediate(2*time.Second, certReadyTimeout, func() (bool, error) {
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
			return nil, fmt.Errorf("error reading TLS certificate and/or key. Please make sure the Secret '%s' is present and has '%s', '%s', and '%s' when selfSignedCert is set to false", TLSSecretName, CACertFile, TLSCertFile, TLSKeyFile)
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

	caCertController := newCACertController(caContentProvider, client, aggregatorClient)
	return caCertController, nil
}

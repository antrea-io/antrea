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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
)

func TestIPsecCertificateApproverAndSigner(t *testing.T) {
	validX509CertificateRequest := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"antrea.io"},
			CommonName:   "worker-node-1",
		},
		DNSNames: []string{"worker-node-1"},
	}
	_, crBytes := x509CRtoPEM(t, &validX509CertificateRequest)
	tests := []struct {
		name                             string
		objects                          []runtime.Object
		csr                              *certificatesv1.CertificateSigningRequest
		expectedError                    error
		expectedApproved, expectedDenied bool
	}{
		{
			name: "verify and sign valid IPsec CSR",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "antrea-agent-8r5f9",
						UID:       "1206ba75-7d75-474c-8110-99255502178c",
					},
					Spec: corev1.PodSpec{
						NodeName: "worker-node-1",
					},
				},
			},
			csr: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-node-1-ipsec",
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					Request:    crBytes,
					SignerName: "antrea.io/antrea-agent-ipsec-tunnel",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageIPsecTunnel,
					},
					Username: "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			expectedApproved: true,
			expectedDenied:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(tt.objects...)
			informerFactory := informers.NewSharedInformerFactory(clientset, 0)
			stopCh := make(chan struct{})
			defer close(stopCh)
			csrInformer := informerFactory.Certificates().V1().CertificateSigningRequests()

			approvingController := NewCSRApprovingController(clientset, csrInformer.Informer(), csrInformer.Lister())
			signingController := NewIPsecCSRSigningController(clientset, csrInformer.Informer(), csrInformer.Lister(), true)

			informerFactory.Start(stopCh)
			informerFactory.WaitForCacheSync(stopCh)

			go approvingController.Run(stopCh)
			go signingController.Run(stopCh)

			csr, err := clientset.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), tt.csr, metav1.CreateOptions{})
			require.NoError(t, err)
			err = wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, 10*time.Second, true,
				func(ctx context.Context) (done bool, err error) {
					csr, err = clientset.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), tt.csr.Name, metav1.GetOptions{})
					require.NoError(t, err)
					if !isCertificateRequestApproved(csr) {
						return false, nil
					}
					if len(csr.Status.Certificate) == 0 {
						return false, nil
					}
					return true, nil
				})
			require.NoError(t, err)
			issued := csr.Status.Certificate
			parsed, err := certutil.ParseCertsPEM(issued)
			assert.NoError(t, err)
			require.Len(t, parsed, 1)
			roots := x509.NewCertPool()
			roots.AddCert(signingController.certificateAuthority.Load().(*certificateAuthority).Certificate)
			verifyOptions := x509.VerifyOptions{
				Roots: roots,
				KeyUsages: []x509.ExtKeyUsage{
					x509.ExtKeyUsageIPSECTunnel,
				},
			}
			_, err = parsed[0].Verify(verifyOptions)
			assert.NoError(t, err)
		})
	}
}

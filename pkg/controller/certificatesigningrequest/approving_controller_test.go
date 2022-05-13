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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeApprover struct {
	approverName         string
	recognized, verified bool
}

var _ approver = (*fakeApprover)(nil)

func (f *fakeApprover) recognize(_ *certificatesv1.CertificateSigningRequest) bool {
	return f.recognized
}

func (f *fakeApprover) verify(_ *certificatesv1.CertificateSigningRequest) (bool, error) {
	return f.verified, nil
}

func (f *fakeApprover) name() string {
	return f.approverName
}

func TestCSRApprovingController_syncCSR(t *testing.T) {
	tests := []struct {
		name                           string
		approvers                      []approver
		expectErr                      bool
		expectApproved, expectedDenied bool
		csrToSync                      *certificatesv1.CertificateSigningRequest
	}{
		{
			name: "recognized and approved",
			approvers: []approver{
				&fakeApprover{
					approverName: "FakeApprover",
					recognized:   true,
					verified:     true,
				},
			},
			expectErr:      false,
			expectApproved: true,
			expectedDenied: false,
			csrToSync: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "csr-1",
				},
			},
		},
		{
			name: "not approved by any approver",
			approvers: []approver{
				&fakeApprover{
					approverName: "FakeApprover",
					recognized:   false,
					verified:     false,
				},
				&fakeApprover{
					approverName: "FakeApprover2",
					recognized:   false,
					verified:     false,
				},
			},
			expectErr:      false,
			expectApproved: false,
			expectedDenied: false,
			csrToSync: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "csr-1",
				},
			},
		},
		{
			name: "recognized by both approver and approved by the second approver",
			approvers: []approver{
				&fakeApprover{
					approverName: "FakeApprover",
					recognized:   true,
					verified:     false,
				},
				&fakeApprover{
					approverName: "FakeApprover2",
					recognized:   true,
					verified:     true,
				},
			},
			expectErr:      false,
			expectApproved: true,
			expectedDenied: false,
			csrToSync: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "csr-1",
				},
			},
		},
		{
			name: "recognized by and approved by the second approver",
			approvers: []approver{
				&fakeApprover{
					approverName: "FakeApprover",
					recognized:   false,
					verified:     true,
				},
				&fakeApprover{
					approverName: "FakeApprover2",
					recognized:   true,
					verified:     true,
				},
			},
			expectErr:      false,
			expectApproved: true,
			expectedDenied: false,
			csrToSync: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "csr-1",
				},
			},
		},
		{
			name: "do not approve denied CSR",
			approvers: []approver{
				&fakeApprover{
					approverName: "FakeApprover",
					recognized:   true,
					verified:     true,
				},
			},
			expectErr:      false,
			expectApproved: false,
			expectedDenied: true,
			csrToSync: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "csr-1",
				},
				Status: certificatesv1.CertificateSigningRequestStatus{
					Conditions: []certificatesv1.CertificateSigningRequestCondition{
						{
							Type:   certificatesv1.CertificateDenied,
							Status: corev1.ConditionTrue,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(tt.csrToSync)
			informerFactory := informers.NewSharedInformerFactory(clientset, 0)
			stopCh := make(chan struct{})
			defer close(stopCh)
			csrInformer := informerFactory.Certificates().V1().CertificateSigningRequests()
			controller := NewCSRApprovingController(clientset, csrInformer.Informer(), csrInformer.Lister())
			controller.csrInformer = csrInformer.Informer()
			controller.csrLister = csrInformer.Lister()
			controller.approvers = tt.approvers

			informerFactory.Start(stopCh)
			informerFactory.WaitForCacheSync(stopCh)

			err := controller.syncCSR(tt.csrToSync.Name)
			assert.Equal(t, tt.expectErr, err != nil)
			csr, err := clientset.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), tt.csrToSync.Name, metav1.GetOptions{})
			require.NoError(t, err)
			approved, denied := getCertApprovalCondition(&csr.Status)
			assert.Equal(t, tt.expectApproved, approved)
			assert.Equal(t, tt.expectedDenied, denied)
		})
	}
}

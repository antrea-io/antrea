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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
)

func Test_validIPSecCSR(t *testing.T) {
	tests := []struct {
		name        string
		objects     []runtime.Object
		cr          *x509.CertificateRequest
		keyUsages   []certificatesv1.KeyUsage
		expectedErr error
	}{
		{
			name: "valid CSR",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
			},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				DNSNames: []string{"worker-node-1"},
			},
			expectedErr: nil,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name: "Organization missing",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
			},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "worker-node-1",
				},
				DNSNames: []string{"worker-node-1"},
			},
			expectedErr: errOrganizationNotAntrea,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name:    "requested Node not found",
			objects: []runtime.Object{},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				DNSNames: []string{"worker-node-1"},
			},
			expectedErr: errors.New("requested Node worker-node-1 not found"),
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name:    "DNS SAN not match",
			objects: []runtime.Object{},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
			},
			expectedErr: errDNSSANNotMatchCommonName,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name:    "key usages not match",
			objects: []runtime.Object{},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				DNSNames: []string{"worker-node-1"},
			},
			expectedErr: errors.New("unsupported key usage: client auth"),
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageClientAuth,
			},
		},
		{
			name: "IP SAN should not be permitted",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
			},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				IPAddresses: []net.IP{net.ParseIP("1.2.3.4")},
				DNSNames:    []string{"worker-node-1"},
			},
			expectedErr: errIPSANNotAllowed,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name: "URI SAN should not be permitted",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
			},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				URIs: []*url.URL{
					{Host: "antrea.io"},
				},
				DNSNames: []string{"worker-node-1"},
			},
			expectedErr: errURISANNotAllowed,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
		{
			name: "Email SAN should not be permitted",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
			},
			cr: &x509.CertificateRequest{
				Subject: pkix.Name{
					Organization: []string{"antrea.io"},
					CommonName:   "worker-node-1",
				},
				EmailAddresses: []string{"user@antrea.io"},
				DNSNames:       []string{"worker-node-1"},
			},
			expectedErr: errEmailSANNotAllowed,
			keyUsages: []certificatesv1.KeyUsage{
				certificatesv1.UsageIPsecTunnel,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			ic := newIPsecCSRApprover(client)
			err := ic.verifyCertificateRequest(tt.cr, tt.keyUsages)
			if tt.expectedErr == nil {
				assert.NoError(t, err, "validIPSecCSR should not return an error")
			} else {
				assert.EqualError(t, err, tt.expectedErr.Error(), "validIPSecCSR should return an error")
			}
		})
	}
}

func Test_verifyIdentity(t *testing.T) {
	tests := []struct {
		name        string
		objects     []runtime.Object
		nodeName    string
		csr         *certificatesv1.CertificateSigningRequest
		expectedErr error
	}{
		{
			name: "valid CSR",
			objects: []runtime.Object{
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
					SignerName: "antrea.io/ipsec",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Username: "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			nodeName:    "worker-node-1",
			expectedErr: nil,
		},
		{
			name: "invalid username",
			objects: []runtime.Object{
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
					SignerName: "antrea.io/ipsec",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Username: "system:serviceaccount:kube-system:my-sa",
				},
			},
			nodeName:    "worker-node-1",
			expectedErr: errUserUnauthorized,
		},
		{
			name: "Pod UID mismatch",
			objects: []runtime.Object{
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
					SignerName: "antrea.io/ipsec",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"7afec259-ba03-441d-adeb-be163da2da2c"},
					},
					Username: "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			nodeName:    "worker-node-1",
			expectedErr: errPodUIDMismatch,
		},
		{
			name: "extra fields missing",
			objects: []runtime.Object{
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
					SignerName: "antrea.io/ipsec",
					Extra:      map[string]certificatesv1.ExtraValue{},
					Username:   "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			nodeName:    "worker-node-1",
			expectedErr: nil,
		},
		{
			name: "Pod is not on requested Node",
			objects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "antrea-agent-8r5f9",
						UID:       "1206ba75-7d75-474c-8110-99255502178c",
					},
					Spec: corev1.PodSpec{
						NodeName: "worker-node-2",
					},
				},
			},
			csr: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-node-1-ipsec",
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: "antrea.io/ipsec",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Username: "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			nodeName:    "worker-node-1",
			expectedErr: errPodNotOnNode,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			ic := newIPsecCSRApprover(client)
			err := ic.verifyIdentity(tt.nodeName, tt.csr)
			if tt.expectedErr == nil {
				assert.NoError(t, err, "verifyPodOnNode should not return an error")
			} else {
				assert.EqualError(t, err, tt.expectedErr.Error(), "verifyPodOnNode should return an error")
			}
		})
	}
}

func Test_ipsecCertificateApprover_recognize(t *testing.T) {
	tests := []struct {
		name           string
		objects        []runtime.Object
		csr            *certificatesv1.CertificateSigningRequest
		expectedResult bool
	}{
		{
			name: "valid IPsec CSR",
			csr: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-node-1-ipsec",
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: "antrea.io/antrea-agent-ipsec-tunnel",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageIPsecTunnel,
					},
				},
			},
			expectedResult: true,
		},
		{
			name: "Unknown signer name",
			csr: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "worker-node-1-ipsec",
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					SignerName: "k8s.io/signer",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"antrea-agent-8r5f9"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageIPsecTunnel,
					},
				},
			},
			expectedResult: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(tt.objects...)
			ic := newIPsecCSRApprover(client)
			recognized := ic.recognize(tt.csr)
			assert.Equal(t, tt.expectedResult, recognized)
		})
	}
}

func x509CRtoPEM(t *testing.T, cr *x509.CertificateRequest) (crypto.PrivateKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	crDer, err := x509.CreateCertificateRequest(rand.Reader, cr, privateKey)
	require.NoError(t, err)
	csrPemBlock := &pem.Block{
		Type:  certutil.CertificateRequestBlockType,
		Bytes: crDer,
	}
	crBytes := pem.EncodeToMemory(csrPemBlock)
	assert.NotEmpty(t, crBytes)
	return privateKey, crBytes
}

func Test_ipsecCertificateApprover_verify(t *testing.T) {
	validX509CertificateRequest := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"antrea.io"},
			CommonName:   "worker-node-1",
		},
		DNSNames: []string{"worker-node-1"},
	}
	_, crBytes := x509CRtoPEM(t, &validX509CertificateRequest)
	tests := []struct {
		name             string
		objects          []runtime.Object
		csr              *certificatesv1.CertificateSigningRequest
		expectedError    error
		expectedApproved bool
	}{
		{
			name: "valid IPsec CSR",
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
					SignerName: "antrea.io/ipsec",
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
		},
		{
			name: "IPsec CSR with unknown username",
			objects: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "worker-node-1",
					},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "my-pod-1",
						UID:       "1206ba75-7d75-474c-8110-99255502178c",
					},
					Spec: corev1.PodSpec{
						NodeName: "worker-node-1",
					},
				},
			},
			csr: &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ipsec-unknown-user",
				},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					Request:    crBytes,
					SignerName: "antrea.io/ipsec",
					Extra: map[string]certificatesv1.ExtraValue{
						"authentication.kubernetes.io/pod-name": {"my-pod-1"},
						"authentication.kubernetes.io/pod-uid":  {"1206ba75-7d75-474c-8110-99255502178c"},
					},
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageIPsecTunnel,
					},
					Username: "system:serviceaccount:kube-system:user-1",
				},
			},
			expectedApproved: false,
		},
		{
			name: "CSR missing ExtraValue",
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
					SignerName: "antrea.io/ipsec",
					Extra:      map[string]certificatesv1.ExtraValue{},
					Usages: []certificatesv1.KeyUsage{
						certificatesv1.UsageIPsecTunnel,
					},
					Username: "system:serviceaccount:kube-system:antrea-agent",
				},
			},
			expectedApproved: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := append(tt.objects, tt.csr)
			client := fake.NewSimpleClientset(objs...)
			ic := newIPsecCSRApprover(client)
			approved, err := ic.verify(tt.csr)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.Equal(t, tt.expectedApproved, approved)
			}
		})
	}
}

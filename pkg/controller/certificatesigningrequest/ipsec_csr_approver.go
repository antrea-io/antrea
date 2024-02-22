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
	"fmt"
	"reflect"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	sautil "k8s.io/apiserver/pkg/authentication/serviceaccount"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	antreaapis "antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/util/env"
)

const (
	ipsecCSRApproverName = "AntreaIPsecCSRApprover"
)

type ipsecCSRApprover struct {
	client                        clientset.Interface
	antreaAgentServiceAccountName string
}

var ipsecTunnelUsages = sets.New[string](
	string(certificatesv1.UsageIPsecTunnel),
)

var _ approver = (*ipsecCSRApprover)(nil)

func getAntreaAgentServiceAccount() string {
	return strings.Join([]string{
		"system", "serviceaccount", env.GetAntreaNamespace(), "antrea-agent",
	}, ":")
}

func newIPsecCSRApprover(client clientset.Interface) *ipsecCSRApprover {
	return &ipsecCSRApprover{
		client:                        client,
		antreaAgentServiceAccountName: getAntreaAgentServiceAccount(),
	}
}

func (ic *ipsecCSRApprover) recognize(csr *certificatesv1.CertificateSigningRequest) bool {
	return csr.Spec.SignerName == antreaapis.AntreaIPsecCSRSignerName
}

func (ic *ipsecCSRApprover) verify(csr *certificatesv1.CertificateSigningRequest) (bool, error) {
	var failedReasons []string
	cr, err := decodeCertificateRequest(csr.Spec.Request)
	if err != nil {
		return false, err
	}
	if err := ic.verifyCertificateRequest(cr, csr.Spec.Usages); err != nil {
		if _, ok := err.(*transientError); ok {
			return false, err
		} else {
			failedReasons = append(failedReasons, err.Error())
		}
	}
	if err := ic.verifyIdentity(cr.Subject.CommonName, csr); err != nil {
		if _, ok := err.(*transientError); ok {
			return false, err
		}
		failedReasons = append(failedReasons, err.Error())
	}

	if len(failedReasons) > 0 {
		klog.InfoS("Verifing CertificateSigningRequest for IPsec failed", "reasons", failedReasons, "CSR", csr.Name)
		return false, nil
	}
	return true, nil
}

func (ic *ipsecCSRApprover) name() string {
	return ipsecCSRApproverName
}

func (ic *ipsecCSRApprover) verifyCertificateRequest(req *x509.CertificateRequest, usages []certificatesv1.KeyUsage) error {
	if !reflect.DeepEqual(req.Subject.Organization, []string{antreaapis.AntreaOrganizationName}) {
		return errOrganizationNotAntrea
	}
	if req.Subject.CommonName == "" {
		return errCommonNameRequired
	}
	if len(req.URIs) > 0 {
		return errURISANNotAllowed
	}
	if len(req.IPAddresses) > 0 {
		return errIPSANNotAllowed
	}
	if len(req.EmailAddresses) > 0 {
		return errEmailSANNotAllowed
	}
	if !reflect.DeepEqual([]string{req.Subject.CommonName}, req.DNSNames) {
		return errDNSSANNotMatchCommonName
	}
	for _, u := range usages {
		if !ipsecTunnelUsages.Has(string(u)) {
			return fmt.Errorf("unsupported key usage: %v", u)
		}
	}
	_, err := ic.client.CoreV1().Nodes().Get(context.TODO(), req.Subject.CommonName, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		return fmt.Errorf("requested Node %s not found", req.Subject.CommonName)
	} else if err != nil {
		return &transientError{err}
	}
	return nil
}

func (ic *ipsecCSRApprover) verifyIdentity(nodeName string, csr *certificatesv1.CertificateSigningRequest) error {
	if csr.Spec.Username != ic.antreaAgentServiceAccountName {
		return errUserUnauthorized
	}
	podNameValues, podUIDValues := csr.Spec.Extra[sautil.PodNameKey], csr.Spec.Extra[sautil.PodUIDKey]
	if len(podNameValues) == 0 && len(podUIDValues) == 0 {
		klog.Warning("Could not determine Pod identity from CertificateSigningRequest.",
			" Enable K8s BoundServiceAccountTokenVolume feature gate to provide maximum security.")
		return nil
	}
	if len(podNameValues) == 0 || len(podUIDValues) == 0 {
		return errExtraFieldsRequired
	}
	podName, podUID := podNameValues[0], podUIDValues[0]
	if podName == "" || podUID == "" {
		return errExtraFieldsRequired
	}
	pod, err := ic.client.CoreV1().Pods(env.GetAntreaNamespace()).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		return fmt.Errorf("Pod %s not found", podName)
	} else if err != nil {
		return &transientError{err}
	}
	if pod.ObjectMeta.UID != types.UID(podUID) {
		return errPodUIDMismatch
	}
	if pod.Spec.NodeName != nodeName {
		return errPodNotOnNode
	}
	return nil
}

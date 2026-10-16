// Copyright 2026 Antrea Authors
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

// This file tests how "antctl observe" authenticates to FlowStreamService with a client certificate,
// as opposed to the bearer token the stand-in Pod's own ServiceAccount provides (see
// testAntctlObserveBearerTokenAuth). FlowStreamService reads such a certificate from the TLS
// handshake and verifies it against the cluster's client CA, so a certificate has to be issued by the
// cluster, for an identity of its own: here through the CertificateSigningRequest API, with the
// kubernetes.io/kube-apiserver-client signer.

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
)

// generateKeyAndPEM returns a fresh ECDSA key and its PEM encoding.
func generateKeyAndPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// issueClusterClientCert has the cluster's CA issue a client certificate whose identity is the user
// userName (it carries no group), and returns it with its key, both PEM encoded. The certificate is
// short-lived. It does not grant the user anything: see bindClusterRoleToUser.
func issueClusterClientCert(t *testing.T, data *TestData, userName string) (certPEM, keyPEM []byte) {
	key, keyPEM := generateKeyAndPEM(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: userName}}, key)
	require.NoError(t, err)

	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: userName},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
			SignerName:        certificatesv1.KubeAPIServerClientSignerName,
			ExpirationSeconds: ptr.To[int32](3600),
			Usages:            []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
		},
	}
	csrs := data.clientset.CertificatesV1().CertificateSigningRequests()
	_, err = csrs.Create(context.TODO(), csr, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create the CertificateSigningRequest")
	t.Cleanup(func() { assert.NoError(t, csrs.Delete(context.TODO(), userName, metav1.DeleteOptions{})) })

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:    certificatesv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AntctlObserveE2E",
		Message: "client certificate for the antctl observe e2e test",
	})
	_, err = csrs.UpdateApproval(context.TODO(), userName, csr, metav1.UpdateOptions{})
	require.NoError(t, err, "failed to approve the CertificateSigningRequest")

	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		got, err := csrs.Get(ctx, userName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		certPEM = got.Status.Certificate
		return len(certPEM) > 0, nil
	}), "the cluster did not issue a certificate (is kube-controller-manager's CSR signer configured?)")
	return certPEM, keyPEM
}

// issueSelfSignedClientCert returns a client certificate that no cluster CA signed.
func issueSelfSignedClientCert(t *testing.T, userName string) (certPEM, keyPEM []byte) {
	key, keyPEM := generateKeyAndPEM(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: userName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
}

// bindClusterRoleToUser binds a ClusterRole to a user, cluster-wide, for the duration of the test.
func bindClusterRoleToUser(t *testing.T, data *TestData, userName, clusterRole string) {
	name := userName + "-" + clusterRole
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: userName}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole},
	}
	_, err := data.clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})
	require.NoErrorf(t, err, "failed to bind ClusterRole %s to user %s", clusterRole, userName)
	t.Cleanup(func() {
		assert.NoError(t, data.clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), name, metav1.DeleteOptions{}))
	})
}

// writeKubeconfigToStandinPod writes a kubeconfig, built from the given authentication, to a file in
// the shared stand-in Pod and returns its path. server and caData are what the kubeconfig needs to
// reach the Kubernetes API server; tests that never contact it can pass placeholders.
func writeKubeconfigToStandinPod(t *testing.T, data *TestData, name, server string, caData []byte, auth *clientcmdapi.AuthInfo) string {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["c"] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: caData}
	cfg.AuthInfos["u"] = auth
	cfg.Contexts["x"] = &clientcmdapi.Context{Cluster: "c", AuthInfo: "u"}
	cfg.CurrentContext = "x"
	content, err := clientcmd.Write(*cfg)
	require.NoError(t, err)

	path := "/tmp/" + name + ".kubeconfig"
	script := fmt.Sprintf("echo %s | base64 -d > %s", base64.StdEncoding.EncodeToString(content), path)
	_, stderr, err := runAntctlCommandFromPod(data, antctlObservePodName, []string{"sh", "-c", script})
	require.NoErrorf(t, err, "failed to write the kubeconfig into the stand-in Pod: %s", stderr)
	t.Cleanup(func() { _, _, _ = runAntctlCommandFromPod(data, antctlObservePodName, []string{"rm", "-f", path}) })
	return path
}

// testAntctlObserveClientCertAuth covers the credential kind a bearer-token Pod never exercises: a
// client certificate for an identity of its own, as a kubeconfig issued by a cluster admin or an
// identity provider that hands out certificates would carry. It also covers credentials the Flow
// Aggregator must reject (the server's own Unauthenticated, as opposed to
// testAntctlObserveNoCredential, which fails earlier at the Kubernetes API server).
func testAntctlObserveClientCertAuth(t *testing.T, data *TestData) {
	// How the stand-in Pod reaches the API server: it is a host-network Pod, so cluster DNS does not
	// apply, and the kubernetes Service's ClusterIP is what its in-cluster config uses too.
	kubernetesSvc, err := data.clientset.CoreV1().Services(metav1.NamespaceDefault).Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	require.NoError(t, err)
	apiServer := fmt.Sprintf("https://%s:%d", kubernetesSvc.Spec.ClusterIP, kubernetesSvc.Spec.Ports[0].Port)
	caData, stderr, err := runAntctlCommandFromPod(data, antctlObservePodName, []string{"cat", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"})
	require.NoErrorf(t, err, "failed to read the cluster CA from the stand-in Pod: %s", stderr)

	faPods, err := data.getFlowAggregators(flowAggregatorNamespace)
	require.NoError(t, err)
	require.NotEmpty(t, faPods)
	faAddress := fmt.Sprintf("%s:%d", faPods[0].Status.PodIP, 14740)

	t.Run("AuthorizedIdentity", func(t *testing.T) {
		user := "antctl-observe-cert-" + randSeq(6)
		certPEM, keyPEM := issueClusterClientCert(t, data, user)
		// The identity needs what it takes to reach the Flow Aggregator (discovery, port
		// forwarding, its CA), and, separately, permission to observe flows.
		bindClusterRoleToUser(t, data, user, antctlObserveDiscoveryClusterRoleName)
		bindClusterRoleToUser(t, data, user, "antrea-flow-viewer")
		kubeconfig := writeKubeconfigToStandinPod(t, data, user, apiServer, []byte(caData),
			&clientcmdapi.AuthInfo{ClientCertificateData: certPEM, ClientKeyData: keyPEM})

		label := randSeq(8)
		addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
		generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)

		var records []observeRecord
		require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
			stdout, stderr, err := runObserve(data, "--kubeconfig", kubeconfig, "-o", "json", "--selector", "targetLabel="+label)
			if err != nil {
				t.Logf("antctl observe failed, retrying: %v: %s", err, stderr)
				return false, nil
			}
			records = parseObserveJSON(t, stdout)
			return len(records) > 0, nil
		}), "a client certificate for an authorized identity should stream flows")
	})

	t.Run("AuthenticatedButNotAuthorized", func(t *testing.T) {
		// The Flow Aggregator caches authorization decisions, refusals included, for ten minutes, so
		// this identity is never granted anything afterwards, and the test above uses another one.
		user := "antctl-observe-cert-" + randSeq(6)
		certPEM, keyPEM := issueClusterClientCert(t, data, user)
		bindClusterRoleToUser(t, data, user, antctlObserveDiscoveryClusterRoleName)
		kubeconfig := writeKubeconfigToStandinPod(t, data, user, apiServer, []byte(caData),
			&clientcmdapi.AuthInfo{ClientCertificateData: certPEM, ClientKeyData: keyPEM})

		_, stderr, err := runObserve(data, "--max-count", "1", "--kubeconfig", kubeconfig)
		require.Error(t, err)
		// PermissionDenied, not Unauthenticated, is what shows that the certificate was accepted at the
		// TLS layer and resolved to an identity, and that it is that identity that was then refused.
		assert.Contains(t, stderr, "PermissionDenied", "the certificate should have authenticated: %s", stderr)
		assert.NotContains(t, stderr, "Unauthenticated")
		assert.Contains(t, stderr, "flows.observability.antrea.io")
	})

	// What follows connects to the Flow Aggregator's address directly and skips verifying its
	// certificate, so that the kubeconfig's credential is never used against the Kubernetes API
	// server, which would reject it first: it is the Flow Aggregator's verdict that is under test.
	rejected := func(t *testing.T, auth *clientcmdapi.AuthInfo) {
		kubeconfig := writeKubeconfigToStandinPod(t, data, "rejected-"+randSeq(6), "https://127.0.0.1:1", nil, auth)
		_, stderr, err := runObserve(data, "--max-count", "1", "--kubeconfig", kubeconfig,
			"--flow-aggregator-address", faAddress, "--flow-aggregator-namespace", flowAggregatorNamespace, "--insecure-skip-tls-verify")
		require.Error(t, err)
		assert.Contains(t, stderr, "Unauthenticated", "the Flow Aggregator should have rejected the credential: %s", stderr)
		assert.True(t, strings.Contains(stderr, "client certificate signed by the cluster's client CA"),
			"the error should say what the Flow Aggregator accepts: %s", stderr)
	}

	t.Run("CertificateNotSignedByTheClusterCA", func(t *testing.T) {
		certPEM, keyPEM := issueSelfSignedClientCert(t, "antctl-observe-self-signed")
		rejected(t, &clientcmdapi.AuthInfo{ClientCertificateData: certPEM, ClientKeyData: keyPEM})
	})

	t.Run("InvalidBearerToken", func(t *testing.T) {
		rejected(t, &clientcmdapi.AuthInfo{Token: "not-a-real-token"})
	})
}

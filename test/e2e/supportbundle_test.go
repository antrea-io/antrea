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

package e2e

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/apis"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/features"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
	"antrea.io/antrea/test/e2e/utils/portforwarder"
)

// getAccessToken retrieves the local access token of an antrea component API server.
func getAccessToken(podName string, containerName string, tokenPath string, data *TestData) (string, error) {
	stdout, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, podName, containerName, []string{"cat", tokenPath})
	if err != nil {
		return "", err
	}
	return stdout, nil
}

// testSupportBundle tests all support bundle related APIs.
func testSupportBundle(name string, t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var podName string
	var podPort int
	if name == "controller" {
		var pod *v1.Pod
		pod, err = data.getAntreaController()
		require.NoError(t, err)
		podName = pod.Name
		podPort = apis.AntreaControllerAPIPort
	} else {
		podName, err = data.getAntreaPodOnNode(controlPlaneNodeName())
		require.NoError(t, err)
		podPort = apis.AntreaAgentAPIPort
	}
	// Acquire token.
	token, err := getAccessToken(podName, fmt.Sprintf("antrea-%s", name), apis.APIServerLoopbackTokenPath, data)
	require.NoError(t, err)
	podIP, err := data.podWaitForIPs(defaultTimeout, podName, metav1.NamespaceSystem)
	require.NoError(t, err)

	for _, podIPStr := range podIP.IPStrings {
		getAndCheckSupportBundle(t, name, podIPStr, podPort, token, podName, data)
	}
}

func getAndCheckSupportBundle(t *testing.T, name, podIP string, podPort int, token string, podName string, data *TestData) {
	// Setup clients.
	localConfig := rest.CopyConfig(data.kubeConfig)
	pf, err := portforwarder.NewPortForwarder(localConfig, metav1.NamespaceSystem, podName, podPort, "localhost", 8080)
	require.NoError(t, err)
	pf.Start()
	defer pf.Stop()
	localConfig.Host = net.JoinHostPort("localhost", "8080")
	localConfig.BearerToken = token
	localConfig.Insecure = true
	localConfig.CAFile = ""
	localConfig.CAData = nil
	clients, err := clientset.NewForConfig(localConfig)
	require.NoError(t, err)
	// Clearing any existing support bundle.
	err = clients.SystemV1beta1().SupportBundles().Delete(context.TODO(), name, metav1.DeleteOptions{})
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	// Checking the initial status.
	bundle, err := clients.SystemV1beta1().SupportBundles().Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.SupportBundleStatusNone, bundle.Status)
	// Creating a new support bundle.
	bundle, err = clients.SystemV1beta1().SupportBundles().Create(context.TODO(), &systemv1beta1.SupportBundle{ObjectMeta: metav1.ObjectMeta{Name: name}}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.SupportBundleStatusCollecting, bundle.Status)
	// Waiting for the generation to be completed.
	ddl := time.After(defaultTimeout)
	err = wait.PollUntilContextCancel(context.TODO(), 200*time.Millisecond, true, func(ctx context.Context) (done bool, err error) {
		select {
		case <-ddl:
			return false, fmt.Errorf("collecting timeout")
		default:
		}
		bundle, err = clients.SystemV1beta1().SupportBundles().Get(context.TODO(), name, metav1.GetOptions{})
		require.NoError(t, err)
		return bundle.Status == systemv1beta1.SupportBundleStatusCollected, nil
	})
	require.NoError(t, err)
	// Checking the complete status.
	bundle, err = clients.SystemV1beta1().SupportBundles().Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.SupportBundleStatusCollected, bundle.Status)
	// Downloading the bundle and verifying sha256sum.
	readStream, err := clients.SystemV1beta1().RESTClient().
		Get().
		Resource("supportbundles").
		Name(name).
		SubResource("download").
		Stream(context.TODO())
	require.NoError(t, err)
	defer readStream.Close()
	hasher := sha256.New()
	_, err = io.Copy(hasher, readStream)
	require.NoError(t, err)
	require.Equal(t, bundle.Sum, fmt.Sprintf("%x", hasher.Sum(nil)))
	// Deleting the bundle.
	err = clients.SystemV1beta1().SupportBundles().Delete(context.TODO(), name, metav1.DeleteOptions{})
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	// Checking that the bundle was deleted.
	bundle, err = clients.SystemV1beta1().SupportBundles().Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.SupportBundleStatusNone, bundle.Status)

}

func TestSupportBundleController(t *testing.T) {
	testSupportBundle("controller", t)
}

func TestSupportBundleAgent(t *testing.T) {
	testSupportBundle("agent", t)
}

func TestSupportBundleCollection(t *testing.T) {
	skipIfFeatureDisabled(t, features.SupportBundleCollection, true, true)
	skipIfHasWindowsNodes(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	deployment, svc, pubKeys, err := data.deploySFTPServer(context.TODO(), 0)
	require.NoError(t, err, "failed to deploy SFTP server")
	require.NotEmpty(t, pubKeys)
	require.NoError(t, data.waitForDeploymentReady(t, deployment.Namespace, deployment.Name, defaultTimeout))
	require.NotEmpty(t, svc.Spec.ClusterIP)

	secretName := "support-bundle-secret"
	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: antreaNamespace,
		},
		Data: map[string][]byte{
			"username": []byte(sftpUser),
			"password": []byte(sftpPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(sec.Namespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(sec.Namespace).Delete(context.TODO(), sec.Name, metav1.DeleteOptions{})

	grantAntreaAccessToSecret(t, data, secretName)

	clientPod := "client"
	require.NoError(t, data.createToolboxPodOnNode(clientPod, data.testNamespace, "", false))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientPod, data.testNamespace))

	invalidPubKey, _, err := sftptesting.GenerateEd25519Key()
	require.NoError(t, err)

	// If cluster has more than 3 Nodes, only consider the first 3.
	const maxNodes = 3
	var nodeNames []string
	for idx := 0; idx < min(maxNodes, clusterInfo.numNodes); idx++ {
		nodeNames = append(nodeNames, nodeName(idx))
	}
	sortedNodeNames := slices.Sorted(slices.Values(nodeNames))

	expectedStatusSuccess := crdv1alpha1.SupportBundleCollectionStatus{
		CollectedNodes: int32(len(nodeNames)),
		DesiredNodes:   int32(len(nodeNames)),
		Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
			{
				Type:   crdv1alpha1.CollectionStarted,
				Status: metav1.ConditionStatus(v1.ConditionTrue),
			},
			{
				Type:   crdv1alpha1.BundleCollected,
				Status: metav1.ConditionStatus(v1.ConditionTrue),
			},
			{
				Type:   crdv1alpha1.CollectionFailure,
				Status: metav1.ConditionStatus(v1.ConditionFalse),
			},
			{
				Type:   crdv1alpha1.CollectionCompleted,
				Status: metav1.ConditionStatus(v1.ConditionTrue),
			},
		},
	}

	t.Run("with ssh host key", func(t *testing.T) {
		testSupportBundleCollection(t, data, "sbc-0", nodeNames, clientPod, svc.Spec.ClusterIP, pubKeys[0].Marshal(), expectedStatusSuccess)
	})
	t.Run("without ssh host key", func(t *testing.T) {
		testSupportBundleCollection(t, data, "sbc-1", nodeNames, clientPod, svc.Spec.ClusterIP, nil, expectedStatusSuccess)
	})
	t.Run("with invalid ssh host key", func(t *testing.T) {
		expectedStatus := crdv1alpha1.SupportBundleCollectionStatus{
			CollectedNodes: 0,
			DesiredNodes:   int32(len(nodeNames)),
			Conditions: []crdv1alpha1.SupportBundleCollectionCondition{
				{
					Type:   crdv1alpha1.CollectionStarted,
					Status: metav1.ConditionStatus(v1.ConditionTrue),
				},
				{
					Type:   crdv1alpha1.BundleCollected,
					Status: metav1.ConditionStatus(v1.ConditionFalse),
				},
				{
					Type:    crdv1alpha1.CollectionFailure,
					Status:  metav1.ConditionStatus(v1.ConditionTrue),
					Reason:  "InternalError",
					Message: fmt.Sprintf("Failed Agent count: %d, \"failed to upload file after 5 attempts\":[%s]", len(nodeNames), strings.Join(sortedNodeNames, ", ")),
				},
				{
					Type:   crdv1alpha1.CollectionCompleted,
					Status: metav1.ConditionStatus(v1.ConditionTrue),
				},
			},
		}
		// The key is correctly formatted but does not match the server's keys.
		testSupportBundleCollection(t, data, "sbc-2", nodeNames, clientPod, svc.Spec.ClusterIP, invalidPubKey.Marshal(), expectedStatus)
	})
}

func testSupportBundleCollection(
	t *testing.T,
	data *TestData,
	bundleName string,
	nodeNames []string,
	clientPod string,
	sftpServerIP string,
	pubKey []byte,
	expectedStatus crdv1alpha1.SupportBundleCollectionStatus,
) {
	sftpURL := fmt.Sprintf("sftp://%s/%s", sftpServerIP, sftpUploadDir)

	// First, create a dedicated upload directory for this test case.
	cmd := []string{"curl", "--insecure", "--user", fmt.Sprintf("%s:%s", sftpUser, sftpPassword), "-Q", fmt.Sprintf("mkdir %s/%s", sftpUploadDir, bundleName), sftpURL + "/"}
	stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPod, toolboxContainerName, cmd)
	require.NoErrorf(t, err, "failed to create upload directory with sftp, stdout: %s, stderr: %s", stdout, stderr)

	sbc := &crdv1alpha1.SupportBundleCollection{
		ObjectMeta: metav1.ObjectMeta{
			Name: bundleName,
		},
		Spec: crdv1alpha1.SupportBundleCollectionSpec{
			Nodes: &crdv1alpha1.BundleNodes{
				NodeNames: nodeNames,
			},
			ExpirationMinutes: 300,
			FileServer: crdv1alpha1.BundleFileServer{
				URL:           fmt.Sprintf("%s:22/%s/%s", sftpServerIP, sftpUploadDir, bundleName),
				HostPublicKey: pubKey,
			},
			Authentication: crdv1alpha1.BundleServerAuthConfiguration{
				AuthType: "BasicAuthentication",
				AuthSecret: &v1.SecretReference{
					Name:      "support-bundle-secret",
					Namespace: antreaNamespace,
				},
			},
		},
	}
	_, err = data.crdClient.CrdV1alpha1().SupportBundleCollections().Create(context.TODO(), sbc, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.crdClient.CrdV1alpha1().SupportBundleCollections().Delete(context.TODO(), bundleName, metav1.DeleteOptions{})
	sbc, err = data.waitForSupportBundleCollectionCompleted(t, bundleName, 30*time.Second)
	require.NoError(t, err)

	require.True(t, supportBundleCollectionStatusEqual(sbc.Status, expectedStatus))

	condFailure := findSupportBundleCollectionCondition(sbc.Status.Conditions, crdv1alpha1.CollectionFailure)
	if condFailure != nil && condFailure.Status == metav1.ConditionTrue || sbc.Status.CollectedNodes != int32(len(nodeNames)) {
		// don't check for uploaded files in case of failure
		return
	}

	// Finally, we check that the expected files have been uploaded the server, but we do not
	// check their contents.
	// --list-only is to ensure that the output only includes file names, with no additional metadata
	cmd = []string{"curl", "--insecure", "--list-only", "--user", fmt.Sprintf("%s:%s", sftpUser, sftpPassword), fmt.Sprintf("%s/%s/", sftpURL, bundleName)}
	stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, clientPod, toolboxContainerName, cmd)
	require.NoErrorf(t, err, "failed to list upload directory with sftp, stdout: %s, stderr: %s", stdout, stderr)
	files := slices.DeleteFunc(strings.Fields(stdout), func(fileName string) bool {
		// Remove symbolic links "." and ".."
		return strings.HasPrefix(fileName, ".")
	})
	expectedFiles := make([]string, len(nodeNames))
	for idx := range nodeNames {
		expectedFiles[idx] = fmt.Sprintf("%s_%s.tar.gz", nodeNames[idx], bundleName)
	}
	assert.ElementsMatch(t, expectedFiles, files, "files uploaded by Antrea to sftp server do not match expectations")
}

func (data *TestData) waitForSupportBundleCollection(
	t *testing.T,
	name string,
	timeout time.Duration,
	condition func(*crdv1alpha1.SupportBundleCollection) bool,
) (*crdv1alpha1.SupportBundleCollection, error) {
	var sbc *crdv1alpha1.SupportBundleCollection
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		c, err := data.crdClient.CrdV1alpha1().SupportBundleCollections().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		sbc = c
		if condition(sbc) {
			return true, nil
		}
		return false, nil
	}); err != nil {
		if sbc != nil {
			t.Logf("Status for SupportBundleCollection: %+v", sbc.Status)
		}
		return nil, err
	}
	return sbc, nil
}

func findSupportBundleCollectionCondition(conditions []crdv1alpha1.SupportBundleCollectionCondition, t crdv1alpha1.SupportBundleCollectionConditionType) *crdv1alpha1.SupportBundleCollectionCondition {
	for idx := range conditions {
		cond := &conditions[idx]
		if cond.Type == t {
			return cond
		}
	}
	return nil
}

func (data *TestData) waitForSupportBundleCollectionCompleted(t *testing.T, name string, timeout time.Duration) (*crdv1alpha1.SupportBundleCollection, error) {
	t.Logf("Waiting for SupportBundleCollection '%s' to be completed", name)
	return data.waitForSupportBundleCollection(t, name, timeout, func(sbc *crdv1alpha1.SupportBundleCollection) bool {
		cond := findSupportBundleCollectionCondition(sbc.Status.Conditions, crdv1alpha1.CollectionCompleted)
		return cond != nil && cond.Status == metav1.ConditionTrue
	})
}

func supportBundleCollectionConditionEqual(c1, c2 crdv1alpha1.SupportBundleCollectionCondition) bool {
	c1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	c2.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return c1 == c2
}

var supportBundleCollectionStatusSemanticEquality = conversion.EqualitiesOrDie(
	supportBundleCollectionConditionSliceEqual,
)

func supportBundleCollectionStatusEqual(status1, status2 crdv1alpha1.SupportBundleCollectionStatus) bool {
	return supportBundleCollectionStatusSemanticEquality.DeepEqual(status1, status2)
}

func supportBundleCollectionConditionSliceEqual(s1, s2 []crdv1alpha1.SupportBundleCollectionCondition) bool {
	sort.Slice(s1, func(i, j int) bool {
		return s1[i].Type < s1[j].Type
	})
	sort.Slice(s2, func(i, j int) bool {
		return s2[i].Type < s2[j].Type
	})

	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		a := s1[i]
		b := s2[i]
		if !supportBundleCollectionConditionEqual(a, b) {
			return false
		}
	}
	return true
}

func grantAntreaAccessToSecret(t *testing.T, data *TestData, secretName string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:         []string{"get"},
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{secretName},
			},
		},
	}
	_, err := data.clientset.RbacV1().Roles(antreaNamespace).Create(context.TODO(), role, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		err := data.clientset.RbacV1().Roles(antreaNamespace).Delete(context.TODO(), role.Name, metav1.DeleteOptions{})
		assert.NoError(t, err)
	})

	for _, serviceAccount := range []string{"antrea-controller", "antrea-agent"} {
		name := fmt.Sprintf("%s-%s", serviceAccount, secretName)
		roleBinding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccount,
					Namespace: antreaNamespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     secretName,
			},
		}
		_, err := data.clientset.RbacV1().RoleBindings(antreaNamespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
		require.NoError(t, err)
		t.Cleanup(func() {
			err := data.clientset.RbacV1().RoleBindings(antreaNamespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
			assert.NoError(t, err)
		})
	}
}

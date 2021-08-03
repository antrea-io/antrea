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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	agentapiserver "antrea.io/antrea/pkg/agent/apiserver"
	"antrea.io/antrea/pkg/apis"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	controllerapiserver "antrea.io/antrea/pkg/apiserver"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

// getAccessToken retrieves the local access token of an antrea component API server.
func getAccessToken(podName string, containerName string, tokenPath string, data *TestData) (string, error) {
	stdout, _, err := data.runCommandFromPod(metav1.NamespaceSystem, podName, containerName, []string{"cat", tokenPath})
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

	var podName, podPort, tokenPath string
	if name == "controller" {
		var pod *v1.Pod
		pod, err = data.getAntreaController()
		require.NoError(t, err)
		podName = pod.Name
		podPort = fmt.Sprint(apis.AntreaControllerAPIPort)
		tokenPath = controllerapiserver.TokenPath
	} else {
		podName, err = data.getAntreaPodOnNode(controlPlaneNodeName())
		require.NoError(t, err)
		podPort = fmt.Sprint(apis.AntreaAgentAPIPort)
		tokenPath = agentapiserver.TokenPath
	}
	// Acquire token.
	token, err := getAccessToken(podName, fmt.Sprintf("antrea-%s", name), tokenPath, data)
	require.NoError(t, err)
	podIP, err := data.podWaitForIPs(defaultTimeout, podName, metav1.NamespaceSystem)
	require.NoError(t, err)

	for _, podIPStr := range podIP.ipStrings {
		getAndCheckSupportBundle(t, name, podIPStr, podPort, token, data)
	}
}

func getAndCheckSupportBundle(t *testing.T, name, podIP, podPort, token string, data *TestData) {
	// Setup clients.
	localConfig := rest.CopyConfig(data.kubeConfig)
	localConfig.Host = net.JoinHostPort(podIP, podPort)
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
	err = wait.PollImmediateUntil(200*time.Millisecond, func() (done bool, err error) {
		select {
		case <-ddl:
			return false, fmt.Errorf("collecting timeout")
		default:
		}
		bundle, err = clients.SystemV1beta1().SupportBundles().Get(context.TODO(), name, metav1.GetOptions{})
		require.NoError(t, err)
		return bundle.Status == systemv1beta1.SupportBundleStatusCollected, nil
	}, nil)
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

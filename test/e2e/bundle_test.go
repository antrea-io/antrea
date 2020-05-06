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
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	agentapiserver "github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/apis"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	controllerapiserver "github.com/vmware-tanzu/antrea/pkg/apiserver"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

// getAccessToken retrieves the local access token of an antrea component API server.
func getAccessToken(podName string, containerName string, tokenPath string, data *TestData) (string, error) {
	stdout, _, err := data.runCommandFromPod(metav1.NamespaceSystem, podName, containerName, []string{"cat", tokenPath})
	if err != nil {
		return "", err
	}
	return stdout, nil
}

// testBundle tests all bundle related APIs.
func testBundle(name string, t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var podName, podPort, tokenPath string
	if name == "controller" {
		podName, err = data.getAntreaController()
		podPort = fmt.Sprint(apis.AntreaControllerAPIPort)
		tokenPath = controllerapiserver.TokenPath
	} else {
		podName, err = data.getAntreaPodOnNode(masterNodeName())
		podPort = fmt.Sprint(apis.AntreaAgentAPIPort)
		tokenPath = agentapiserver.TokenPath
	}
	require.NoError(t, err)
	// acquired token.
	token, err := getAccessToken(podName, fmt.Sprintf("antrea-%s", name), tokenPath, data)
	require.NoError(t, err)
	podIP, err := data.podWaitForIP(defaultTimeout, podName, metav1.NamespaceSystem)
	require.NoError(t, err)
	// setup clients.
	localConfig := rest.CopyConfig(data.kubeConfig)
	localConfig.Host = net.JoinHostPort(podIP, podPort)
	localConfig.BearerToken = token
	localConfig.Insecure = true
	localConfig.CAFile = ""
	localConfig.CAData = nil
	clients, err := clientset.NewForConfig(localConfig)
	require.NoError(t, err)
	// Clearing any exists bundle.
	err = clients.SystemV1beta1().Bundles().Delete(name, &metav1.DeleteOptions{})
	require.NoError(t, nil)
	time.Sleep(100 * time.Millisecond)
	// Checking the initial status.
	bundle, err := clients.SystemV1beta1().Bundles().Get(name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.BundleStatusNone, bundle.Status)
	// Creating a new bundle.
	bundle, err = clients.SystemV1beta1().Bundles().Create(&systemv1beta1.Bundle{ObjectMeta: metav1.ObjectMeta{Name: name}})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.BundleStatusCollecting, bundle.Status)
	// Waiting the generation to be completed.
	ddl := time.After(defaultTimeout)
	err = wait.PollImmediateUntil(200*time.Millisecond, func() (done bool, err error) {
		select {
		case <-ddl:
			return false, fmt.Errorf("collecting timeout")
		default:
		}
		bundle, err = clients.SystemV1beta1().Bundles().Get(name, metav1.GetOptions{})
		require.NoError(t, err)
		return bundle.Status == systemv1beta1.BundleStatusCollected, nil
	}, nil)
	require.NoError(t, err)
	// Checking the complete status.
	bundle, err = clients.SystemV1beta1().Bundles().Get(name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.BundleStatusCollected, bundle.Status)
	// Downloading the bundle and verify sha256sum.
	readStream, err := clients.SystemV1beta1().RESTClient().
		Get().
		Resource("bundles").
		Name(name).
		SubResource("download").
		Stream()
	require.NoError(t, err)
	defer readStream.Close()
	hasher := sha256.New()
	_, err = io.Copy(hasher, readStream)
	require.NoError(t, err)
	require.Equal(t, bundle.Sum, fmt.Sprintf("%x", hasher.Sum(nil)))
	// Deleting the bundle.
	err = clients.SystemV1beta1().Bundles().Delete(name, &metav1.DeleteOptions{})
	require.NoError(t, nil)
	time.Sleep(100 * time.Millisecond)
	// Checking if the bundle deleted.
	bundle, err = clients.SystemV1beta1().Bundles().Get(name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, systemv1beta1.BundleStatusNone, bundle.Status)
}

func TestBundleController(t *testing.T) {
	testBundle("controller", t)
}

func TestBundleAgent(t *testing.T) {
	testBundle("agent", t)
}

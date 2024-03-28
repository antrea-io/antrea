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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	certutil "k8s.io/client-go/util/cert"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/certificate"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	// Namespace and name of the Secret that holds user-provided TLS certificate.
	tlsSecretNamespace = "kube-system"
	tlsSecretName      = "antrea-controller-tls"

	caConfigMapNamespace = "kube-system"
)

// TestSecurity is the top-level test which contains all subtests for
// Security related test cases so they can share setup, teardown.
func TestSecurity(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testUserProvidedCert", func(t *testing.T) { testUserProvidedCert(t, data) })
	t.Run("testSelfSignedCert", func(t *testing.T) { testSelfSignedCert(t, data) })
}

// testUserProvidedCert tests the selfSignedCert=false case. It covers dynamic server certificate.
func testUserProvidedCert(t *testing.T, data *TestData) {
	// Re-configure antrea-controller to use user-provided cert.
	// Note antrea-controller must be restarted to take effect.
	cc := func(config *controllerconfig.ControllerConfig) {
		config.SelfSignedCert = new(bool)
		*config.SelfSignedCert = false
	}
	if err := data.mutateAntreaConfigMap(cc, nil, false, false); err != nil {
		t.Fatalf("Failed to update ConfigMap: %v", err)
	}
	t.Cleanup(func() {
		data.mutateAntreaConfigMap(func(config *controllerconfig.ControllerConfig) {
			config.SelfSignedCert = nil
		}, nil, true, false)
	})

	genCertKeyAndUpdateSecret := func() ([]byte, []byte) {
		certPem, keyPem, _ := certutil.GenerateSelfSignedCertKey("antrea", nil, k8s.GetServiceDNSNames("kube-system", apis.AntreaServiceName))
		secret, err := data.clientset.CoreV1().Secrets(tlsSecretNamespace).Get(context.TODO(), tlsSecretName, metav1.GetOptions{})
		exists := true
		if err != nil {
			if !errors.IsNotFound(err) {
				t.Fatalf("Failed to get Secret %s: %v", tlsSecretName, err)
			}
			exists = false
			secret = &v1.Secret{
				Data: map[string][]byte{
					certificate.CACertFile:  certPem,
					certificate.TLSCertFile: certPem,
					certificate.TLSKeyFile:  keyPem,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      tlsSecretName,
					Namespace: tlsSecretNamespace,
				},
				Type: v1.SecretTypeTLS,
			}
		}
		secret.Data = map[string][]byte{
			certificate.CACertFile:  certPem,
			certificate.TLSCertFile: certPem,
			certificate.TLSKeyFile:  keyPem,
		}
		if exists {
			if _, err := data.clientset.CoreV1().Secrets(tlsSecretNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
				t.Fatalf("Failed to update Secret %s: %v", tlsSecretName, err)
			}
		} else {
			if _, err := data.clientset.CoreV1().Secrets(tlsSecretNamespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
				t.Fatalf("Failed to create Secret %s: %v", tlsSecretName, err)
			}
		}
		return certPem, keyPem
	}

	// Create/update the secret and restart antrea-controller, then verify apiserver and its clients are using the
	// provided certificate.
	certPem, _ := genCertKeyAndUpdateSecret()
	t.Cleanup(func() {
		data.clientset.CoreV1().Secrets(tlsSecretNamespace).Delete(context.TODO(), tlsSecretName, metav1.DeleteOptions{})
	})
	testCert(t, data, string(certPem), true)

	// Update the secret and do not restart antrea-controller, then verify apiserver and its clients are using the
	// new certificate.
	certPem, _ = genCertKeyAndUpdateSecret()
	testCert(t, data, string(certPem), false)
}

// testSelfSignedCert tests the selfSignedCert=true case.
func testSelfSignedCert(t *testing.T, data *TestData) {
	secretBeforeRestart, err := data.clientset.CoreV1().Secrets(tlsSecretNamespace).Get(context.TODO(), tlsSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	testCert(t, data, string(secretBeforeRestart.Data[certificate.TLSCertFile]), true)

	secretAfterRestart, err := data.clientset.CoreV1().Secrets(tlsSecretNamespace).Get(context.TODO(), tlsSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, secretBeforeRestart, secretAfterRestart)
}

// testCert optionally restarts antrea-controller, then checks:
// 1. The CA bundle published in antrea-ca ConfigMap matches expectedCABundle if provided.
// 1. The CA bundle published in antrea-ca ConfigMap can be used to verify antrea-controller's serving cert.
// 2. The CA bundle in Antrea APIServices match the one in antrea-ca ConfigMap.
// 3. All antrea-agents can use the CA bundle to verify antrea-controller's serving cert.
func testCert(t *testing.T, data *TestData, expectedCABundle string, restartPod bool) {
	var antreaController *v1.Pod
	var err error
	// We expect the CA to be published very soon after antrea-controller restarts, while it may take up to 2 minutes
	// (1 minute kubelet sync period + 1 minute DynamicFileCAContent sync period) to detect the certificate change if
	// antrea-controller doesn't restart.
	timeout := 10 * time.Second
	if restartPod {
		antreaController, err = data.restartAntreaControllerPod(defaultTimeout)
		if err != nil {
			t.Fatalf("Error when restarting antrea-controller Pod: %v", err)
		}
	} else {
		antreaController, err = data.getAntreaController()
		if err != nil {
			t.Fatalf("Error when getting antrea-controller Pod: %v", err)
		}
		timeout += 2 * time.Minute
	}

	var caBundle string
	var configMap *v1.ConfigMap
	if err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		var err error
		configMap, err = data.clientset.CoreV1().ConfigMaps(caConfigMapNamespace).Get(context.TODO(), apis.AntreaCAConfigMapName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("cannot get ConfigMap antrea-ca")
		}
		var exists bool
		caBundle, exists = configMap.Data[apis.CAConfigMapKey]
		if !exists {
			t.Log("Missing content for CA bundle, retrying")
			return false, nil
		}

		if expectedCABundle != "" && expectedCABundle != caBundle {
			t.Log("CA bundle doesn't match the expected one, retrying")
			return false, nil
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Failed to get CA bundle availability: %v", err)
	}

	// We create a test Pod which needs access to the CA bundle.
	// Because this Pod will be created inside the test Namespace, it will not have direct access to the antrea-ca ConfigMap,
	// which is in the kube-system Namespace. Therefore, we make a "copy" of the antrea-ca ConfigMap in the test Namespace.
	configMapCopy := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "antrea-ca-e2e",
			Namespace: data.testNamespace,
		},
		Data: configMap.Data,
	}
	if _, err := data.clientset.CoreV1().ConfigMaps(data.testNamespace).Create(context.TODO(), &configMapCopy, metav1.CreateOptions{}); err != nil {
		t.Errorf("Error when creating ConfigMap %s: %v", configMapCopy.Name, err)
	}
	defer func() {
		if err := data.clientset.CoreV1().ConfigMaps(data.testNamespace).Delete(context.TODO(), configMapCopy.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting ConfigMap %s: %v", configMapCopy.Name, err)
		}
	}()

	caFile := "/etc/config/ca.crt"
	clientName := "agnhost"
	reqURL := fmt.Sprintf("https://%s/readyz", k8s.GetServiceDNSNames("kube-system", apis.AntreaServiceName)[0])
	cmd := []string{"curl", "--cacert", caFile, "-s", reqURL}
	require.NoError(t, NewPodBuilder(clientName, data.testNamespace, agnhostImage).WithContainerName(getImageName(agnhostImage)).MountConfigMap(configMapCopy.Name, "/etc/config/", "config-volume").WithHostNetwork(false).Create(data))
	defer data.DeletePodAndWait(defaultTimeout, clientName, data.testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientName, data.testNamespace))
	if err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientName, agnhostContainerName, cmd)
		if err != nil {
			t.Logf("error when running cmd: %v , stdout: <%v>, stderr: <%v>", err, stdout, stderr)
			return false, err
		}
		t.Logf("The CABundle in ConfigMap antrea-ca is valid")
		return true, nil
	}); err != nil {
		t.Fatalf("Failed to get a valid CA cert from ConfigMap: %v", err)
	}

	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea",
	}
	apiServices, err := data.aggregatorClient.ApiregistrationV1().APIServices().List(context.TODO(), listOptions)
	if err != nil {
		t.Fatalf("Failed to list Antrea APIServices: %v", err)
	}
	for _, apiService := range apiServices.Items {
		if caBundle != string(apiService.Spec.CABundle) {
			t.Logf("The CABundle in APIService %s is invalid", apiService.Name)
		}
		t.Logf("The CABundle in APIService %s is valid", apiService.Name)
	}

	// antrea-agents reconnect every 5 seconds, we expect their connections are restored in a few seconds.
	if err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		cmds := []string{"antctl", "get", "controllerinfo", "-o", "json"}
		stdout, _, err := runAntctl(antreaController.Name, cmds, data)
		if err != nil {
			return true, err
		}
		var controllerInfo v1beta1.AntreaControllerInfo
		err = json.Unmarshal([]byte(stdout), &controllerInfo)
		if err != nil {
			return true, err
		}
		if clusterInfo.numNodes != int(controllerInfo.ConnectedAgentNum) {
			t.Logf("Expected %d connected agents, got %d", clusterInfo.numNodes, controllerInfo.ConnectedAgentNum)
			return false, nil
		}
		t.Logf("Got connections from all %d antrea-agents", clusterInfo.numNodes)
		return true, nil
	}); err != nil {
		t.Fatalf("Didn't get connections from all %d antrea-agents: %v", clusterInfo.numNodes, err)
	}
}

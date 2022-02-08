// Copyright 2021 Antrea Authors
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
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreae2e "antrea.io/antrea/test/e2e"
	e2euttils "antrea.io/antrea/test/e2e/utils"
)

func (data *MCTestData) setupTestResources(t *testing.T) string {
	podName := randName(nginxPodName)
	createPodAndService := func(clusterName, clusterServiceName string) {
		if err := createPodWrapper(t, data, clusterName, multiClusterTestNamespace, podName, "", nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
			t.Fatalf("Error when creating nginx Pod in cluster %s: %v", clusterName, err)
		}
		if _, err := data.createService(clusterName, clusterServiceName, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
			false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
			t.Fatalf("Error when creating Service %s in cluster %s: %v", clusterServiceName, clusterName, err)
		}
	}
	// Create Pod and Service in west and ease cluster
	createPodAndService(westCluster, westClusterTestService)
	createPodAndService(eastCluster, eastClusterTestService)
	return podName
}

func (data *MCTestData) tearDownTestResources(t *testing.T, podName string) {
	deleteServiceWrapper(t, testData, westCluster, multiClusterTestNamespace, westClusterTestService)
	deleteServiceWrapper(t, testData, eastCluster, multiClusterTestNamespace, eastClusterTestService)
	deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, podName)
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName)
}

// Deploy service exports in east and west clusters
func setUpServiceExport(data *MCTestData, t *testing.T) {
	if err := data.deployServiceExport(westCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in west cluster: %v", err)
	}
	if err := data.deployServiceExport(eastCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in east cluster: %v", err)
	}
	time.Sleep(importServiceDelay)
}

func tearDownServiceExport(data *MCTestData) {
	data.deleteServiceExport(westCluster)
	data.deleteServiceExport(eastCluster)
}

// Try to curl the counter part services in east and west clusters.
// If we get status code 200, it means that the resources is exported by the east cluster
// and imported by the west cluster.
func testProbeMCService(t *testing.T, data *MCTestData) {
	data.testProbeMCService(t)
}

func testANP(t *testing.T, data *MCTestData) {
	data.testANP(t)
}

func (data *MCTestData) testProbeMCService(t *testing.T) {
	data.probeMCServiceFromCluster(t, eastCluster, westClusterTestService)
	data.probeMCServiceFromCluster(t, westCluster, eastClusterTestService)
}

func (data *MCTestData) testANP(t *testing.T) {
	clientPodName := "test-service-client"
	svc, err := data.getService(eastCluster, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", westClusterTestService))
	if err != nil {
		t.Fatalf("Error when getting the imported service %s: %v", fmt.Sprintf("antrea-mc-%s", westClusterTestService), err)
	}

	eastIP := svc.Spec.ClusterIP
	gwClientName := clientPodName + "-gateway"
	regularClientName := clientPodName + "-regularnode"

	createEastPod := func(nodeName string, podName string) {
		if err := data.createPod(eastCluster, podName, nodeName, multiClusterTestNamespace, "client", agnhostImage,
			[]string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, false, nil); err != nil {
			t.Fatalf("Error when creating client Pod in east cluster: %v", err)
		}
		t.Logf("Checking Pod status %s in Namespace %s of cluster %s", podName, multiClusterTestNamespace, eastCluster)
		_, err := data.podWaitFor(defaultTimeout, eastCluster, podName, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
			return pod.Status.Phase == corev1.PodRunning, nil
		})
		if err != nil {
			deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName)
			t.Fatalf("Error when waiting for Pod '%s' in east cluster: %v", podName, err)
		}
	}

	// Create a Pod in east cluster's Gateway and verify the MC Service connectivity from it.
	createEastPod(data.clusterGateways[eastCluster], gwClientName)
	defer deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, gwClientName)

	t.Logf("Probing Service from client Pod %s in cluster %s", gwClientName, eastCluster)
	if err := data.probeServiceFromPodInCluster(eastCluster, gwClientName, "client", multiClusterTestNamespace, eastIP); err != nil {
		t.Fatalf("Error when probing Service from client Pod %s in cluster %s, err: %v", gwClientName, eastCluster, err)
	}

	// Create a Pod in east cluster's regular Node and verify the MC Service connectivity from it.
	createEastPod(data.clusterRegularNodes[eastCluster], regularClientName)
	defer deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, regularClientName)

	t.Logf("Probing Service from client Pod %s in cluster %s", regularClientName, eastCluster)
	if err := data.probeServiceFromPodInCluster(eastCluster, regularClientName, "client", multiClusterTestNamespace, eastIP); err != nil {
		t.Fatalf("Error when probing Service from client Pod %s in cluster %s, err: %v", regularClientName, eastCluster, err)
	}

	// Create a Pod in west cluster and verify the MC Service connectivity from it.
	if err := data.createPod(westCluster, clientPodName, "", multiClusterTestNamespace, "client", agnhostImage,
		[]string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating client Pod in west cluster: %v", err)
	}
	defer deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, clientPodName)
	_, err = data.podWaitFor(defaultTimeout, westCluster, clientPodName, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		t.Fatalf("Error when waiting for Pod '%s' in west cluster: %v", clientPodName, err)
	}

	svc, err = data.getService(westCluster, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", eastClusterTestService))
	if err != nil {
		t.Fatalf("Error when getting the imported service %s: %v", fmt.Sprintf("antrea-mc-%s", eastClusterTestService), err)
	}
	westIP := svc.Spec.ClusterIP
	if err := data.probeServiceFromPodInCluster(westCluster, clientPodName, "client", multiClusterTestNamespace, westIP); err != nil {
		t.Fatalf("Error when probing service from %s, err: %v", westCluster, err)
	}

	// Verify that ACNP works fine with new Multicluster Service.
	data.verifyMCServiceACNP(t, gwClientName, eastIP)
}

func (data *MCTestData) probeMCServiceFromCluster(t *testing.T, clusterName string, serviceName string) string {
	svc, err := data.getService(clusterName, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", serviceName))
	if err != nil {
		t.Fatalf("Error when getting the imported service %s: %v", fmt.Sprintf("antrea-mc-%s", serviceName), err)
	}

	ip := svc.Spec.ClusterIP
	if err := data.probeFromCluster(clusterName, ip); err != nil {
		t.Fatalf("Error when probing service from %s", clusterName)
	}
	return ip
}

func (data *MCTestData) verifyMCServiceACNP(t *testing.T, clientPodName, eastIP string) {
	var err error
	anpBuilder := &e2euttils.AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(multiClusterTestNamespace, "block-west-exported-service").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ANPAppliedToSpec{{PodSelector: map[string]string{"app": "client"}}}).
		AddToServicesRule([]crdv1alpha1.NamespacedName{{
			Name:      fmt.Sprintf("antrea-mc-%s", westClusterTestService),
			Namespace: multiClusterTestNamespace},
		}, "", nil, crdv1alpha1.RuleActionDrop)
	if _, err := data.createOrUpdateANP(eastCluster, anpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ANP %s: %v", anpBuilder.Name, err)
	}
	defer data.deleteANP(eastCluster, multiClusterTestNamespace, anpBuilder.Name)

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, clientPodName, "client", eastIP, fmt.Sprintf("antrea-mc-%s", westClusterTestService), 80, corev1.ProtocolTCP)
	if connectivity == antreae2e.Error {
		t.Errorf("Failure -- could not complete probeFromPodInCluster: %v", err)
	} else if connectivity != antreae2e.Dropped {
		t.Errorf("Failure -- wrong result from probing exported Service after applying toService AntreaNetworkPolicy. Expected: %v, Actual: %v", antreae2e.Dropped, connectivity)
	}
}

func (data *MCTestData) deployServiceExport(clusterName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl apply -f %s", serviceExportYML))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deploying the ServiceExport: %v, stderr: %s", err, stderr)
	}

	return nil
}

func (data *MCTestData) deleteServiceExport(clusterName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl delete -f %s", serviceExportYML))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deleting the ServiceExport: %v, stderr: %s", err, stderr)
	}

	return nil
}

// getNodeNamesFromCluster will pick up a Node randomly as the Gateway
// and also a regular Node from the specified cluster.
func getNodeNamesFromCluster(clusterName string) (string, string, error) {
	rc, output, stderr, err := provider.RunCommandOnNode(clusterName, "kubectl get node -o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{end}'")
	if err != nil || rc != 0 || stderr != "" {
		return "", "", fmt.Errorf("error when getting Node list: %v, stderr: %s", err, stderr)
	}
	nodes := strings.Split(strings.TrimRight(output, " "), " ")
	gwIdx := rand.Intn(len(nodes)) // #nosec G404: for test only
	var regularNode string
	for i, node := range nodes {
		if i != gwIdx {
			regularNode = node
			break
		}
	}
	return nodes[gwIdx], regularNode, nil
}

// setGatewayNode adds an annotation to assign it as Gateway Node.
func (data *MCTestData) setGatewayNode(t *testing.T, clusterName string, nodeName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl annotate node %s multicluster.antrea.io/gateway=true", nodeName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when annotate the Node %s: %s, stderr: %s", nodeName, err, stderr)
	}
	t.Logf("The Node %s is annotated as Gateway in cluster %s", nodeName, clusterName)
	return nil
}

func (data *MCTestData) unsetGatewayNode(clusterName string, nodeName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl annotate node %s multicluster.antrea.io/gateway-", nodeName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when cleaning up annotation of the Node: %v, stderr: %s", err, stderr)
	}
	return nil
}

func initializeGateway(t *testing.T, data *MCTestData) {
	data.clusterGateways = make(map[string]string)
	data.clusterRegularNodes = make(map[string]string)
	// Annotates a Node as Gateway, then member controller will create a Gateway correspondingly.
	for clusterName := range data.clusterTestDataMap {
		if clusterName == leaderCluster {
			// Skip Gateway initialization for the leader cluster
			continue
		}
		gwName, regularNode, err := getNodeNamesFromCluster(clusterName)
		failOnError(err, t)
		err = data.setGatewayNode(t, clusterName, gwName)
		failOnError(err, t)
		data.clusterGateways[clusterName] = gwName
		data.clusterRegularNodes[clusterName] = regularNode
	}
}

func teardownGateway(t *testing.T, data *MCTestData) {
	for clusterName := range data.clusterTestDataMap {
		if clusterName == leaderCluster {
			continue
		}
		if _, ok := data.clusterGateways[clusterName]; ok {
			t.Logf("Removing the Gateway annotation on Node %s in cluster %s", data.clusterGateways[clusterName], clusterName)
			if err := data.unsetGatewayNode(clusterName, data.clusterGateways[clusterName]); err != nil {
				t.Errorf("Error: %v", err)
			}
		}
	}
}

func (data *MCTestData) probeFromCluster(clusterName string, url string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("curl --connect-timeout 5 -s %s", url))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when curl the url %s: %v", url, err)
	}
	return nil
}

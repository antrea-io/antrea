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
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreae2e "antrea.io/antrea/test/e2e"
	e2euttils "antrea.io/antrea/test/e2e/utils"
)

func initializeForServiceExportsTest(t *testing.T, data *MCTestData) {
	data.setupServerPodAndService(t)
	data.setUpServiceExport(t)
	data.setUpClientPodInCluster(t)
}

func tearDownForServiceExportsTest(t *testing.T, data *MCTestData) {
	data.tearDownClientPodInCluster(t)
	data.tearDownServiceExport()
	data.tearDownServerPodAndService(t)
}

func (data *MCTestData) setupServerPodAndService(t *testing.T) {
	createPodAndService := func(clusterName, clusterServiceName string) {
		if err := createPodWrapper(t, data, clusterName, multiClusterTestNamespace, testServerPod, "", nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
			t.Fatalf("Error when creating nginx Pod in cluster %s: %v", clusterName, err)
		}
		if _, err := data.createService(clusterName, clusterServiceName, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
			false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
			t.Fatalf("Error when creating Service %s in cluster %s: %v", clusterServiceName, clusterName, err)
		}
	}
	// Create Pod and Service in west and east clusters
	createPodAndService(westCluster, westClusterTestService)
	createPodAndService(eastCluster, eastClusterTestService)
}

func (data *MCTestData) tearDownServerPodAndService(t *testing.T) {
	deleteServiceWrapper(t, testData, westCluster, multiClusterTestNamespace, westClusterTestService)
	deleteServiceWrapper(t, testData, eastCluster, multiClusterTestNamespace, eastClusterTestService)
	deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, testServerPod)
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, testServerPod)
}

// Deploy ServiceExports in east and west clusters
func (data *MCTestData) setUpServiceExport(t *testing.T) {
	if err := data.deployServiceExport(westCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in west cluster: %v", err)
	}
	if err := data.deployServiceExport(eastCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in east cluster: %v", err)
	}
	time.Sleep(importServiceDelay)
}

func (data *MCTestData) tearDownServiceExport() {
	data.deleteServiceExport(westCluster)
	data.deleteServiceExport(eastCluster)
}

func (data *MCTestData) setUpClientPodInCluster(t *testing.T) {
	data.createClientPodInCluster(t, eastCluster, data.clusterGateways[eastCluster], getClusterGatewayClientPodName(eastCluster))
	data.createClientPodInCluster(t, eastCluster, data.clusterRegularNodes[eastCluster], getClusterRegularClientPodName(eastCluster))
	data.createClientPodInCluster(t, westCluster, data.clusterGateways[westCluster], getClusterGatewayClientPodName(westCluster))
	data.createClientPodInCluster(t, westCluster, data.clusterRegularNodes[westCluster], getClusterRegularClientPodName(westCluster))
}

func (data *MCTestData) tearDownClientPodInCluster(t *testing.T) {
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, getClusterGatewayClientPodName(eastCluster))
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, getClusterRegularClientPodName(eastCluster))
	deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, getClusterGatewayClientPodName(westCluster))
	deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, getClusterRegularClientPodName(westCluster))
}

// Try to curl the counter part Services in east and west clusters.
// If we get status code 200, it means that the resources are exported by the east
// cluster and imported by the west cluster.
func testMCServiceConnectivity(t *testing.T, data *MCTestData) {
	data.testMCServiceConnectivity(t)
}

// Delete existing Pod to scale down the number of Endpoints to zero, then
// the Multi-cluster Service should be deleted due to empty Endpoints.
func testScaleDownMCServiceEndpoints(t *testing.T, data *MCTestData) {
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, testServerPod)
	time.Sleep(2 * time.Second)
	mcServiceName := fmt.Sprintf("antrea-mc-%s", eastClusterTestService)
	_, err := data.getService(westCluster, multiClusterTestNamespace, mcServiceName)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Expected to get not found error when getting the imported Service %s, but got: %v", mcServiceName, err)
	}
}

func testANPToServices(t *testing.T, data *MCTestData) {
	data.testANPToServices(t)
}

func (data *MCTestData) testMCServiceConnectivity(t *testing.T) {
	data.probeMCServiceFromCluster(t, eastCluster, westClusterTestService)
	data.probeMCServiceFromCluster(t, westCluster, eastClusterTestService)
}

func (data *MCTestData) probeMCServiceFromCluster(t *testing.T, clusterName string, serviceName string) {
	svc, err := data.getService(clusterName, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", serviceName))
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", fmt.Sprintf("antrea-mc-%s", serviceName), err)
	}
	ip := svc.Spec.ClusterIP
	gwClientName := getClusterGatewayClientPodName(clusterName)
	regularClientName := getClusterRegularClientPodName(clusterName)

	t.Logf("Probing Service from client Pod %s in cluster %s", gwClientName, clusterName)
	if err := data.probeServiceFromPodInCluster(clusterName, gwClientName, "client", multiClusterTestNamespace, ip); err != nil {
		t.Fatalf("Error when probing Service from client Pod %s in cluster %s, err: %v", gwClientName, clusterName, err)
	}
	t.Logf("Probing Service from client Pod %s in cluster %s", regularClientName, clusterName)
	if err := data.probeServiceFromPodInCluster(clusterName, regularClientName, "client", multiClusterTestNamespace, ip); err != nil {
		t.Fatalf("Error when probing Service from client Pod %s in cluster %s, err: %v", regularClientName, clusterName, err)
	}
}

func (data *MCTestData) testANPToServices(t *testing.T) {
	svc, err := data.getService(eastCluster, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", westClusterTestService))
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", fmt.Sprintf("antrea-mc-%s", westClusterTestService), err)
	}
	eastIP := svc.Spec.ClusterIP
	eastGwClientName := getClusterGatewayClientPodName(eastCluster)
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Verify that ACNP ToServices works fine with the new Multi-cluster Service.
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

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", eastIP, fmt.Sprintf("antrea-mc-%s", westClusterTestService), 80, corev1.ProtocolTCP)
	if connectivity == antreae2e.Error {
		t.Errorf("Failure -- could not complete probeFromPodInCluster: %v", err)
	} else if connectivity != antreae2e.Dropped {
		t.Errorf("Failure -- wrong result from probing exported Service from gateway clientPod after applying toServices AntreaNetworkPolicy. Expected: %v, Actual: %v", antreae2e.Dropped, connectivity)
	}

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", eastIP, fmt.Sprintf("antrea-mc-%s", westClusterTestService), 80, corev1.ProtocolTCP)
	if connectivity == antreae2e.Error {
		t.Errorf("Failure -- could not complete probeFromPodInCluster: %v", err)
	} else if connectivity != antreae2e.Dropped {
		t.Errorf("Failure -- wrong result from probing exported Service from regular clientPod after applying toServices AntreaNetworkPolicy. Expected: %v, Actual: %v", antreae2e.Dropped, connectivity)
	}
}

func (data *MCTestData) createClientPodInCluster(t *testing.T, cluster string, nodeName string, podName string) {
	if err := data.createPod(cluster, podName, nodeName, multiClusterTestNamespace, "client", agnhostImage,
		[]string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating client Pod in cluster '%s': %v", cluster, err)
	}
	t.Logf("Checking Pod status %s in Namespace %s of cluster %s", podName, multiClusterTestNamespace, cluster)
	_, err := data.podWaitFor(defaultTimeout, cluster, podName, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		deletePodWrapper(t, data, cluster, multiClusterTestNamespace, podName)
		t.Fatalf("Error when waiting for Pod '%s' in cluster '%s': %v", podName, cluster, err)
	}
}

func (data *MCTestData) deployServiceExport(clusterName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(clusterName), fmt.Sprintf("kubectl apply -f %s", serviceExportYML))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deploying the ServiceExport: %v, stderr: %s", err, stderr)
	}

	return nil
}

func (data *MCTestData) deleteServiceExport(clusterName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(clusterName), fmt.Sprintf("kubectl delete -f %s", serviceExportYML))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deleting the ServiceExport: %v, stderr: %s", err, stderr)
	}

	return nil
}

// getNodeNamesFromCluster will pick up a Node randomly as the Gateway
// and also a regular Node from the specified cluster.
func (data *MCTestData) getNodeNamesFromCluster(clusterName string) (string, string, error) {
	rc, output, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(clusterName), "/bin/sh -c kubectl get nodes -o custom-columns=:.metadata.name --no-headers | tr '\n' ' '")
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
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(clusterName), fmt.Sprintf("kubectl annotate node %s multicluster.antrea.io/gateway=true", nodeName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when annotate the Node %s: %s, stderr: %s", nodeName, err, stderr)
	}
	t.Logf("The Node %s is annotated as Gateway in cluster %s", nodeName, clusterName)
	return nil
}

func (data *MCTestData) unsetGatewayNode(clusterName string, nodeName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(clusterName), fmt.Sprintf("kubectl annotate node %s multicluster.antrea.io/gateway-", nodeName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when cleaning up annotation of the Node: %v, stderr: %s", err, stderr)
	}
	return nil
}

func (data *MCTestData) getControlPlaneNodeName(clusterName string) string {
	controlplaneNodeName := clusterName
	if testOptions.providerName == "kind" {
		controlplaneNodeName = data.controlPlaneNames[clusterName]
	}
	return controlplaneNodeName
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
		gwName, regularNode, err := data.getNodeNamesFromCluster(clusterName)
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

func getClusterGatewayClientPodName(cluster string) string {
	return cluster + "-" + gatewayNodeClientSuffix
}

func getClusterRegularClientPodName(cluster string) string {
	return cluster + "-" + regularNodeClientSuffix
}

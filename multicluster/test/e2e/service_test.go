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
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
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
	// Test Service connectivity for both local and remote Endpoints.
	data.testMCServiceConnectivity(t)
}

// Updating existing Pod's label to scale down the number of Endpoints to zero, then
// the Multi-cluster Service should be deleted due to empty Endpoints.
func testScaleDownMCServiceEndpoints(t *testing.T, data *MCTestData) {
	newPatch := func(app string) []byte {
		patch, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{
				"labels": map[string]interface{}{
					"app": app,
				},
			},
		})
		return patch
	}

	if err := data.patchPod(eastCluster, multiClusterTestNamespace, testServerPod, newPatch("dummy")); err != nil {
		t.Fatalf("Failed to patch Pod %s/%s in Cluster %s", multiClusterTestNamespace, testServerPod, eastCluster)
	}
	defer func() {
		// Revert changes, because we shouldn't make changes to the test env that is also
		// used by other test cases.
		if err := data.patchPod(eastCluster, multiClusterTestNamespace, testServerPod, newPatch("nginx")); err != nil {
			t.Fatalf("Failed to patch Pod %s/%s in Cluster %s", multiClusterTestNamespace, testServerPod, eastCluster)
		}
	}()
	var getErr error
	require.Eventually(t, func() bool {
		_, getErr = data.getService(westCluster, multiClusterTestNamespace, mcEastClusterTestService)
		return apierrors.IsNotFound(getErr)
	}, 2*time.Second, 100*time.Millisecond, "Expected to get not found error when getting the imported Service %s, but got %v", mcEastClusterTestService, getErr)
}

func testANNPToServices(t *testing.T, data *MCTestData) {
	data.testANNPToServices(t)
}

func testStretchedNetworkPolicy(t *testing.T, data *MCTestData) {
	data.testStretchedNetworkPolicy(t)
}

func testStretchedNetworkPolicyReject(t *testing.T, data *MCTestData) {
	data.testStretchedNetworkPolicyReject(t)
}

func testStretchedNetworkPolicyUpdatePod(t *testing.T, data *MCTestData) {
	data.testStretchedNetworkPolicyUpdatePod(t)
}
func testStretchedNetworkPolicyUpdateNS(t *testing.T, data *MCTestData) {
	data.testStretchedNetworkPolicyUpdateNS(t)
}
func testStretchedNetworkPolicyUpdatePolicy(t *testing.T, data *MCTestData) {
	data.testStretchedNetworkPolicyUpdatePolicy(t)
}

func (data *MCTestData) testMCServiceConnectivity(t *testing.T) {
	// Connectivity to remote Endpoint which is the exported Service's ClusterIP from another member cluster.
	data.probeMCServiceFromCluster(t, eastCluster, westClusterTestService)
	data.probeMCServiceFromCluster(t, westCluster, eastClusterTestService)
	// Connectivity to local Endpoint which is the exported Service's ClusterIP from its own cluster.
	data.probeMCServiceFromCluster(t, eastCluster, eastClusterTestService)
	data.probeMCServiceFromCluster(t, westCluster, westClusterTestService)
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

func (data *MCTestData) testANNPToServices(t *testing.T) {
	svc, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	eastIP := svc.Spec.ClusterIP
	eastGwClientName := getClusterGatewayClientPodName(eastCluster)
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Verify that ANNP ToServices works fine with the new Multi-cluster Service.
	annpBuilder1 := &e2euttils.AntreaNetworkPolicySpecBuilder{}
	annpBuilder1 = annpBuilder1.SetName(multiClusterTestNamespace, "block-west-exported-service").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ANNPAppliedToSpec{{PodSelector: map[string]string{"app": "client"}}}).
		AddToServicesRule([]crdv1beta1.PeerService{{
			Name:      mcWestClusterTestService,
			Namespace: multiClusterTestNamespace},
		}, "", nil, crdv1beta1.RuleActionDrop)
	if _, err := data.createOrUpdateANNP(eastCluster, annpBuilder1.Get()); err != nil {
		t.Fatalf("Error creating ANNP %s: %v", annpBuilder1.Name, err)
	}
	eastClusterData := data.clusterTestDataMap[eastCluster]
	if err := eastClusterData.WaitForANNPCreationAndRealization(t, annpBuilder1.Namespace, annpBuilder1.Name, policyRealizedTimeout); err != nil {
		t.Errorf("Failed to wait for ANNP %s/%s to be realized in cluster %s", annpBuilder1.Namespace, annpBuilder1.Name, eastCluster)
		failOnError(err, t)
	}

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", eastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, "Failure -- wrong result from probing exported Service from gateway clientPod after applying toServices AntreaNetworkPolicy")

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", eastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, "Failure -- wrong result from probing exported Service from regular clientPod after applying toServices AntreaNetworkPolicy")

	data.deleteANNP(eastCluster, multiClusterTestNamespace, annpBuilder1.Name)

	// Verify that ANNP ToServices with scope works fine.
	annpBuilder2 := &e2euttils.AntreaNetworkPolicySpecBuilder{}
	annpBuilder2 = annpBuilder2.SetName(multiClusterTestNamespace, "block-west-service-clusterset-scope").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ANNPAppliedToSpec{{PodSelector: map[string]string{"app": "client"}}}).
		AddToServicesRule([]crdv1beta1.PeerService{{
			Name:      westClusterTestService,
			Namespace: multiClusterTestNamespace,
			Scope:     "ClusterSet",
		}}, "", nil, crdv1beta1.RuleActionDrop)
	if _, err := data.createOrUpdateANNP(eastCluster, annpBuilder2.Get()); err != nil {
		t.Fatalf("Error creating ANNP %s: %v", annpBuilder2.Name, err)
	}
	if err := eastClusterData.WaitForANNPCreationAndRealization(t, annpBuilder2.Namespace, annpBuilder2.Name, policyRealizedTimeout); err != nil {
		t.Errorf("Failed to wait for ANNP %s/%s to be realized in cluster %s", annpBuilder2.Namespace, annpBuilder2.Name, eastCluster)
		failOnError(err, t)
	}
	defer data.deleteANNP(eastCluster, multiClusterTestNamespace, annpBuilder2.Name)

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", eastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, "Failure -- wrong result from probing exported Service from gateway clientPod after applying toServices AntreaNetworkPolicy")

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", eastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, "Failure -- wrong result from probing exported Service from regular clientPod after applying toServices AntreaNetworkPolicy")

}

func (data *MCTestData) testStretchedNetworkPolicy(t *testing.T) {
	westExpSvc, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	westExpSvcIP := westExpSvc.Spec.ClusterIP
	eastGwClientName := getClusterGatewayClientPodName(eastCluster)
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Verify that Stretched NetworkPolicy works fine with podSelect or podSelect+nsSelector.
	acnpBuilder1 := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder1 = acnpBuilder1.SetName("drop-client-pod-sel").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(map[string]string{"antrea-e2e": eastGwClientName}, nil, "", nil, crdv1beta1.RuleActionDrop).
		AddStretchedIngressRule(map[string]string{"antrea-e2e": eastRegularClientName}, map[string]string{"kubernetes.io/metadata.name": multiClusterTestNamespace}, "", nil, crdv1beta1.RuleActionDrop)
	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder1.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder1.Name, err)
	}
	westClusterData := data.clusterTestDataMap[westCluster]
	if err := westClusterData.WaitForACNPCreationAndRealization(t, acnpBuilder1.Name, policyRealizedTimeout); err != nil {
		t.Errorf("Failed to wait for ACNP %s to be realized in cluster %s", acnpBuilder1.Name, westCluster)
		failOnError(err, t)
	}

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastGwClientName))

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))
	data.deleteACNP(westCluster, acnpBuilder1.Name)

	// Verify that Stretched NetworkPolicy works fine with nsSelect.
	acnpBuilder2 := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder2 = acnpBuilder2.SetName("drop-client-ns-sel").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(nil, map[string]string{"kubernetes.io/metadata.name": multiClusterTestNamespace}, "", nil, crdv1beta1.RuleActionDrop)

	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder2.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder2.Name, err)
	}
	defer data.deleteACNP(westCluster, acnpBuilder2.Name)
	if err := westClusterData.WaitForACNPCreationAndRealization(t, acnpBuilder2.Name, policyRealizedTimeout); err != nil {
		t.Errorf("Failed to wait for ACNP %s to be realized in cluster %s", acnpBuilder2.Name, westCluster)
		failOnError(err, t)
	}

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastGwClientName))

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))
}

func (data *MCTestData) testStretchedNetworkPolicyReject(t *testing.T) {
	westExpSvcInEast, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	westExpSvcInEastIP := westExpSvcInEast.Spec.ClusterIP

	eastGwClientName := getClusterGatewayClientPodName(eastCluster)
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	acnpBuilder := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("drop-client-pod-sel").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(map[string]string{"app": "client"}, nil, "", nil, crdv1beta1.RuleActionReject)
	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder.Name, err)
	}
	westClusterData := data.clusterTestDataMap[westCluster]
	if err := westClusterData.WaitForACNPCreationAndRealization(t, acnpBuilder.Name, policyRealizedTimeout); err != nil {
		t.Errorf("Failed to wait for ACNP %s to be realized in cluster %s", acnpBuilder.Name, westCluster)
		failOnError(err, t)
	}
	defer data.deleteACNP(westCluster, acnpBuilder.Name)

	testConnectivity := func() {
		connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", westExpSvcInEastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
		assert.Equal(t, antreae2e.Rejected, connectivity, getStretchedNetworkPolicyErrorMessage(eastGwClientName))

		connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcInEastIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
		assert.Equal(t, antreae2e.Rejected, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))
	}

	// Test when the server Pod is created and running on the Gateway Node.
	deletePodAndWaitWrapper(t, data, westCluster, multiClusterTestNamespace, testServerPod)
	if err := createPodWrapper(t, data, westCluster, multiClusterTestNamespace, testServerPod+"-gw", data.clusterGateways[westCluster], nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in cluster %s: %v", westCluster, err)
	}
	testConnectivity()

	// Test when the server Pod is created and running on the regular Node.
	deletePodAndWaitWrapper(t, data, westCluster, multiClusterTestNamespace, testServerPod+"-gw")
	if err := createPodWrapper(t, data, westCluster, multiClusterTestNamespace, testServerPod+"-regular", data.clusterRegularNodes[westCluster], nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in cluster %s: %v", westCluster, err)
	}
	testConnectivity()
}

func (data *MCTestData) testStretchedNetworkPolicyUpdatePod(t *testing.T) {
	westExpSvc, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	westExpSvcIP := westExpSvc.Spec.ClusterIP
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Create a Stretched NetworkPolicy that doesn't select any Pods.
	acnpBuilder := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("drop-client-pod-update").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(map[string]string{"antrea-e2e": eastRegularClientName, "foo": "bar"}, nil, "", nil, crdv1beta1.RuleActionDrop)
	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder.Name, err)
	}
	defer data.deleteACNP(westCluster, acnpBuilder.Name)

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Connected, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))

	// Update Pod Label to match the Stretched NetworkPolicy selector.
	if err = data.updatePod(eastCluster, multiClusterTestNamespace, eastRegularClientName, func(pod *corev1.Pod) { pod.Labels["foo"] = "bar" }); err != nil {
		t.Errorf("Failure -- fail to update eastRegularClientPod: %v", err)
	}
	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))

	// Revert Pod Label update to test this Pod won't be selected again.
	if err = data.updatePod(eastCluster, multiClusterTestNamespace, eastRegularClientName, func(pod *corev1.Pod) { delete(pod.Labels, "foo") }); err != nil {
		t.Errorf("Failure -- fail to update eastRegularClientPod: %v", err)
	}
	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Connected, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))
}

func (data *MCTestData) testStretchedNetworkPolicyUpdateNS(t *testing.T) {
	westExpSvc, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	westExpSvcIP := westExpSvc.Spec.ClusterIP
	eastGwClientName := getClusterGatewayClientPodName(eastCluster)
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Verify that Stretched NetworkPolicy works fine with nsSelector.
	acnpBuilder := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("drop-client-ns-update").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(nil, map[string]string{"kubernetes.io/metadata.name": multiClusterTestNamespace, "foo": "bar"}, "", nil, crdv1beta1.RuleActionDrop)

	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder.Name, err)
	}
	defer data.deleteACNP(westCluster, acnpBuilder.Name)

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Connected, connectivity, getStretchedNetworkPolicyErrorMessage(eastGwClientName))

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Connected, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))

	// Update NS label to match the Stretched NetworkPolicy selector.
	if err = data.updateNamespace(eastCluster, multiClusterTestNamespace, func(ns *corev1.Namespace) { ns.Labels["foo"] = "bar" }); err != nil {
		t.Errorf("Failure -- fail to update multiClusterTestNamespace: %v", err)
	}

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastGwClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastGwClientName))

	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))

	// Revert Namespace Label update.
	if err = data.updateNamespace(eastCluster, multiClusterTestNamespace, func(ns *corev1.Namespace) { delete(ns.Labels, "foo") }); err != nil {
		t.Errorf("Failure -- fail to update multiClusterTestNamespace: %v", err)
	}
}

func (data *MCTestData) testStretchedNetworkPolicyUpdatePolicy(t *testing.T) {
	westExpSvc, err := data.getService(eastCluster, multiClusterTestNamespace, mcWestClusterTestService)
	if err != nil {
		t.Fatalf("Error when getting the imported Service %s: %v", mcWestClusterTestService, err)
	}
	westExpSvcIP := westExpSvc.Spec.ClusterIP
	eastRegularClientName := getClusterRegularClientPodName(eastCluster)

	// Create a Stretched NetworkPolicy that doesn't select any Pods.
	acnpBuilder := &e2euttils.ClusterNetworkPolicySpecBuilder{}
	acnpBuilder = acnpBuilder.SetName("drop-client-pod-update").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ACNPAppliedToSpec{{PodSelector: map[string]string{"app": "nginx"}}}).
		AddStretchedIngressRule(map[string]string{"foo": "bar"}, nil, "", nil, crdv1beta1.RuleActionDrop)

	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ACNP %s: %v", acnpBuilder.Name, err)
	}
	defer data.deleteACNP(westCluster, acnpBuilder.Name)

	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Connected, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))

	// Update the policy to select the eastRegularClient.
	acnpBuilder.AddStretchedIngressRule(map[string]string{"antrea-e2e": eastRegularClientName}, nil, "", nil, crdv1beta1.RuleActionDrop)
	if _, err := data.createOrUpdateACNP(westCluster, acnpBuilder.Get()); err != nil {
		t.Fatalf("Error updateing ACNP %s: %v", acnpBuilder.Name, err)
	}
	connectivity = data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, eastRegularClientName, "client", westExpSvcIP, mcWestClusterTestService, 80, corev1.ProtocolTCP)
	assert.Equal(t, antreae2e.Dropped, connectivity, getStretchedNetworkPolicyErrorMessage(eastRegularClientName))
}

func getStretchedNetworkPolicyErrorMessage(client string) string {
	return fmt.Sprintf("Failure -- wrong result from probing exported Service from %s clientPod after applying Stretched NetworkPolicy", client)
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

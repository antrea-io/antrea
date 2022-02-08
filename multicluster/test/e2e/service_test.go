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
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreae2e "antrea.io/antrea/test/e2e"
	e2euttils "antrea.io/antrea/test/e2e/utils"
)

// Try to curl the counter part services in east and west clusters.
// If we get status code 200, it means that the resources is exported by the east cluster
// and imported by the west cluster.
func testProbeMCService(t *testing.T, data *MCTestData) {
	data.testProbeMCService(t)
}

func testANP(t *testing.T, data *MCTestData) {
	data.testANP(t)
}

func (data *MCTestData) setupTestResources(t *testing.T) string {

	podName := randName(nginxPodName)
	if err := createPodWrapper(t, data, westCluster, multiClusterTestNamespace, podName, nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in west cluster: %v", err)
	}

	if err := createPodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName, nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in east cluster: %v", err)
	}

	if _, err := data.createService(westCluster, westClusterTestService, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
		false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
		t.Fatalf("Error when creating Servie %s in west cluster: %v", westClusterTestService, err)
	}

	if _, err := data.createService(eastCluster, eastClusterTestService, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
		false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
		t.Fatalf("Error when creating Servie %s in east cluster: %v", eastClusterTestService, err)
	}
	return podName
}

func (data *MCTestData) tearDownTestResources(t *testing.T, podName string) {
	deleteServiceWrapper(t, testData, westCluster, multiClusterTestNamespace, westClusterTestService)
	deleteServiceWrapper(t, testData, eastCluster, multiClusterTestNamespace, eastClusterTestService)
	deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, podName)
	deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName)
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

func (data *MCTestData) testProbeMCService(t *testing.T) {
	data.probeMCServiceFromCluster(t, eastCluster, westClusterTestService)
	data.probeMCServiceFromCluster(t, westCluster, eastClusterTestService)
}

func (data *MCTestData) testANP(t *testing.T) {

	clientPodName := "test-service-client"
	if err := data.createPod(eastCluster, clientPodName, multiClusterTestNamespace, "client", agnhostImage,
		[]string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating client Pod in east cluster: %v", err)
	}
	defer deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, clientPodName)
	_, err := data.podWaitFor(defaultTimeout, eastCluster, clientPodName, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		t.Fatalf("Error when waiting for Pod '%s' in east cluster: %v", clientPodName, err)
	}

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

	westIP := data.probeMCServiceFromCluster(t, westCluster, eastClusterTestService)
	connectivity := data.probeFromPodInCluster(eastCluster, multiClusterTestNamespace, clientPodName, "client", westIP, "westClusterServiceIP", 80, corev1.ProtocolTCP)
	if connectivity == antreae2e.Error {
		t.Errorf("Failure -- could not complete probeFromPodInCluster: %v", err)
	} else if connectivity != antreae2e.Dropped {
		t.Errorf("Failure -- wrong result from probing exported Service after applying toService AntreaNetworkPolicy. Expected: %v, Actual: %v", antreae2e.Dropped, connectivity)
	}
}

func (data *MCTestData) deployServiceExport(clusterName string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl apply -f %s", serviceExportYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying the ServiceExport: %v", err)
	}

	return nil
}

func (data *MCTestData) deleteServiceExport(clusterName string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl delete -f %s", serviceExportYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deleting the ServiceExport: %v", err)
	}

	return nil
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

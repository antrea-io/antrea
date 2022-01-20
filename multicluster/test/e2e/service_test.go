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

func TestConnectivity(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testServiceExport", func(t *testing.T) {
		testServiceExport(t, data)
	})
}

func testServiceExport(t *testing.T, data *TestData) {
	data.testServiceExport(t)
}

// testServiceExport is used to test the service between clusters by following steps
// we create a nginx in on cluster(east), and try to curl it in another cluster(west).
// If we got status code 200, it means that the resources is exported by the east cluster
// and imported by the west cluster.
// TODO(yang): reorg test function contents
func (data *TestData) testServiceExport(t *testing.T) {
	podName := randName("test-nginx-")
	clientPodName := "test-service-client"

	if err := createPodWrapper(t, data, westCluster, multiClusterTestNamespace, podName, nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in west cluster: %v", err)
	}
	defer deletePodWrapper(t, data, westCluster, multiClusterTestNamespace, podName)

	if err := createPodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName, nginxImage, "nginx", nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating nginx Pod in east cluster: %v", err)
	}
	defer deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, podName)

	if _, err := data.createService(westCluster, westClusterTestService, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
		false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
		t.Fatalf("Error when creating Servie %s in west cluster: %v", westClusterTestService, err)
	}
	defer deleteServiceWrapper(t, testData, westCluster, multiClusterTestNamespace, westClusterTestService)

	if _, err := data.createService(eastCluster, eastClusterTestService, multiClusterTestNamespace, 80, 80, corev1.ProtocolTCP, map[string]string{"app": "nginx"}, false,
		false, corev1.ServiceTypeClusterIP, nil, nil); err != nil {
		t.Fatalf("Error when creating Servie %s in east cluster: %v", eastClusterTestService, err)
	}
	defer deleteServiceWrapper(t, testData, eastCluster, multiClusterTestNamespace, eastClusterTestService)

	if err := data.deployServiceExport(westCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in west cluster: %v", err)
	}
	defer data.deleteServiceExport(westCluster)
	if err := data.deployServiceExport(eastCluster); err != nil {
		t.Fatalf("Error when deploy ServiceExport in east cluster: %v", err)
	}
	defer data.deleteServiceExport(eastCluster)
	time.Sleep(importServiceDelay)

	svc, err := data.getService(eastCluster, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", westClusterTestService))
	if err != nil {
		t.Fatalf("Error when getting the imported service %s: %v", fmt.Sprintf("antrea-mc-%s", westClusterTestService), err)
	}

	eastIP := svc.Spec.ClusterIP
	if err := data.probeFromCluster(eastCluster, eastIP); err != nil {
		t.Fatalf("Error when probe service from %s", eastCluster)
	}
	svc, err = data.getService(westCluster, multiClusterTestNamespace, fmt.Sprintf("antrea-mc-%s", eastClusterTestService))
	if err != nil {
		t.Fatalf("Error when getting the imported service %s: %v", fmt.Sprintf("antrea-mc-%s", eastClusterTestService), err)
	}
	westIP := svc.Spec.ClusterIP
	if err := data.probeFromCluster(westCluster, westIP); err != nil {
		t.Fatalf("Error when probe service from %s", westCluster)
	}

	if err := data.createPod(eastCluster, clientPodName, multiClusterTestNamespace, "client", agnhostImage,
		[]string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating client Pod in east cluster: %v", err)
	}
	defer deletePodWrapper(t, data, eastCluster, multiClusterTestNamespace, clientPodName)
	_, err = data.podWaitFor(defaultTimeout, eastCluster, clientPodName, multiClusterTestNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	if err != nil {
		t.Fatalf("Error when waiting for Pod '%s' in east cluster: %v", clientPodName, err)
	}

	anpBuilder := &e2euttils.AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(multiClusterTestNamespace, "block-west-exported-service").
		SetPriority(1.0).
		SetAppliedToGroup([]e2euttils.ANPAppliedToSpec{{PodSelector: map[string]string{"app": "client"}}}).
		AddToServicesRule([]crdv1alpha1.ServiceReference{{
			Name:      fmt.Sprintf("antrea-mc-%s", westClusterTestService),
			Namespace: multiClusterTestNamespace},
		}, "", nil, crdv1alpha1.RuleActionDrop)
	if _, err := createOrUpdateANP(data.getCRDClientOfCluster(eastCluster), anpBuilder.Get()); err != nil {
		t.Fatalf("Error creating ANP %s: %v", anpBuilder.Name, err)
	}
	defer deleteANP(data.getCRDClientOfCluster(eastCluster), multiClusterTestNamespace, anpBuilder.Name)

	connectivity := data.probe(eastCluster, multiClusterTestNamespace, clientPodName, "client", westIP, "westClusterServiceIP", 80, corev1.ProtocolTCP)
	if connectivity == antreae2e.Error {
		t.Errorf("Failure -- could not complete probe: %v", err)
	} else if connectivity != antreae2e.Dropped {
		t.Errorf("Failure -- wrong result from probing exported Service after applying toService AntreaNetworkPolicy. Expected: %v, Actual: %v", antreae2e.Dropped, connectivity)
	}
}

func (data *TestData) deployServiceExport(clusterName string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl apply -f %s", serviceExportYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying the ServiceExport: %v", err)
	}

	return nil
}

func (data *TestData) deleteServiceExport(clusterName string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("kubectl delete -f %s", serviceExportYML))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deleting the ServiceExport: %v", err)
	}

	return nil
}

func (data *TestData) probeFromCluster(clusterName string, url string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(clusterName, fmt.Sprintf("curl --connect-timeout 5 -s %s", url))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when curl the url %s: %v", url, err)
	}

	return nil
}

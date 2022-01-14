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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
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
func (data *TestData) testServiceExport(t *testing.T) {
	podName := randName("test-nginx-")

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

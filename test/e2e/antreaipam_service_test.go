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
	"testing"

	annotation "antrea.io/antrea/pkg/ipam"
)

func TestAntreaIPAMService(t *testing.T) {
	skipIfNotAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	// Create AntreaIPAM IPPool and test Namespace
	var ipPools []string
	for _, namespace := range []string{testAntreaIPAMNamespace, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12} {
		ipPool, err := createIPPool(t, data, namespace)
		if err != nil {
			t.Fatalf("Creating IPPool failed, err=%+v", err)
		}
		defer deleteIPPoolWrapper(t, data, ipPool.Name)
		ipPools = append(ipPools, ipPool.Name)
		annotations := map[string]string{}
		annotations[annotation.AntreaIPAMAnnotationKey] = ipPool.Name
		err = data.createNamespaceWithAnnotations(namespace, annotations)
		if err != nil {
			t.Fatalf("Creating AntreaIPAM Namespace failed, err=%+v", err)
		}
		defer deleteAntreaIPAMNamespace(t, data, namespace)
	}

	t.Run("testAntreaIPAMPodToAntreaIPAMClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, data.testNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace, data.testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN11ClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN12ClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToAntreaIPAMVLAN11ClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11ClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, data.testNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToClusterIPv4", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		data.testClusterIP(t, false, testAntreaIPAMNamespace11, data.testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})

	t.Run("testAntreaIPAMPodToAntreaIPAMNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, data.testNamespace, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace, data.testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN11NodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMVLAN12NodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace12)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMPodToAntreaIPAMVLAN11NodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToAntreaIPAMNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace11, testAntreaIPAMNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11NodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, data.testNamespace, testAntreaIPAMNamespace11)
		checkIPPoolsEmpty(t, data, ipPools)
	})
	t.Run("testAntreaIPAMVLAN11PodToNodePort", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		data.testNodePort(t, false, testAntreaIPAMNamespace11, data.testNamespace)
		checkIPPoolsEmpty(t, data, ipPools)
	})
}

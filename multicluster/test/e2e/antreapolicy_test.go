// Copyright 2022 Antrea Authors
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

	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e/utils"
)

const (
	// Provide enough time for policies to be imported and enforced by the CNI plugin.
	policyRealizedTimeout              = 6 * time.Second
	acnpIsolationResourceExport        = "test-acnp-copy-span-ns-isolation.yml"
	acnpIsolationName                  = "antrea-mc-strict-namespace-isolation"
	acnpCrossClusterIsolationResExport = "test-acnp-cross-cluster-ns-isolation.yml"
	acnpCrossClusterIsolationName      = "antrea-mc-strict-namespace-isolation-cross-cluster"
)

var (
	allPodsPerCluster    []antreae2e.Pod
	perNamespacePods     []string
	perClusterNamespaces map[string]antreae2e.TestNamespaceMeta
	podsByNamespace      map[string][]antreae2e.Pod
	clusterK8sUtilsMap   map[string]*antreae2e.KubernetesUtils
)

func failOnError(err error, t *testing.T) {
	if err != nil {
		t.Errorf("%+v", err)
		for _, k8sUtils := range clusterK8sUtilsMap {
			k8sUtils.Cleanup(perClusterNamespaces)
		}
		t.Fatalf("test failed: %v", err)
	}
}

// initializeForPolicyTest creates three Pods in three test Namespaces for each test cluster.
func initializeForPolicyTest(t *testing.T, data *MCTestData) {
	perNamespacePods = []string{"a", "b", "c"}
	perClusterNamespaces = make(map[string]antreae2e.TestNamespaceMeta)
	for _, ns := range []string{"x", "y", "z"} {
		perClusterNamespaces[ns] = antreae2e.TestNamespaceMeta{Name: ns}
	}

	allPodsPerCluster = []antreae2e.Pod{}
	podsByNamespace = make(map[string][]antreae2e.Pod)
	clusterK8sUtilsMap = make(map[string]*antreae2e.KubernetesUtils)

	for _, podName := range perNamespacePods {
		for _, ns := range perClusterNamespaces {
			allPodsPerCluster = append(allPodsPerCluster, antreae2e.NewPod(ns.Name, podName))
			podsByNamespace[ns.Name] = append(podsByNamespace[ns.Name], antreae2e.NewPod(ns.Name, podName))
		}
	}
	for clusterName := range data.clusterTestDataMap {
		d := data.clusterTestDataMap[clusterName]
		k8sUtils, err := antreae2e.NewKubernetesUtils(&d)
		failOnError(err, t)
		if clusterName != leaderCluster {
			_, err = k8sUtils.Bootstrap(perClusterNamespaces, perNamespacePods, true, nil, nil)
			failOnError(err, t)
		}
		clusterK8sUtilsMap[clusterName] = k8sUtils
	}
}

// tearDownForPolicyTest deletes the test Namespaces specific for policy tests.
func tearDownForPolicyTest() {
	for _, k8sUtils := range clusterK8sUtilsMap {
		k8sUtils.Cleanup(perClusterNamespaces)
	}
}

// testAntreaPolicyCopySpanNSIsolation tests that after applying a ResourceExport of an ACNP
// for Namespace isolation, strict Namespace isolation is enforced in each of the member clusters.
func testAntreaPolicyCopySpanNSIsolation(t *testing.T, data *MCTestData) {
	setup := func() {
		err := data.deployACNPResourceExport(t, acnpIsolationResourceExport)
		failOnError(err, t)
	}
	teardown := func() {
		err := data.deleteACNPResourceExport(acnpIsolationResourceExport)
		failOnError(err, t)
	}
	reachability := antreae2e.NewReachability(allPodsPerCluster, antreae2e.Dropped)
	reachability.ExpectAllSelfNamespace(antreae2e.Connected)
	testStep := &antreae2e.TestStep{
		Name:         "Port 80",
		Reachability: reachability,
		Ports:        []int32{80},
		Protocol:     utils.ProtocolTCP,
	}
	testCaseList := []*antreae2e.TestCase{
		{
			Name:  "ACNP strict Namespace isolation for all clusters",
			Steps: []*antreae2e.TestStep{testStep},
		},
	}
	executeTestsOnAllMemberClusters(t, testCaseList, acnpIsolationName, setup, teardown, false)
}

func testAntreaPolicyCrossClusterNSIsolation(t *testing.T, data *MCTestData) {
	setup := func() {
		err := data.deployACNPResourceExport(t, acnpCrossClusterIsolationResExport)
		failOnError(err, t)
	}
	teardown := func() {
		err := data.deleteACNPResourceExport(acnpCrossClusterIsolationResExport)
		failOnError(err, t)
	}
	reachability := antreae2e.NewReachability(allPodsPerCluster, antreae2e.Dropped)
	reachability.ExpectAllSelfNamespace(antreae2e.Connected)
	testStep := &antreae2e.TestStep{
		Name:         "Port 80",
		Reachability: reachability,
		Ports:        []int32{80},
		Protocol:     utils.ProtocolTCP,
	}
	testCaseList := []*antreae2e.TestCase{
		{
			Name:  "ACNP strict cross-cluster Namespace isolation",
			Steps: []*antreae2e.TestStep{testStep},
		},
	}
	executeTestsOnAllMemberClusters(t, testCaseList, acnpCrossClusterIsolationName, setup, teardown, true)
}

func executeTestsOnAllMemberClusters(t *testing.T, testList []*antreae2e.TestCase, acnpName string, setup, teardown func(), testCrossCluster bool) {
	setup()
	for _, testCase := range testList {
		t.Logf("Running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			t.Logf("Running step %s of test case %s", step.Name, testCase.Name)
			reachability := step.Reachability
			for clusterName, k8sUtils := range clusterK8sUtilsMap {
				if clusterName == leaderCluster {
					// skip verification for the leader cluster
					continue
				}
				if err := k8sUtils.WaitForACNPCreationAndRealization(t, acnpName, policyRealizedTimeout); err != nil {
					t.Errorf("Failed to get ACNP to be replicated in cluster %s", clusterName)
					failOnError(err, t)
				}
				start := time.Now()
				k8sUtils.Validate(allPodsPerCluster, reachability, step.Ports, step.Protocol)
				step.Duration = time.Since(start)
				_, wrong, _ := step.Reachability.Summary()
				if wrong != 0 {
					t.Errorf("Failure in cluster %s -- %d wrong results", clusterName, wrong)
					reachability.PrintSummary(true, true, true)
				}
				if testCrossCluster {
					for remoteClusterName, remoteClusterK8s := range clusterK8sUtilsMap {
						if remoteClusterName == leaderCluster || remoteClusterName == clusterName {
							continue
						}
						newReachability := reachability.NewReachabilityWithSameExpectations()
						k8sUtils.ValidateRemoteCluster(remoteClusterK8s, allPodsPerCluster, newReachability, step.Ports[0], step.Protocol)
						_, wrong, _ = newReachability.Summary()
						if wrong != 0 {
							t.Errorf("Failure from cluster %s to cluster %s -- %d wrong results", clusterName, remoteClusterName, wrong)
							newReachability.PrintSummary(true, true, true)
						}
					}
				}
			}
		}
	}
	teardown()
}

func (data *MCTestData) deployACNPResourceExport(t *testing.T, reFileName string) error {
	t.Logf("Creating ResourceExport %s in the leader cluster", reFileName)
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(leaderCluster), fmt.Sprintf("kubectl apply -f %s", reFileName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deploying the ACNP ResourceExport in leader cluster: %v, stderr: %s", err, stderr)
	}
	return nil
}

func (data *MCTestData) deleteACNPResourceExport(reFileName string) error {
	rc, _, stderr, err := provider.RunCommandOnNode(data.getControlPlaneNodeName(leaderCluster), fmt.Sprintf("kubectl delete -f %s", reFileName))
	if err != nil || rc != 0 || stderr != "" {
		return fmt.Errorf("error when deleting the ACNP ResourceExport in leader cluster: %v, stderr: %s", err, stderr)
	}
	return nil
}

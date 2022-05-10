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

	log "github.com/sirupsen/logrus"

	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e/utils"
)

const (
	// Provide enough time for policies to be enforced & deleted by the CNI plugin.
	networkPolicyDelay          = 2 * time.Second
	acnpIsolationResourceExport = "test-acnp-copy-span-ns-isolation.yml"
	acnpName                    = "antrea-mc-strict-namespace-isolation"
)

var (
	allPodsPerCluster                      []antreae2e.Pod
	perNamespacePods, perClusterNamespaces []string
	podsByNamespace                        map[string][]antreae2e.Pod
	clusterK8sUtilsMap                     map[string]*antreae2e.KubernetesUtils
)

func failOnError(err error, t *testing.T) {
	if err != nil {
		log.Errorf("%+v", err)
		for _, k8sUtils := range clusterK8sUtilsMap {
			k8sUtils.Cleanup(perClusterNamespaces)
		}
		t.Fatalf("test failed: %v", err)
	}
}

// initializeForPolicyTest creates three Pods in three test Namespaces for each test cluster.
func initializeForPolicyTest(t *testing.T, data *MCTestData) {
	perNamespacePods = []string{"a", "b", "c"}
	perClusterNamespaces = []string{"x", "y", "z"}

	allPodsPerCluster = []antreae2e.Pod{}
	podsByNamespace = make(map[string][]antreae2e.Pod)
	clusterK8sUtilsMap = make(map[string]*antreae2e.KubernetesUtils)

	for _, podName := range perNamespacePods {
		for _, ns := range perClusterNamespaces {
			allPodsPerCluster = append(allPodsPerCluster, antreae2e.NewPod(ns, podName))
			podsByNamespace[ns] = append(podsByNamespace[ns], antreae2e.NewPod(ns, podName))
		}
	}
	for clusterName := range data.clusterTestDataMap {
		d := data.clusterTestDataMap[clusterName]
		k8sUtils, err := antreae2e.NewKubernetesUtils(&d)
		failOnError(err, t)
		_, err = k8sUtils.Bootstrap(perClusterNamespaces, perNamespacePods)
		failOnError(err, t)
		clusterK8sUtilsMap[clusterName] = k8sUtils
	}
}

// tearDownForPolicyTest deletes the test Namespaces specific for policy tests.
func tearDownForPolicyTest() {
	for _, k8sUtils := range clusterK8sUtilsMap {
		k8sUtils.Cleanup(perClusterNamespaces)
	}
}

func testMCAntreaPolicy(t *testing.T, data *MCTestData) {
	data.testAntreaPolicyCopySpanNSIsolation(t)
}

// testAntreaPolicyCopySpanNSIsolation tests that after applying a ResourceExport of an ACNP
// for Namespace isolation, strict Namespace isolation is enforced in each of the member clusters.
func (data *MCTestData) testAntreaPolicyCopySpanNSIsolation(t *testing.T) {
	setup := func() {
		err := data.deployACNPResourceExport(acnpIsolationResourceExport)
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
	executeTestsOnAllMemberClusters(t, testCaseList, setup, teardown)
}

func executeTestsOnAllMemberClusters(t *testing.T, testList []*antreae2e.TestCase, setup, teardown func()) {
	setup()
	time.Sleep(networkPolicyDelay)
	for _, testCase := range testList {
		log.Infof("Running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("Running step %s of test case %s", step.Name, testCase.Name)
			reachability := step.Reachability
			if reachability != nil {
				for clusterName, k8sUtils := range clusterK8sUtilsMap {
					if clusterName == leaderCluster {
						// skip traffic test for the leader cluster
						continue
					}
					if _, err := k8sUtils.GetACNP(acnpName); err != nil {
						t.Errorf("Failed to get ACNP to be replicated in cluster %s", clusterName)
					}
					start := time.Now()
					k8sUtils.Validate(allPodsPerCluster, reachability, step.Ports, step.Protocol)
					step.Duration = time.Now().Sub(start)
					_, wrong, _ := step.Reachability.Summary()
					if wrong != 0 {
						t.Errorf("Failure in cluster %s -- %d wrong results", clusterName, wrong)
						reachability.PrintSummary(true, true, true)
					}
				}
			}
		}
	}
	teardown()
}

func (data *MCTestData) deployACNPResourceExport(reFileName string) error {
	var rc int
	var err error
	log.Infof("Creating ResourceExport %s in the leader cluster", reFileName)
	rc, _, _, err = provider.RunCommandOnNode(leaderCluster, fmt.Sprintf("kubectl apply -f %s", reFileName))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deploying the ACNP ResourceExport in leader cluster: %v", err)
	}
	return nil
}

func (data *MCTestData) deleteACNPResourceExport(reFileName string) error {
	var rc int
	var err error
	rc, _, _, err = provider.RunCommandOnNode(leaderCluster, fmt.Sprintf("kubectl delete -f %s", reFileName))
	if err != nil || rc != 0 {
		return fmt.Errorf("error when deleting the ACNP ResourceExport in leader cluster: %v", err)
	}
	return nil
}

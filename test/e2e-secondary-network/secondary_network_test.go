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

package e2esecondary

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	logs "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	antreae2e "antrea.io/antrea/test/e2e"
)

type testPodInfo struct {
	podName  string
	nodeName string
	// map from interface name to secondary network name.
	interfaceNetworks map[string]string
}

type testData struct {
	e2eTestData *antreae2e.TestData
	networkType string
	pods        []*testPodInfo
}

const (
	networkTypeSriov = "sriov"
	networkTypeVLAN  = "vlan"

	// Namespace of NetworkAttachmentDefinition CRs.
	attachDefNamespace = "default"

	containerName  = "toolbox"
	podApp         = "secondaryTest"
	osType         = "linux"
	pingCount      = 5
	pingSize       = 40
	defaultTimeout = 10 * time.Second
	sriovReqName   = "intel.com/intel_sriov_netdevice"
	sriovResNum    = 3
)

// formAnnotationStringOfPod forms the annotation string, used in the generation of each Pod YAML file.
func (data *testData) formAnnotationStringOfPod(pod *testPodInfo) string {
	var annotationString = ""
	for i, n := range pod.interfaceNetworks {
		podNetworkSpec := fmt.Sprintf("{\"name\": \"%s\", \"namespace\": \"%s\", \"interface\": \"%s\"}",
			n, attachDefNamespace, i)
		if annotationString == "" {
			annotationString = "[" + podNetworkSpec
		} else {
			annotationString = annotationString + ", " + podNetworkSpec
		}
	}
	annotationString = annotationString + "]"
	return annotationString
}

// createPodOnNode creates the Pod for the specific annotations as per the parsed Pod information using the NewPodBuilder API
func (data *testData) createPods(t *testing.T, ns string) error {
	var err error
	for _, pod := range data.pods {
		err := data.createPodForSecondaryNetwork(ns, pod)
		if err != nil {
			return fmt.Errorf("error in creating pods.., err: %v", err)
		}
	}
	return err
}

// The Wrapper function createPodForSecondaryNetwork creates the Pod adding the annotation, arguments, commands, Node, container name,
// resource requests and limits as arguments with the NewPodBuilder API
func (data *testData) createPodForSecondaryNetwork(ns string, pod *testPodInfo) error {
	podBuilder := antreae2e.NewPodBuilder(pod.podName, ns, antreae2e.ToolboxImage).
		OnNode(pod.nodeName).WithContainerName(containerName).
		WithAnnotations(map[string]string{
			"k8s.v1.cni.cncf.io/networks": fmt.Sprintf("%s", data.formAnnotationStringOfPod(pod)),
		}).
		WithLabels(map[string]string{
			"App": fmt.Sprintf("%s", podApp),
		})

	if data.networkType == networkTypeSriov {
		computeResources := resource.NewQuantity(sriovResNum, resource.DecimalSI)
		podBuilder = podBuilder.WithResources(corev1.ResourceList{sriovReqName: *computeResources}, corev1.ResourceList{sriovReqName: *computeResources})
	}
	return podBuilder.Create(data.e2eTestData)
}

// getSecondaryInterface checks the secondary interfaces created for the specific Pod and returns its IPv4 address.
func (data *testData) getSecondaryInterface(targetPod *testPodInfo, interfaceName string) (string, error) {
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d/ -f1", interfaceName)}
	stdout, _, err := data.e2eTestData.RunCommandFromPod(data.e2eTestData.GetTestNamespace(), targetPod.podName, containerName, cmd)
	stdout = strings.TrimSuffix(stdout, "\n")
	if err != nil || stdout == "" {
		return "", fmt.Errorf("interface %s not found on %s. err: %v", interfaceName, targetPod.podName, err)
	}
	return stdout, nil
}

// checkSubnet checks if the IP address to be pinged has the same subnet as the Pod from which the IP Address is pinged.
func (data *testData) checkSubnet(t *testing.T, sourcePod, targetPod *testPodInfo, targetNetwork string) (bool, error) {
	for i, n := range sourcePod.interfaceNetworks {
		if n == targetNetwork {
			_, err := data.getSecondaryInterface(sourcePod, i)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// pingBetweenInterfaces parses through all the created Pods and pings the other Pod if the two Pods
// both have a secondary network interface on the same network.
func (data *testData) pingBetweenInterfaces(t *testing.T) error {
	e2eTestData := data.e2eTestData
	namespace := e2eTestData.GetTestNamespace()
	for _, sourcePod := range data.pods {
		for _, targetPod := range data.pods {
			if targetPod.podName == sourcePod.podName {
				continue
			}
			for i, n := range targetPod.interfaceNetworks {
				_, err := e2eTestData.PodWaitFor(defaultTimeout, targetPod.podName, namespace, func(pod *corev1.Pod) (bool, error) {
					return pod.Status.Phase == corev1.PodRunning, nil
				})
				if err != nil {
					return fmt.Errorf("error when waiting for Pod %s: %v", targetPod.podName, err)
				}

				matched, _ := data.checkSubnet(t, sourcePod, targetPod, n)
				if matched {
					secondaryIPAddress, err := data.getSecondaryInterface(targetPod, i)
					if err != nil {
						return err
					}
					ip := net.ParseIP(secondaryIPAddress)
					if ip == nil {
						return fmt.Errorf("failed to parse IP (%s) for interface %s of Pod %s", secondaryIPAddress, i, targetPod.podName)
					}
					var IPToPing antreae2e.PodIPs
					if ip.To4() != nil {
						IPToPing = antreae2e.PodIPs{IPv4: &ip}
					} else {
						IPToPing = antreae2e.PodIPs{IPv6: &ip}
					}
					if err := e2eTestData.RunPingCommandFromTestPod(antreae2e.PodInfo{Name: sourcePod.podName, OS: osType, NodeName: sourcePod.nodeName, Namespace: namespace},
						namespace, &IPToPing, containerName, pingCount, pingSize, false); err != nil {
						return fmt.Errorf("ping '%s' -> '%s'(Interface: %s, IP Address: %s) failed: %v", sourcePod.podName, targetPod.podName, i, secondaryIPAddress, err)
					}
					logs.Infof("ping '%s' -> '%s'( Interface: %s, IP Address: %s): OK", sourcePod.podName, targetPod.podName, i, secondaryIPAddress)
				}
			}
		}
	}
	return nil
}

func testSecondaryNetwork(t *testing.T, networkType string, pods []*testPodInfo) {
	e2eTestData, err := antreae2e.SetupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer antreae2e.TeardownTest(t, e2eTestData)

	testData := &testData{e2eTestData: e2eTestData, networkType: networkType, pods: pods}

	t.Run("testCreateTestPodOnNode", func(t *testing.T) {
		testData.createPods(t, e2eTestData.GetTestNamespace())
	})
	t.Run("testpingBetweenInterfaces", func(t *testing.T) {
		err := testData.pingBetweenInterfaces(t)
		if err != nil {
			t.Fatalf("Error when pinging between interfaces: %v", err)
		}
	})
}

func TestSriovNetwork(t *testing.T) {
	// Create Pods on the control plane Node, assuming a single Node cluster for the SR-IOV
	// test.
	nodeName := antreae2e.NodeName(0)
	pods := []*testPodInfo{
		{
			podName:           "sriov-pod1",
			nodeName:          nodeName,
			interfaceNetworks: map[string]string{"eth1": "sriov-net1", "eth2": "sriov-net2"},
		},
		{
			podName:           "sriov-pod2",
			nodeName:          nodeName,
			interfaceNetworks: map[string]string{"eth2": "sriov-net1", "eth3": "sriov-net3"},
		},
		{
			podName:           "sriov-pod3",
			nodeName:          nodeName,
			interfaceNetworks: map[string]string{"eth4": "sriov-net1"},
		},
	}
	testSecondaryNetwork(t, networkTypeSriov, pods)
}

func TestVLANNetwork(t *testing.T) {
	if antreae2e.NodeCount() < 2 {
		t.Fatalf("The test requires at least 2 nodes, but the cluster has only %d", antreae2e.NodeCount())
	}
	node1 := antreae2e.NodeName(0)
	node2 := antreae2e.NodeName(1)
	pods := []*testPodInfo{
		{
			podName:           "vlan-pod1",
			nodeName:          node1,
			interfaceNetworks: map[string]string{"eth1": "vlan-net1", "eth2": "vlan-net2"},
		},
		{
			podName:           "vlan-pod2",
			nodeName:          node1,
			interfaceNetworks: map[string]string{"eth1": "vlan-net1", "eth2": "vlan-net3"},
		},
		{
			podName:           "vlan-pod3",
			nodeName:          node2,
			interfaceNetworks: map[string]string{"eth1": "vlan-net2"},
		},
	}
	testSecondaryNetwork(t, networkTypeVLAN, pods)
}

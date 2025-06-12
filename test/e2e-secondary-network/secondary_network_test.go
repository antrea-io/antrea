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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netattdef "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	logs "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e-secondary-network/aws"
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
	ipPoolNamespace    = "default"
	secondaryOVSBridge = "br-secondary"

	containerName  = "toolbox"
	podApp         = "secondaryTest"
	osType         = "linux"
	pingCount      = 5
	pingSize       = 40
	defaultTimeout = 10 * time.Second
	sriovReqName   = "intel.com/intel_sriov_netdevice"
	sriovResNum    = 1
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
			return fmt.Errorf("error in creating pods.., err: %w", err)
		}
	}
	return err
}

func generateExpectedNetworks(pod *testPodInfo, ipv4Addrs, ipv6Addrs map[string]net.IP, macMap map[string]string) []nadv1.NetworkStatus {
	var statuses []nadv1.NetworkStatus
	for inf, name := range pod.interfaceNetworks {
		var ips []string
		if ip, ok := ipv4Addrs[inf]; ok && len(ip) != 0 {
			ips = append(ips, ip.String())
		}
		if ip, ok := ipv6Addrs[inf]; ok && len(ip) != 0 {
			ips = append(ips, ip.String())
		}
		statuses = append(statuses, nadv1.NetworkStatus{
			Name:      name,
			Interface: inf,
			IPs:       ips,
			Mac:       macMap[inf],
			Default:   false,
		})
	}
	return statuses
}

func (data *testData) assertPodNetworkStatus(t *testing.T, clientset *kubernetes.Clientset, pods []*testPodInfo, ns string) error {
	for _, pod := range pods {
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			podItem, err := clientset.CoreV1().Pods(ns).Get(ctx, pod.podName, metav1.GetOptions{})
			assert.NoError(collect, err, "Failed to get Pod")

			secondaryNetworkList, err := utils.ParsePodNetworkAnnotation(podItem)
			assert.NoError(collect, err, "Failed to parse network annotation")

			ips, ipv6Addrs, macMap, err := data.listPodAddresses(pod)
			assert.NoError(collect, err, "Failed to parse Pod network interface information")

			networkStatus, err := utils.GetNetworkStatus(podItem)
			assert.NoError(collect, err, "Failed to parse network status from Pod annotation")
			assert.Equal(collect, true, len(networkStatus) == len(ips)-2, "The number of network interface statuses in `k8s.v1.cni.cncf.io/network-status` should match the number of secondary network interface IPs in the Pod")
			assert.Equal(collect, true, len(networkStatus) == len(secondaryNetworkList), "The number of network interface statuses in `k8s.v1.cni.cncf.io/network-status` should be consistent with the number of network interface defined in `k8s.v1.cni.cncf.io/networks`")

			expectedSecondaryNetworkStatuses := generateExpectedNetworks(pod, ips, ipv6Addrs, macMap)
			assert.ElementsMatch(collect, expectedSecondaryNetworkStatuses, networkStatus, "The Pod network-status annotation is not as expected")
		}, 20*time.Second, time.Second, "Pod %s network status validation timed out", pod.podName)
	}
	return nil
}

// The Wrapper function createPodForSecondaryNetwork creates the Pod adding the annotation, arguments, commands, Node, container name,
// resource requests and limits as arguments with the NewPodBuilder API
func (data *testData) createPodForSecondaryNetwork(ns string, pod *testPodInfo) error {
	podBuilder := antreae2e.NewPodBuilder(pod.podName, ns, antreae2e.ToolboxImage).
		OnNode(pod.nodeName).WithContainerName(containerName).
		WithAnnotations(map[string]string{
			nadv1.NetworkAttachmentAnnot: data.formAnnotationStringOfPod(pod),
		}).
		WithLabels(map[string]string{
			"App": podApp,
		})

	if data.networkType == networkTypeSriov {
		computeResources := resource.NewQuantity(sriovResNum, resource.DecimalSI)
		podBuilder = podBuilder.WithResources(corev1.ResourceList{sriovReqName: *computeResources}, corev1.ResourceList{sriovReqName: *computeResources})
	}
	return podBuilder.Create(data.e2eTestData)
}

// listPodAddresses returns Pod network interface information with enhanced parsing.
func (data *testData) listPodAddresses(targetPod *testPodInfo) (map[string]net.IP, map[string]net.IP, map[string]string, error) {
	cmd := []string{"ip", "addr", "show"}
	stdout, _, err := data.e2eTestData.RunCommandFromPod(data.e2eTestData.GetTestNamespace(), targetPod.podName, containerName, cmd)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error when listing interfaces for %s: %w", targetPod.podName, err)
	}
	ipv4Result := make(map[string]net.IP)
	macResult := make(map[string]string)
	ipv6Result := make(map[string]net.IP)
	var currentInterface string
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasSuffix(fields[0], ":") {
			// first field is ifindex, second field is interface name
			currentInterface = strings.Split(strings.TrimSuffix(fields[1], ":"), "@")[0]
			ipv4Result[currentInterface] = nil
			ipv6Result[currentInterface] = nil
			macResult[currentInterface] = ""
		} else if len(fields) >= 2 && (fields[0] == "inet" || fields[0] == "inet6") {
			ipStr := strings.Split(fields[1], "/")[0]
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, nil, nil, fmt.Errorf("failed to parse IP (%s) for interface %s of Pod %s", ipStr, currentInterface, targetPod.podName)
			}
			if fields[0] == "inet" {
				ipv4Result[currentInterface] = ip
			} else if fields[0] == "inet6" && strings.Contains(line, "scope global") {
				ipv6Result[currentInterface] = ip
			}
		} else if len(fields) >= 2 && fields[0] == "link/ether" {
			macResult[currentInterface] = fields[1]
		}
	}
	return ipv4Result, ipv6Result, macResult, nil
}

// pingBetweenInterfaces parses through all the created Pods and pings the other Pod if the two Pods
// both have a secondary network interface on the same network.
func (data *testData) pingBetweenInterfaces(t *testing.T) error {
	e2eTestData := data.e2eTestData
	namespace := e2eTestData.GetTestNamespace()

	type attachment struct {
		network string
		iface   string
		ip      net.IP
	}
	type network struct {
		// maps each Pod to its attachments in this network (typically just one)
		podAttachments map[*testPodInfo][]*attachment
	}
	networks := make(map[string]*network)
	addPodNetworkAttachments := func(pod *testPodInfo, podAttachments []*attachment) {
		for _, pa := range podAttachments {
			if _, ok := networks[pa.network]; !ok {
				networks[pa.network] = &network{
					podAttachments: make(map[*testPodInfo][]*attachment),
				}
			}
			networks[pa.network].podAttachments[pod] = append(networks[pa.network].podAttachments[pod], pa)
		}
	}

	// Collect all secondary network IPs when they are available.
	for _, testPod := range data.pods {
		_, err := e2eTestData.PodWaitFor(defaultTimeout, testPod.podName, namespace, func(pod *corev1.Pod) (bool, error) {
			if pod.Status.Phase != corev1.PodRunning {
				return false, nil
			}
			var podNetworkAttachments []*attachment
			podIPs, _, _, err := data.listPodAddresses(testPod)
			if err != nil {
				return false, err
			}
			for iface, net := range testPod.interfaceNetworks {
				if podIPs[iface] == nil {
					return false, nil
				}
				podNetworkAttachments = append(podNetworkAttachments, &attachment{
					network: net,
					iface:   iface,
					ip:      podIPs[iface],
				})
			}
			// we found all the expected secondary network interfaces / attachments
			addPodNetworkAttachments(testPod, podNetworkAttachments)
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("error when waiting for secondary IPs for Pod %+v: %w", testPod, err)
		}
	}

	// Run ping-mesh test for each secondary network.
	for _, network := range networks {
		for sourcePod := range network.podAttachments {
			for targetPod, targetPodAttachments := range network.podAttachments {
				if sourcePod == targetPod {
					continue
				}
				for _, targetAttachment := range targetPodAttachments {
					var IPToPing antreae2e.PodIPs
					if targetAttachment.ip.To4() != nil {
						IPToPing = antreae2e.PodIPs{IPv4: &targetAttachment.ip}
					} else {
						IPToPing = antreae2e.PodIPs{IPv6: &targetAttachment.ip}
					}
					if err := e2eTestData.RunPingCommandFromTestPod(antreae2e.PodInfo{Name: sourcePod.podName, OS: osType, NodeName: sourcePod.nodeName, Namespace: namespace},
						namespace, &IPToPing, containerName, pingCount, pingSize, false); err != nil {
						return fmt.Errorf("ping '%s' -> '%s'(Interface: %s, IP Address: %s) failed: %w", sourcePod.podName, targetPod.podName, targetAttachment.iface, targetAttachment.ip, err)
					}
					logs.Infof("ping '%s' -> '%s'( Interface: %s, IP Address: %s): OK", sourcePod.podName, targetPod.podName, targetAttachment.iface, targetAttachment.ip)
				}
			}
		}
	}
	return nil
}

// getIPPoolNames maps each Pod's interface to its associated IPPools.
func (data *testData) getIPPoolNames(ifaces []string, vlanPod *testPodInfo, namespace string) (map[string][]string, error) {
	client, err := netattdef.NewForConfig(data.e2eTestData.KubeConfig)
	if err != nil {
		return nil, err
	}

	ipPoolsMap := make(map[string][]string)

	for _, iface := range ifaces {
		networkName, exists := vlanPod.interfaceNetworks[iface]
		if !exists {
			return nil, fmt.Errorf("network name not found for interface %s", iface)
		}
		netAttachDef, err := client.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Get(context.TODO(), networkName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get NetworkAttachmentDefinition %s for interface %s: %w", networkName, iface, err)
		}

		var netAttachDefConfig struct {
			IPAM struct {
				IPPools []string `json:"ippools"`
			} `json:"ipam"`
		}

		if err := json.Unmarshal([]byte(netAttachDef.Spec.Config), &netAttachDefConfig); err != nil {
			return nil, fmt.Errorf("failed to parse NetworkAttachmentDefinition config JSON for interface %s: %w", iface, err)
		}

		ipPoolsMap[iface] = netAttachDefConfig.IPAM.IPPools

	}
	return ipPoolsMap, nil
}

func (data *testData) checkIPReleased(ipPools map[string][]string, ifacesIPs map[string]net.IP, ifaces []string) error {
	crdClient := data.e2eTestData.CRDClient
	return wait.PollUntilContextTimeout(context.Background(), time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		for _, iface := range ifaces {
			ipPoolName, exists := ipPools[iface]
			if !exists {
				return false, fmt.Errorf("no IPPool found for interface %s", iface)
			}

			podIP, exists := ifacesIPs[iface]
			if !exists {
				return false, fmt.Errorf("no IP found for interface %s", iface)
			}

			ipPool, err := crdClient.CrdV1beta1().IPPools().Get(ctx, ipPoolName[0], metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get IPPool %s: %w", ipPoolName[0], err)
			}

			for _, ipAddress := range ipPool.Status.IPAddresses {
				if podIP.String() == ipAddress.IPAddress {
					return false, nil
				}
			}
			logs.Infof("Released PodIP: %v, Interface: %s", podIP, iface)
		}
		return true, nil
	})
}

func (data *testData) getOVSPortsOnSecondaryBridge(t *testing.T, nodeName string) ([]string, error) {
	cmd := []string{"ovs-vsctl", "list-ports", secondaryOVSBridge}

	stdout, stderr, err := data.e2eTestData.RunCommandFromAntreaPodOnNode(nodeName, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run ovs-vsctl on node %s: %v\nstderr: %s", nodeName, err, stderr)
	}

	ovsPorts := strings.Fields(stdout)
	return ovsPorts, nil
}

// reconcilationAfterAgentRestart verifies OVS Ports cleanup and IP release.
func (data *testData) reconcilationAfterAgentRestart(t *testing.T) error {
	beforeAgentRestartOvsPorts := make(map[string][]string)
	beforeAgentRestartIPsAndIfaces := make(map[string]map[string]net.IP)
	for _, pod := range data.pods {
		ports, err := data.getOVSPortsOnSecondaryBridge(t, pod.nodeName)
		require.NoError(t, err, "Failed to get Secondary bridge OVS Ports before agent restart")
		beforeAgentRestartOvsPorts[pod.nodeName] = ports

		ips, _, _, err := data.listPodAddresses(pod)
		require.NoError(t, err, "Failed to get Pod IP before agent restart")
		beforeAgentRestartIPsAndIfaces[pod.podName] = ips
	}

	require.NoError(t, data.e2eTestData.RestartAntreaAgentPods(30*time.Second), "Failed to restart Antrea agent Pods")

	afterAgentRestartOvsPorts := make(map[string][]string)
	afterAgentRestartIPsAndIfaces := make(map[string]map[string]net.IP)
	for _, pod := range data.pods {
		ports, err := data.getOVSPortsOnSecondaryBridge(t, pod.nodeName)
		require.NoError(t, err, "Failed to get Secondary bridge OVS Ports after agent restart")
		afterAgentRestartOvsPorts[pod.nodeName] = ports

		ips, _, _, err := data.listPodAddresses(pod)
		require.NoError(t, err, "Failed to get Pod IP after agent restart")
		afterAgentRestartIPsAndIfaces[pod.podName] = ips
	}

	// Compare OVS ports before and after restart
	for nodeName, portsBefore := range beforeAgentRestartOvsPorts {
		assert.ElementsMatch(t, portsBefore, afterAgentRestartOvsPorts[nodeName],
			"Secondary bridge OVS Ports mismatch after agent restart on node %s", nodeName)
	}

	// Compare IPs and interfaces before and after restart
	for podName, ipsBefore := range beforeAgentRestartIPsAndIfaces {
		assert.Equal(t, ipsBefore, afterAgentRestartIPsAndIfaces[podName],
			"Pod: %s, Interfaces and IPs mismatch after agent restart", podName)
	}

	// Remove Pod and check IP released or not.
	vlanPod := data.pods[1]
	ifaces := []string{"eth1", "eth2"}
	ifacesIPs, _, _, err := data.listPodAddresses(vlanPod)
	require.NoError(t, err, "Failed to get IPs of Interfaces")

	beforeDeletionOvsPorts, err := data.getOVSPortsOnSecondaryBridge(t, vlanPod.nodeName)
	require.NoError(t, err, "Failed to get OVS Ports Before Pod deletion")

	ipPools, err := data.getIPPoolNames(ifaces, vlanPod, ipPoolNamespace)
	require.NoError(t, err, "Failed to get IPPool")

	require.NoError(t, data.e2eTestData.DeletePodAndWait(defaultTimeout, vlanPod.podName, data.e2eTestData.GetTestNamespace()), "Failed to delete Pod")

	afterDeletionOvsPorts, err := data.getOVSPortsOnSecondaryBridge(t, vlanPod.nodeName)
	require.NoError(t, err, "Failed to get OVS Ports After Pod deletion")

	assert.NotEqual(t, beforeDeletionOvsPorts, afterDeletionOvsPorts, "OVS Ports for VLAN Pod still exist")

	return data.checkIPReleased(ipPools, ifacesIPs, ifaces)
}

func testSecondaryNetwork(t *testing.T, networkType string, pods []*testPodInfo) {
	e2eTestData, err := antreae2e.SetupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer antreae2e.TeardownTest(t, e2eTestData)

	testData := &testData{e2eTestData: e2eTestData, networkType: networkType, pods: pods}

	ns := e2eTestData.GetTestNamespace()
	if err := testData.createPods(t, ns); err != nil {
		t.Fatalf("Error when create test Pods: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(e2eTestData.KubeConfig)
	if err != nil {
		t.Fatalf("Error when creating kubernetes client: %v", err)
	}
	if err := testData.pingBetweenInterfaces(t); err != nil {
		t.Fatalf("Error when pinging between interfaces: %v", err)
	}
	if err := testData.assertPodNetworkStatus(t, clientset, pods, ns); err != nil {
		t.Fatalf("Error when checking the Pod annotation: %v", err)
	}
	t.Run("testReconcilationAfterAgentRestart", func(t *testing.T) {
		testData.reconcilationAfterAgentRestart(t)
	})
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

func (data *testData) assignIP(clientset *kubernetes.Clientset) error {
	e2eTestData := data.e2eTestData
	namespace := e2eTestData.GetTestNamespace()

	for _, testPod := range data.pods {
		node, err := clientset.CoreV1().Nodes().Get(context.TODO(), testPod.nodeName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error when getting the cluster Node %s: %w", testPod.nodeName, err)
		}
		eni, exists := node.Labels["eni-id"]
		if !exists {
			return fmt.Errorf("the label `eni-id` not found in the cluster Node: %s", testPod.nodeName)
		}
		var podIP net.IP
		_, err = e2eTestData.PodWaitFor(defaultTimeout, testPod.podName, namespace, func(pod *corev1.Pod) (bool, error) {
			if pod.Status.Phase != corev1.PodRunning {
				return false, nil
			}
			podIPs, _, _, err := data.listPodAddresses(testPod)
			if err != nil {
				return false, err
			}
			ip, exists := podIPs["eth1"]
			if !exists || ip == nil {
				logs.Infof("IP not available for interface 'eth1' in Pod %s, retrying...", testPod.podName)
				return false, nil
			}
			podIP = ip

			return true, nil
		})
		if err := aws.AssignIPToEC2ENI(context.TODO(), eni, podIP.String()); err != nil {
			return err
		}
		logs.Infof("assigned private IP address %s to interface %s", podIP, eni)
		if err != nil {
			return fmt.Errorf("error when waiting for the secondary IP for Pod %+v: %w", testPod, err)
		}
	}
	return nil
}

func TestSRIOVNetwork(t *testing.T) {
	e2eTestData, err := antreae2e.SetupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer antreae2e.TeardownTest(t, e2eTestData)

	pods := []*testPodInfo{
		{
			podName:           "sriov-pod1",
			nodeName:          antreae2e.NodeName(0),
			interfaceNetworks: map[string]string{"eth1": "sriov-net1"},
		},
		{
			podName:           "sriov-pod2",
			nodeName:          antreae2e.NodeName(1),
			interfaceNetworks: map[string]string{"eth1": "sriov-net1"},
		},
	}

	testData := &testData{e2eTestData: e2eTestData, networkType: networkTypeSriov, pods: pods}

	// Get the original VF interface name on the Node.
	pod1 := pods[0].podName
	node1 := pods[0].nodeName
	vfName := GetVFInterfaceName(t, e2eTestData, node1)
	logs.Infof("The original VF interface name is %s on Node %s", vfName, node1)

	ns := e2eTestData.GetTestNamespace()
	if err := testData.createPods(t, ns); err != nil {
		t.Fatalf("Error when create test Pods: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(e2eTestData.KubeConfig)
	if err != nil {
		t.Fatalf("Error when creating kubernetes client: %v", err)
	}
	if err := testData.assignIP(clientset); err != nil {
		t.Fatalf("Error when assign IP to ec2 instance: %v", err)
	}
	if err := testData.pingBetweenInterfaces(t); err != nil {
		t.Fatalf("Error when pinging between interfaces: %v", err)
	}
	if err := testData.assertPodNetworkStatus(t, clientset, pods, ns); err != nil {
		t.Fatalf("Error when checking the Pod annotation: %v", err)
	}
	if err := testData.assertVFName(t, e2eTestData, vfName, pod1, node1, ns); err != nil {
		t.Fatalf("Error when checking the VF device name: %v", err)
	}
}

func (data *testData) assertVFName(t *testing.T, e2eTestData *antreae2e.TestData, vfName, podName, nodeName, ns string) error {
	//  Delete a Pod and check the VF device is recovered with the original interface name.
	err := e2eTestData.DeletePodAndWait(5*time.Second, podName, ns)
	if err == nil {
		recoveredVFName := GetVFInterfaceName(t, e2eTestData, nodeName)
		logs.Infof("The recovered VF interface name is %s on Node %s", recoveredVFName, nodeName)
		assert.Equal(t, vfName, recoveredVFName, "VF name is not recovered correctly on Node %s, the expected VF name is %s, but got %s", nodeName, vfName, recoveredVFName)
	}
	return err
}

func GetVFInterfaceName(t *testing.T, e2eTestData *antreae2e.TestData, nodeName string) string {
	cmd := "ip -d link show | grep -B1 0000:00:04.0 | head -n 1 | awk -F': ' '{print $2}' | xargs"
	_, vfName, _, err := e2eTestData.RunCommandOnNode(nodeName, cmd)
	if err != nil {
		t.Fatalf("Error when checking the VF interface name on the Node %s: %v", nodeName, err)
	}
	return vfName
}

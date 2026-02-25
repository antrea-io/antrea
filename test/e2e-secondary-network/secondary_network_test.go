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

	"antrea.io/antrea/pkg/agent/cniserver"
	antreae2e "antrea.io/antrea/test/e2e"
	"antrea.io/antrea/test/e2e-secondary-network/aws"
)

type testPodInfo struct {
	podName  string
	nodeName string
	// map from interface name to secondary network name.
	interfaceNetworks map[string]string
	// map from interface name to secondary MAC address.
	macAddresses map[string]string
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
	defaultTimeout = 30 * time.Second
	sriovReqName   = "intel.com/intel_sriov_netdevice"
	sriovResNum = 1

	ipFamilyIPv4 = 4
	ipFamilyIPv6 = 6
)

// formAnnotationStringOfPod forms the annotation string, used in the generation of each Pod YAML file.
func (data *testData) formAnnotationStringOfPod(pod *testPodInfo) string {
	var annotationString string
	for i, n := range pod.interfaceNetworks {
		podNetworkSpec := fmt.Sprintf("{\"name\": \"%s\", \"namespace\": \"%s\", \"interface\": \"%s\"",
			n, attachDefNamespace, i)

		if pod.macAddresses != nil {
			if mac, ok := pod.macAddresses[i]; ok {
				podNetworkSpec += fmt.Sprintf(", \"mac\": \"%s\"", mac)
			}
		}
		podNetworkSpec += "}"

		if annotationString == "" {
			annotationString = "[" + podNetworkSpec
		} else {
			annotationString = annotationString + ", " + podNetworkSpec
		}
	}
	annotationString += "]"
	return annotationString
}

// createPodOnNode creates the Pod for the specific annotations as per the parsed Pod information using the NewPodBuilder API
func (data *testData) createPods(t *testing.T, ns string) error {
	for _, pod := range data.pods {
		if err := data.createPodForSecondaryNetwork(ns, pod); err != nil {
			return fmt.Errorf("error creating Pods: %w", err)
		}
	}
	return nil
}

func generateExpectedNetworks(pod *testPodInfo, ipv4Addrs, ipv6Addrs map[string]net.IP, macMap map[string]string, isSRIOV bool) []nadv1.NetworkStatus {
	var statuses []nadv1.NetworkStatus
	for inf, name := range pod.interfaceNetworks {
		var ips []string
		if ip, ok := ipv4Addrs[inf]; ok && len(ip) != 0 {
			ips = append(ips, ip.String())
		}
		if ip, ok := ipv6Addrs[inf]; ok && len(ip) != 0 {
			ips = append(ips, ip.String())
		}
		if len(ips) == 0 {
			continue
		}
		status := nadv1.NetworkStatus{
			Name:      name,
			Interface: inf,
			IPs:       ips,
			Mac:       macMap[inf],
			Default:   false,
		}
		if isSRIOV && inf != "eth0" {
			status.DeviceInfo = &nadv1.DeviceInfo{
				Type: nadv1.DeviceInfoTypePCI,
				// The PCI address is defined in the file test/e2e-secondary-network/sriov-secondary-networks.yml.
				// so we use the value directly instead of checking Pod's interface.
				Pci: &nadv1.PciDevice{
					PciAddress: "0000:00:04.0",
				},
			}
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (data *testData) assertPodNetworkStatus(t *testing.T, clientset *kubernetes.Clientset, pods []*testPodInfo, ns string, isSRIOV bool) error {
	for _, pod := range pods {
		assert.EventuallyWithT(t, func(collect *assert.CollectT) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			podItem, err := clientset.CoreV1().Pods(ns).Get(ctx, pod.podName, metav1.GetOptions{})
			assert.NoError(collect, err, "Failed to get Pod")

			var secondaryNetworkList []*nadv1.NetworkSelectionElement
			if len(podItem.Annotations[nadv1.NetworkAttachmentAnnot]) != 0 {
				secondaryNetworkList, err = utils.ParsePodNetworkAnnotation(podItem)
				assert.NoError(collect, err, "Failed to parse network annotation")
			}
			if secondaryNetworkList == nil {
				_, ok := podItem.Annotations[nadv1.NetworkStatusAnnot]
				assert.False(t, ok, "Pod network status annotation should be deleted")
				return
			}

			ips, ipv6Addrs, macMap, err := data.listPodAddresses(pod)
			assert.NoError(collect, err, "Failed to parse Pod network interface information")

			networkStatus, err := utils.GetNetworkStatus(podItem)
			assert.NoError(collect, err, "Failed to parse network status from Pod annotation")
			assert.Equal(collect, true, len(networkStatus) == len(ips)-1, "The number of network "+
				"interface statuses in `k8s.v1.cni.cncf.io/network-status` %+v should match the total number of interfaces "+
				"IPs in the Pod except the loopback interface", networkStatus)
			assert.Equal(collect, true, len(networkStatus) == len(secondaryNetworkList)+1, "The number of network "+
				"interface statuses in `k8s.v1.cni.cncf.io/network-status` %+v should be consistent with the total number of "+
				"the network interface defined in `k8s.v1.cni.cncf.io/networks` %+v plus the primary interface", networkStatus, secondaryNetworkList)

			var secondaryNetworkStatus []nadv1.NetworkStatus
			for i, network := range networkStatus {
				if network.Interface == "eth0" {
					assert.Equal(t, macMap[network.Interface], network.Mac, "The primary network status `Mac` is not as expected")
					assert.Equal(t, cniserver.AntreaCNIType, network.Name, "The primary network status `Name` is not as expected")
					assert.Equal(t, true, network.Default, "The primary network status `Default` is not as expected")
				} else {
					secondaryNetworkStatus = append(secondaryNetworkStatus, networkStatus[i])
				}
			}
			expectedSecondaryNetworkStatuses := generateExpectedNetworks(pod, ips, ipv6Addrs, macMap, isSRIOV)
			assert.ElementsMatch(collect, expectedSecondaryNetworkStatuses, secondaryNetworkStatus, "The Pod network-status annotation is not as expected")
		}, 20*time.Second, time.Second, "Pod %s network status validation timed out", pod.podName)
	}
	return nil
}

func (data *testData) deletePodNetworkAttachmentAnnot(t *testing.T, pods []*testPodInfo, ns string) error {
	for _, pod := range pods {
		err := data.e2eTestData.UpdatePod(ns, pod.podName, func(pod *corev1.Pod) {
			pod.Annotations[nadv1.NetworkAttachmentAnnot] = ""
		})
		if err != nil {
			return err
		}
		t.Logf("Delete Pod %s annotation: %+v\n", nadv1.NetworkAttachmentAnnot, pod)
	}
	return nil
}

func (data *testData) updatePodNetworkAttachmentAnnot(t *testing.T, pods []*testPodInfo, ns string) error {
	for _, pod := range pods {
		anno := data.formAnnotationStringOfPod(pod)
		err := data.e2eTestData.UpdatePod(ns, pod.podName, func(pod *corev1.Pod) {
			pod.Annotations[nadv1.NetworkAttachmentAnnot] = anno
		})
		if err != nil {
			return err
		}
		t.Logf("Update Pod annotation: %s, Pod: %+v\n", anno, pod)
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

// verifySecondaryInterfaces verifies MAC addresses and tests connectivity (ping)
// between secondary interfaces of all created Pods that are on the same network
// for the specified IP family (ipFamilyIPv4 or ipFamilyIPv6).
func (data *testData) verifySecondaryInterfaces(t *testing.T, family int) error {
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

	// Collect all secondary network IPs and verify MACs when they are available.
	for _, testPod := range data.pods {
		_, err := e2eTestData.PodWaitFor(defaultTimeout, testPod.podName, namespace, func(pod *corev1.Pod) (bool, error) {
			if pod.Status.Phase != corev1.PodRunning {
				return false, nil
			}
			var podNetworkAttachments []*attachment
			podIPs, podIPv6s, macResult, err := data.listPodAddresses(testPod)
			if err != nil {
				return false, err
			}
			for iface, net := range testPod.interfaceNetworks {
				ip := podIPs[iface]
				ipv6 := podIPv6s[iface]

				if family == ipFamilyIPv4 && ip == nil {
					return false, nil
				}
				if family == ipFamilyIPv6 && ipv6 == nil {
					return false, nil
				}

				if expectedMAC, ok := testPod.macAddresses[iface]; ok {
					actualMAC, exists := macResult[iface]
					if !exists {
						return false, fmt.Errorf("interface %s not found when checking MAC in Pod %s", iface, testPod.podName)
					}
					assert.Equal(t, expectedMAC, actualMAC, "MAC address mismatch for interface %s in Pod %s", iface, testPod.podName)
					logs.Infof("Interface %s in Pod %s has expected MAC address: %s", iface, testPod.podName, actualMAC)
				}

				if family == ipFamilyIPv4 && ip != nil {
					podNetworkAttachments = append(podNetworkAttachments, &attachment{
						network: net,
						iface:   iface,
						ip:      ip,
					})
				}
				if family == ipFamilyIPv6 && ipv6 != nil {
					podNetworkAttachments = append(podNetworkAttachments, &attachment{
						network: net,
						iface:   iface,
						ip:      ipv6,
					})
				}
			}
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

func (data *testData) checkIPReleased(ipPools map[string][]string, ifacesIPv4 map[string]net.IP, ifacesIPv6 map[string]net.IP, ifaces []string) error {
	crdClient := data.e2eTestData.CRDClient
	return wait.PollUntilContextTimeout(context.Background(), time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		for _, iface := range ifaces {
			poolNames, exists := ipPools[iface]
			if !exists {
				return false, fmt.Errorf("no IPPool found for interface %s", iface)
			}

			for _, poolName := range poolNames {
				ipPool, err := crdClient.CrdV1beta1().IPPools().Get(ctx, poolName, metav1.GetOptions{})
				if err != nil {
					return false, fmt.Errorf("failed to get IPPool %s: %w", poolName, err)
				}

				for _, ipAddress := range ipPool.Status.IPAddresses {
					if (ifacesIPv4[iface] != nil && ifacesIPv4[iface].String() == ipAddress.IPAddress) ||
						(ifacesIPv6[iface] != nil && ifacesIPv6[iface].String() == ipAddress.IPAddress) {
						return false, nil
					}
				}
			}
			logs.Infof("Released IPs for interface %s: IPv4=%v, IPv6=%v", iface, ifacesIPv4[iface], ifacesIPv6[iface])
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
	beforeAgentRestartIPv4s := make(map[string]map[string]net.IP)
	beforeAgentRestartIPv6s := make(map[string]map[string]net.IP)
	for _, pod := range data.pods {
		ports, err := data.getOVSPortsOnSecondaryBridge(t, pod.nodeName)
		require.NoError(t, err, "Failed to get Secondary bridge OVS Ports before agent restart")
		beforeAgentRestartOvsPorts[pod.nodeName] = ports

		ipv4s, ipv6s, _, err := data.listPodAddresses(pod)
		require.NoError(t, err, "Failed to get Pod IP before agent restart")
		beforeAgentRestartIPv4s[pod.podName] = ipv4s
		beforeAgentRestartIPv6s[pod.podName] = ipv6s
	}

	require.NoError(t, data.e2eTestData.RestartAntreaAgentPods(30*time.Second), "Failed to restart Antrea agent Pods")

	afterAgentRestartOvsPorts := make(map[string][]string)
	afterAgentRestartIPv4s := make(map[string]map[string]net.IP)
	afterAgentRestartIPv6s := make(map[string]map[string]net.IP)
	for _, pod := range data.pods {
		ports, err := data.getOVSPortsOnSecondaryBridge(t, pod.nodeName)
		require.NoError(t, err, "Failed to get Secondary bridge OVS Ports after agent restart")
		afterAgentRestartOvsPorts[pod.nodeName] = ports

		ipv4s, ipv6s, _, err := data.listPodAddresses(pod)
		require.NoError(t, err, "Failed to get Pod IP after agent restart")
		afterAgentRestartIPv4s[pod.podName] = ipv4s
		afterAgentRestartIPv6s[pod.podName] = ipv6s
	}

	for nodeName, portsBefore := range beforeAgentRestartOvsPorts {
		assert.ElementsMatch(t, portsBefore, afterAgentRestartOvsPorts[nodeName],
			"Secondary bridge OVS Ports mismatch after agent restart on node %s", nodeName)
	}

	for podName, ipv4sBefore := range beforeAgentRestartIPv4s {
		assert.Equal(t, ipv4sBefore, afterAgentRestartIPv4s[podName],
			"Pod: %s, IPv4 addresses mismatch after agent restart", podName)
	}
	for podName, ipv6sBefore := range beforeAgentRestartIPv6s {
		assert.Equal(t, ipv6sBefore, afterAgentRestartIPv6s[podName],
			"Pod: %s, IPv6 addresses mismatch after agent restart", podName)
	}

	vlanPod := data.pods[1]
	ifaces := []string{"eth1", "eth2"}
	ifacesIPv4, ifacesIPv6, _, err := data.listPodAddresses(vlanPod)
	require.NoError(t, err, "Failed to get IPs of Interfaces")

	beforeDeletionOvsPorts, err := data.getOVSPortsOnSecondaryBridge(t, vlanPod.nodeName)
	require.NoError(t, err, "Failed to get OVS Ports Before Pod deletion")

	ipPools, err := data.getIPPoolNames(ifaces, vlanPod, ipPoolNamespace)
	require.NoError(t, err, "Failed to get IPPool")

	require.NoError(t, data.e2eTestData.DeletePodAndWait(defaultTimeout, vlanPod.podName, data.e2eTestData.GetTestNamespace()), "Failed to delete Pod")

	afterDeletionOvsPorts, err := data.getOVSPortsOnSecondaryBridge(t, vlanPod.nodeName)
	require.NoError(t, err, "Failed to get OVS Ports After Pod deletion")

	assert.NotEqual(t, beforeDeletionOvsPorts, afterDeletionOvsPorts, "OVS Ports for VLAN Pod still exist")

	return data.checkIPReleased(ipPools, ifacesIPv4, ifacesIPv6, ifaces)
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
		t.Fatalf("Error when creating test Pods: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(e2eTestData.KubeConfig)
	if err != nil {
		t.Fatalf("Error when creating kubernetes client: %v", err)
	}

	t.Run("IPv4Connectivity", func(t *testing.T) {
		antreae2e.SkipIfNotIPv4Cluster(t)
		if err := testData.verifySecondaryInterfaces(t, ipFamilyIPv4); err != nil {
			t.Fatalf("Error verifying IPv4 secondary interfaces: %v", err)
		}
	})

	t.Run("IPv6Connectivity", func(t *testing.T) {
		antreae2e.SkipIfNotIPv6Cluster(t)
		if err := testData.verifySecondaryInterfaces(t, ipFamilyIPv6); err != nil {
			t.Fatalf("Error verifying IPv6 secondary interfaces: %v", err)
		}
	})

	t.Run("NetworkStatus", func(t *testing.T) {
		if err := testData.assertPodNetworkStatus(t, clientset, pods, ns, networkType == networkTypeSriov); err != nil {
			t.Fatalf("Error when checking the Pod annotation: %v", err)
		}
	})

	t.Run("ReconciliationAfterAgentRestart", func(t *testing.T) {
		err := testData.reconcilationAfterAgentRestart(t)
		require.NoError(t, err, "IP release check failed after agent restart")
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
			macAddresses:      map[string]string{"eth1": "aa:bb:cc:dd:ee:01", "eth2": "aa:bb:cc:dd:ee:02"},
		},
		{
			podName:           "vlan-pod2",
			nodeName:          node1,
			interfaceNetworks: map[string]string{"eth1": "vlan-net1", "eth2": "vlan-net3"},
			macAddresses:      map[string]string{"eth1": "aa:bb:cc:dd:ee:03", "eth2": "aa:bb:cc:dd:ee:04"},
		},
		{
			podName:           "vlan-pod3",
			nodeName:          node2,
			interfaceNetworks: map[string]string{"eth1": "vlan-net2"},
			macAddresses:      map[string]string{"eth1": "aa:bb:cc:dd:ee:05"},
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
	antreae2e.SkipIfNotIPv4Cluster(t)
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
	require.NotEmpty(t, vfName, "VF interface name should not be empty")
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
	if err := testData.verifySecondaryInterfaces(t, ipFamilyIPv4); err != nil {
		t.Fatalf("Error verifying secondary interfaces (configuration and connectivity): %v", err)
	}
	if err := testData.assertPodNetworkStatus(t, clientset, pods, ns, true); err != nil {
		t.Fatalf("Error when checking the Pod annotation: %v", err)
	}
	// Delete the Pod secondary network annotation
	if err := testData.deletePodNetworkAttachmentAnnot(t, pods, e2eTestData.GetTestNamespace()); err != nil {
		t.Fatalf("Error when updating the annotation of Pod: %v", err)
	}
	// Check the Pod network status annotation
	if err := testData.assertPodNetworkStatus(t, clientset, pods, e2eTestData.GetTestNamespace(), true); err != nil {
		t.Fatalf("Error when checking the Pod NetworkStatus annotation: %v", err)
	}

	// Update the Pod secondary network annotation
	if err := testData.updatePodNetworkAttachmentAnnot(t, pods, e2eTestData.GetTestNamespace()); err != nil {
		t.Fatalf("Error when updating the annotation of Pod: %v", err)
	}
	// Check the Pod network status annotation
	if err := testData.assertPodNetworkStatus(t, clientset, pods, e2eTestData.GetTestNamespace(), true); err != nil {
		t.Fatalf("Error when checking the Pod networkstatus annotation: %v", err)
	}
	//  Delete a Pod and check the VF device is recovered with the original interface name.
	err = e2eTestData.DeletePodAndWait(10*time.Second, pod1, ns)
	require.NoError(t, err, "Unable to delete the Pod %s/%s in time", ns, pod1)
	testData.assertVFName(t, e2eTestData, vfName, node1)
}

func (data *testData) assertVFName(t *testing.T, e2eTestData *antreae2e.TestData, vfName, nodeName string) {
	recoveredVFName := GetVFInterfaceName(t, e2eTestData, nodeName)
	logs.Infof("The recovered VF interface name is %s on Node %s", recoveredVFName, nodeName)
	assert.Equal(t, vfName, recoveredVFName, "VF name is not recovered correctly on Node %s, the expected VF name is %s, but got %s", nodeName, vfName, recoveredVFName)
}

func GetVFInterfaceName(t *testing.T, e2eTestData *antreae2e.TestData, nodeName string) string {
	cmd := []string{"ip", "-d", "link", "show"}
	stdOut, _, err := e2eTestData.RunCommandFromAntreaPodOnNode(nodeName, cmd)
	if err != nil {
		require.NoError(t, err, fmt.Sprintf("Error when checking the VF interface name on the Node %s", nodeName))
	}
	var prevLine string
	for line := range strings.Lines(string(stdOut)) {
		if strings.Contains(line, "0000:00:04.0") {
			parts := strings.SplitN(prevLine, ": ", 2)
			if len(parts) >= 2 {
				ifaceName := strings.TrimSpace(parts[1])
				if i := strings.IndexByte(ifaceName, ':'); i != -1 {
					ifaceName = ifaceName[:i]
				}
				return ifaceName
			}
		}
		prevLine = line
	}
	return ""
}

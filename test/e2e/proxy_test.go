// Copyright 2020 Antrea Authors
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
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/features"
)

type expectTableFlows struct {
	tableID int
	flows   []string
}

func skipIfProxyDisabled(t *testing.T, data *TestData) {
	if featureGate, err := data.GetAgentFeatures(antreaNamespace); err != nil {
		t.Fatalf("Error when detecting proxy: %v", err)
	} else if !featureGate.Enabled(features.AntreaProxy) {
		t.Skip("Skipping test because AntreaProxy is not enabled")
	}
}

func TestProxyNodePortService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)
	skipIfNumNodesLessThan(t, 2)

	nodeName := nodeName(1)
	require.NoError(t, data.createNginxPod("nginx", nodeName))
	_, err = data.podWaitForIPs(defaultTimeout, "nginx", testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "nginx", testNamespace))
	ipProctol := corev1.IPv4Protocol
	svc, err := data.createNginxNodePortService(true, &ipProctol)
	require.NoError(t, err)
	require.NoError(t, data.createBusyboxPodOnNode("busybox", nodeName))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "busybox", testNamespace))
	var nodePort string
	for _, port := range svc.Spec.Ports {
		if port.NodePort != 0 {
			nodePort = fmt.Sprint(port.NodePort)
			break
		}
	}
	busyboxPod, err := data.podWaitFor(defaultTimeout, "busybox", testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busyboxPod.Status)
	_, _, err = data.runCommandFromPod(testNamespace, "busybox", busyboxContainerName, []string{"wget", "-O", "-", net.JoinHostPort(busyboxPod.Status.HostIP, nodePort), "-T", "1"})
	require.NoError(t, err, "Service NodePort should be able to be connected from Pod")
	_, _, _, err = RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", net.JoinHostPort(busyboxPod.Status.HostIP, nodePort), "-T", "1"}, " "))
	require.NoError(t, err, "Service NodePort should be able to be connected from Node IP address on Node which does not have Endpoint")
	_, _, _, err = RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", net.JoinHostPort("127.0.0.1", nodePort), "-T", "1"}, " "))
	require.NoError(t, err, "Service NodePort should be able to be connected from loopback address on Node which does not have Endpoint")
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.253", "169.254.169.254"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceSessionAffinity(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := "nginx"
	require.NoError(t, data.createNginxPod(nginx, nodeName))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService("", true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)

	busyboxPod := "busybox"
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, nodeName))
	defer data.deletePodAndWait(defaultTimeout, busyboxPod)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyboxPod, testNamespace))
	stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", svc.Spec.ClusterIP, "-T", "1"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", ingressIP, "-T", "1"})
		require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	}

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	table40Output, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, "table=40"})
	require.NoError(t, err)
	if *ipFamily == corev1.IPv4Protocol {
		require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIP.ipv4.To4()), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[8:16]), "0")))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[0:8]), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	}
}

func TestProxyHairpin(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
}

func testProxyHairpin(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	busybox := "busybox"
	nodeName := nodeName(1)
	err := data.createPodOnNode(busybox, nodeName, busyboxImage, []string{"nc", "-lk", "-p", "80"}, nil, nil, []corev1.ContainerPort{{ContainerPort: 80, Protocol: corev1.ProtocolTCP}}, false, nil)
	defer data.deletePodAndWait(defaultTimeout, busybox)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busybox, testNamespace))
	svc, err := data.createService(busybox, 80, 80, map[string]string{"antrea-e2e": "busybox"}, false, corev1.ServiceTypeClusterIP, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, busybox)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	stdout, stderr, err := data.runCommandFromPod(testNamespace, busybox, busyboxContainerName, []string{"nc", svc.Spec.ClusterIP, "80", "-w", "1", "-e", "ls", "/"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
}

func TestProxyEndpointLifeCycle(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
}

func testProxyEndpointLifeCycle(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := "nginx"
	require.NoError(t, data.createNginxPod(nginx, nodeName))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService("", false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}

	keywords := make(map[int]string)
	keywords[42] = fmt.Sprintf("nat(dst=%s)", net.JoinHostPort(nginxIP, "80")) // endpointNATTable

	var groupKeywords []string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeywords = append(groupKeywords, fmt.Sprintf("set_field:0x%s->xxreg3", strings.TrimPrefix(hex.EncodeToString(*nginxIPs.ipv6), "0")))
	} else {
		groupKeywords = append(groupKeywords, fmt.Sprintf("0x%s->NXM_NX_REG3[]", strings.TrimPrefix(hex.EncodeToString(nginxIPs.ipv4.To4()), "0")))
	}

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.Contains(t, tableOutput, keyword)
	}

	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.Contains(t, groupOutput, k)
	}

	require.NoError(t, data.deletePodAndWait(defaultTimeout, nginx))

	// Wait for one second to make sure the pipeline to be updated.
	time.Sleep(time.Second)

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.NotContains(t, tableOutput, keyword)
	}

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.NotContains(t, groupOutput, k)
	}
}

func TestProxyServiceLifeCycle(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.253", "169.254.169.254"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceLifeCycle(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := "nginx"
	require.NoError(t, data.createNginxPod(nginx, nodeName))
	defer data.deletePodAndWait(defaultTimeout, nginx)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}
	svc, err := data.createNginxClusterIPService("", false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(false, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	svcLBflows := make([]string, len(ingressIPs)+1)
	if *ipFamily == corev1.IPv6Protocol {
		svcLBflows[0] = fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP)
		for idx, ingressIP := range ingressIPs {
			svcLBflows[idx+1] = fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP)
		}
	} else {
		svcLBflows[0] = fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP)
		for idx, ingressIP := range ingressIPs {
			svcLBflows[idx+1] = fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP)
		}
	}

	table42Format := "nat(dst=%s:80)"
	if *ipFamily == corev1.IPv6Protocol {
		table42Format = "nat(dst=[%s]:80)"
	}
	expectedFlows := []expectTableFlows{
		{
			41, // serviceLBTable
			svcLBflows,
		},
		{
			42,
			[]string{fmt.Sprintf(table42Format, nginxIP)}, // endpointNATTable
		},
	}

	var groupKeyword string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeyword = fmt.Sprintf("set_field:0x%s->xxreg3,load:0x%x->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv6.To16()), "0"), 80)
	} else {
		groupKeyword = fmt.Sprintf("load:0x%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv4.To4()), "0"), 80)
	}
	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.Contains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.Contains(t, tableOutput, expectedFlow)
		}
	}

	require.NoError(t, data.deleteService(nginx))
	require.NoError(t, data.deleteService(nginxLBService))

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.NotContains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.NotContains(t, tableOutput, expectedFlow)
		}
	}
}

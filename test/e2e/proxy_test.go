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

func TestProxyServiceSessionAffinity(t *testing.T) {
	// TODO: add check for IPv6 address after Antrea Proxy supports IPv6
	skipIfIPv6Cluster(t)
	skipIfNotIPv4Cluster(t)
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	nodeName := nodeName(1)
	require.NoError(t, data.createNginxPod("nginx", nodeName))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, "nginx", testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "nginx", testNamespace))
	svc, err := data.createNginxClusterIPService(true)
	require.NoError(t, err)
	ingressIPs := []string{"169.254.1.253", "169.254.1.254"}
	_, err = data.createNginxLoadBalancerService(true, ingressIPs)
	require.NoError(t, err)
	require.NoError(t, data.createBusyboxPodOnNode("busybox", nodeName))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "busybox", testNamespace))
	stdout, stderr, err := data.runCommandFromPod(testNamespace, "busybox", busyboxContainerName, []string{"wget", "-O", "-", svc.Spec.ClusterIP, "-T", "1"})
	require.NoError(t, err, fmt.Sprintf("stdout: %s\n, stderr: %s", stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runCommandFromPod(testNamespace, "busybox", busyboxContainerName, []string{"wget", "-O", "-", ingressIP, "-T", "1"})
		require.NoError(t, err, fmt.Sprintf("stdout: %s\n, stderr: %s", stdout, stderr))
	}

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	table40Output, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, "table=40"})
	require.NoError(t, err)
	require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
	// TODO: add check for IPv6 address after Antrea Proxy is supported with IPv6
	require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIP.ipv4.To4()), "0")))
	for _, ingressIP := range ingressIPs {
		require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
	}
}

func TestProxyHairpin(t *testing.T) {
	// TODO: add check for IPv6 address after Antrea Proxy supports IPv6
	skipIfIPv6Cluster(t)
	skipIfNotIPv4Cluster(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	nodeName := nodeName(1)
	err = data.createPodOnNode("busybox", nodeName, busyboxImage, []string{"nc", "-lk", "-p", "80"}, nil, nil, []corev1.ContainerPort{{ContainerPort: 80, Protocol: corev1.ProtocolTCP}}, false, nil)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, "busybox", testNamespace))
	svc, err := data.createService("busybox", 80, 80, map[string]string{"antrea-e2e": "busybox"}, false, corev1.ServiceTypeClusterIP)
	require.NoError(t, err)
	stdout, stderr, err := data.runCommandFromPod(testNamespace, "busybox", busyboxContainerName, []string{"nc", svc.Spec.ClusterIP, "80", "-w", "1", "-e", "ls", "/"})
	require.NoError(t, err, fmt.Sprintf("stdout: %s\n, stderr: %s", stdout, stderr))
}

func TestProxyEndpointLifeCycle(t *testing.T) {
	// TODO: add check for IPv6 address after Antrea Proxy supports IPv6
	skipIfIPv6Cluster(t)
	skipIfNotIPv4Cluster(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	nodeName := nodeName(1)
	require.NoError(t, data.createNginxPod("nginx", nodeName))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, "nginx", testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService(false)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	// TODO: Add support for IPv6 address after Antrea Proxy in IPv6 is supported
	nginxIP := nginxIPs.ipv4.String()

	keywords := map[int]string{
		42: fmt.Sprintf("nat(dst=%s:80)", nginxIP), // endpointNATTable
	}

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.Contains(t, tableOutput, keyword)
	}

	require.NoError(t, data.deletePodAndWait(defaultTimeout, "nginx"))

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.NotContains(t, tableOutput, keyword)
	}
}

func TestProxyServiceLifeCycle(t *testing.T) {
	// TODO: add check for IPv6 address after Antrea Proxy supports IPv6
	skipIfIPv6Cluster(t)
	skipIfNotIPv4Cluster(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

	nodeName := nodeName(1)
	require.NoError(t, data.createNginxPod("nginx", nodeName))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, "nginx", testNamespace)
	require.NoError(t, err)
	// TODO: Add support for IPv6 address after Antrea Proxy in IPv6 is supported
	nginxIP := nginxIPs.ipv4.String()
	svc, err := data.createNginxClusterIPService(false)
	require.NoError(t, err)
	ingressIPs := []string{"169.254.1.253", "169.254.1.254"}
	_, err = data.createNginxLoadBalancerService(false, ingressIPs)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	svcLBflows := make([]string, len(ingressIPs)+1)
	svcLBflows[0] = fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP)
	for idx, ingressIP := range ingressIPs {
		svcLBflows[idx+1] = fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP)
	}
	expectedFlows := []expectTableFlows{
		{
			41, // serviceLBTable
			svcLBflows,
		},
		{
			42,
			[]string{fmt.Sprintf("nat(dst=%s:80)", nginxIP)}, // endpointNATTable
		},
	}

	// TODO : add check for IPv6 address after Antrea Proxy is supported with IPv6
	groupKeyword := fmt.Sprintf("load:0x%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15],load:0x2->NXM_NX_REG4[16..18]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv4.To4()), "0"), 80)
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

	require.NoError(t, data.deleteService("nginx"))
	require.NoError(t, data.deleteService("nginx-loadbalancer"))
	time.Sleep(time.Second)

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

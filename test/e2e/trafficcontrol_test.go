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
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/features"
)

type trafficControlTestConfig struct {
	nodeName         string
	podName          string
	podIPs           map[corev1.IPFamily]string
	collectorPodName string
	collectorPodIPs  map[corev1.IPFamily]string
}

var (
	vni          = int32(1)
	dstVXLANPort = int32(1111)
	labels       = map[string]string{"tc-e2e": "agnhost"}

	tcTestConfig = trafficControlTestConfig{
		podName:          "test-tc-pod",
		podIPs:           map[corev1.IPFamily]string{},
		collectorPodName: "test-packets-collector-pod",
		collectorPodIPs:  map[corev1.IPFamily]string{},
	}
)

func TestTrafficControl(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfFeatureDisabled(t, features.TrafficControl, true, false)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	tcTestConfig.nodeName = controlPlaneNodeName()

	createTrafficControlTestPod(t, data, tcTestConfig.podName)
	createTrafficControlPacketsCollectorPod(t, data, tcTestConfig.collectorPodName)

	t.Run("TestMirrorToRemote", func(t *testing.T) { testMirrorToRemote(t, data) })
	t.Run("TestMirrorToLocal", func(t *testing.T) { testMirrorToLocal(t, data) })
	t.Run("TestRedirectToLocal", func(t *testing.T) { testRedirectToLocal(t, data) })
}

func createTrafficControlTestPod(t *testing.T, data *TestData, podName string) {
	args := []string{"netexec", "--http-port=8080"}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).OnNode(tcTestConfig.nodeName).WithArgs(args).WithPorts(ports).WithLabels(labels).Create(data))
	ips, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, data.testNamespace))

	if ips.IPv4 != nil {
		tcTestConfig.podIPs[corev1.IPv4Protocol] = ips.IPv4.String()
	}
	if ips.IPv6 != nil {
		tcTestConfig.podIPs[corev1.IPv6Protocol] = ips.IPv6.String()
	}
}

func createTrafficControlPacketsCollectorPod(t *testing.T, data *TestData, podName string) {
	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).OnNode(tcTestConfig.nodeName).WithCommand([]string{"sleep", "3600"}).Privileged().Create(data))
	ips, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, data.testNamespace))

	if ips.IPv4 != nil {
		tcTestConfig.collectorPodIPs[corev1.IPv4Protocol] = ips.IPv4.String()
	}
	if ips.IPv6 != nil {
		tcTestConfig.collectorPodIPs[corev1.IPv6Protocol] = ips.IPv6.String()
	}
}

func (data *TestData) createTrafficControl(t *testing.T,
	generateName string,
	matchExpressions []metav1.LabelSelectorRequirement,
	matchLabels map[string]string,
	direction v1alpha2.Direction,
	action v1alpha2.TrafficControlAction,
	targetPort interface{},
	isTargetPortVXLAN bool,
	returnPort interface{}) *v1alpha2.TrafficControl {
	tc := &v1alpha2.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1alpha2.TrafficControlSpec{
			AppliedTo: v1alpha2.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
			Direction:  direction,
			Action:     action,
			ReturnPort: &v1alpha2.TrafficControlPort{},
		},
	}
	switch targetPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.TargetPort.OVSInternal = targetPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.TargetPort.Device = targetPort.(*v1alpha2.NetworkDevice)
	case *v1alpha2.UDPTunnel:
		if isTargetPortVXLAN {
			tc.Spec.TargetPort.VXLAN = targetPort.(*v1alpha2.UDPTunnel)
		} else {
			tc.Spec.TargetPort.GENEVE = targetPort.(*v1alpha2.UDPTunnel)
		}
	case *v1alpha2.GRETunnel:
		tc.Spec.TargetPort.GRE = targetPort.(*v1alpha2.GRETunnel)
	case *v1alpha2.ERSPANTunnel:
		tc.Spec.TargetPort.ERSPAN = targetPort.(*v1alpha2.ERSPANTunnel)
	}

	switch returnPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.ReturnPort.OVSInternal = returnPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.ReturnPort.Device = returnPort.(*v1alpha2.NetworkDevice)
	default:
		tc.Spec.ReturnPort = nil
	}

	tc, err := data.crdClient.CrdV1alpha2().TrafficControls().Create(context.TODO(), tc, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create TrafficControl")
	return tc
}

func countPackets(t *testing.T, data *TestData, portName string, isPortOnNode bool, podName string, direction string) int {
	var stdout, stderr string
	var err error
	cmd := fmt.Sprintf("ip -s link show %s", portName)
	if !isPortOnNode {
		stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, podName, agnhostContainerName, []string{"sh", "-c", cmd})
	} else {
		_, stdout, stderr, err = data.RunCommandOnNode(tcTestConfig.nodeName, cmd)
	}
	require.NoError(t, err)
	require.Equal(t, "", stderr)

	re := regexp.MustCompile(fmt.Sprintf(`(?s)%s.*?\d+.*?(\d+)`, direction))
	matches := re.FindStringSubmatch(stdout)
	require.Equal(t, 2, len(matches))
	packets, _ := strconv.Atoi(matches[1])

	return packets
}

func abs(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

func verifyMirroredPackets(t *testing.T, data *TestData, portName string, isPortOnNode bool) {
	// Get the number of received packets on the interface for receiving mirrored packets before testing mirroring.
	receivedPacketsBefore := countPackets(t, data, portName, isPortOnNode, tcTestConfig.collectorPodName, "RX")

	icmpRequests := 100
	for _, ip := range tcTestConfig.podIPs {
		cmd := fmt.Sprintf("ping %s -i 0.01 -c %d", ip, icmpRequests)
		t.Logf("Generate packets for mirroring with command '%s'", cmd)
		data.RunCommandFromPod(data.testNamespace, tcTestConfig.collectorPodName, agnhostContainerName, []string{"sh", "-c", cmd})
	}

	mirroredPackets := icmpRequests * 2 * len(tcTestConfig.podIPs)
	t.Logf("The total number of mirrored packets is %d", mirroredPackets)

	// Get the number of received packets on the interface for receiving mirrored packet.
	receivedPackets := countPackets(t, data, portName, isPortOnNode, tcTestConfig.collectorPodName, "RX") - receivedPacketsBefore
	t.Logf("The actual number of received packets is %d", receivedPackets)

	// The difference in the number of packets mirrored and received should be within 10.
	require.GreaterOrEqual(t, 10, abs(receivedPackets, mirroredPackets))
}

func testMirrorToRemote(t *testing.T, data *TestData) {
	skipIfNotIPv4Cluster(t)

	// Create a VXLAN tunnel on the collector Pod to receive mirrored packets.
	tunnelPeer := "vxlan0"
	cmd := fmt.Sprintf(`ip link add %[3]s type vxlan id %[1]d dstport %[2]d dev eth0 && \
ip link set %[3]s up`, vni, dstVXLANPort, tunnelPeer)
	_, _, err := data.RunCommandFromPod(data.testNamespace, tcTestConfig.collectorPodName, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err, "Failed to create VXLAN tunnel")

	// Create a TrafficControl whose target port is VXLAN.
	targetPort := &v1alpha2.UDPTunnel{RemoteIP: tcTestConfig.collectorPodIPs[corev1.IPv4Protocol], VNI: &vni, DestinationPort: &dstVXLANPort}

	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, targetPort, true, nil)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})
	// Wait flows of the TrafficControl to be realized.
	time.Sleep(time.Second)

	// Verify the number of mirrored packets.
	verifyMirroredPackets(t, data, tunnelPeer, false)
}

func testMirrorToLocal(t *testing.T, data *TestData) {
	// Create a TrafficControl whose target port is OVS internal port.
	portName := "test-port"
	targetPort := &v1alpha2.OVSInternalPort{Name: portName}
	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, targetPort, false, nil)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})
	// Wait flows of the TrafficControl to be realized.
	time.Sleep(time.Second)

	// Verify the number of mirrored packets.
	verifyMirroredPackets(t, data, portName, true)
}

func verifyRedirectedPackets(t *testing.T, data *TestData, targetPort, returnPort string) {
	// Get the number of received and sent packets on test Pod before testing redirect.
	packetsBefore := countPackets(t, data, "eth0", false, tcTestConfig.podName, "RX") +
		countPackets(t, data, "eth0", false, tcTestConfig.podName, "TX")
	// Get the number of received packets on target port before testing redirect. Note that, received packets on veth pair
	// are counted as TX.
	packetsOnTargetPortBefore := countPackets(t, data, targetPort, true, "", "TX")
	// Get the number of sent packets on return port before testing redirect. Note that, sent packets on veth pair are
	// counted as RX.
	packetsOnReturnPortBefore := countPackets(t, data, returnPort, true, "", "RX")

	for _, ip := range tcTestConfig.podIPs {
		cmd := fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused http://%s/hostname", net.JoinHostPort(ip, "8080"))
		t.Logf("Generate packets for redirecting with command '%s'", cmd)
		for i := 0; i < 10; i++ {
			hostname, _, err := data.RunCommandFromPod(data.testNamespace, tcTestConfig.collectorPodName, agnhostContainerName, []string{"sh", "-c", cmd})
			require.NoError(t, err)
			require.Equal(t, tcTestConfig.podName, hostname)
		}
	}

	// Get the number of redirected packets on test Pod.
	packetsOnPod := countPackets(t, data, "eth0", false, tcTestConfig.podName, "RX") +
		countPackets(t, data, "eth0", false, tcTestConfig.podName, "TX") - packetsBefore
	t.Logf("The total number of redirected packets on test Pod is %d", packetsOnPod)

	// Get the number of received packets on target port after testing redirect.
	packetsOnTargetPort := countPackets(t, data, targetPort, true, "", "TX") - packetsOnTargetPortBefore
	t.Logf("The actual number of received packets on target port is %d", packetsOnTargetPort)

	// Get the number of sent packets on return port after testing redirect.
	packetsOnReturnPort := countPackets(t, data, returnPort, true, "", "RX") - packetsOnReturnPortBefore
	t.Logf("The actual number of sent packets on return port is %d", packetsOnReturnPort)

	// The difference in the number of packets redirected and received should be within 10.
	require.GreaterOrEqual(t, 10, abs(packetsOnTargetPort, packetsOnPod))
	require.GreaterOrEqual(t, 10, abs(packetsOnReturnPort, packetsOnPod))
	require.GreaterOrEqual(t, 10, abs(packetsOnTargetPort, packetsOnReturnPort))
}

func testRedirectToLocal(t *testing.T, data *TestData) {
	targetPortName := "target1"
	returnPortName := "return1"
	tempPodName := "pod-to-create-veth-pair"
	cmd := fmt.Sprintf(`ip link del dev %[1]s ; \
ip link add dev %[1]s type veth peer name %[2]s && \
ip link set dev %[1]s up && \
ip link set dev %[2]s up`, targetPortName, returnPortName)
	if err := NewPodBuilder(tempPodName, data.testNamespace, agnhostImage).OnNode(tcTestConfig.nodeName).WithCommand([]string{"sleep", "3600"}).InHostNetwork().Privileged().Create(data); err != nil {
		t.Fatalf("Failed to create Pod %s: %v", tempPodName, err)
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, tempPodName, data.testNamespace))
	_, _, err := data.RunCommandFromPod(data.testNamespace, tempPodName, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err)
	defer data.RunCommandFromPod(data.testNamespace, tempPodName, agnhostContainerName, []string{"sh", "-c", fmt.Sprintf("ip link del dev %s", targetPortName)})

	targetPort := &v1alpha2.NetworkDevice{Name: targetPortName}
	returnPort := &v1alpha2.NetworkDevice{Name: returnPortName}

	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionRedirect, targetPort, false, returnPort)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})
	// Wait flows of TrafficControl to be realized.
	time.Sleep(time.Second)

	// Verify the number of redirected packets.
	verifyRedirectedPackets(t, data, targetPortName, returnPortName)
}

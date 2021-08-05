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
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
)

const (
	IntraNode           connType = "IntraNode"
	InterNode           connType = "InterNode"
	roundNum                     = 3
	netperfControlPort           = 12865
	netperfDataPort1             = 10000
	netperfDataPort2             = 10001
	netperfDataPort3             = 10002
	iperfImage                   = "networkstatic/iperf3"
	netperfImage                 = "sirot/netperf-latest"
	heyImage                     = "ricoli/hey"
	iperfLocalClient             = "iperf-local-client"
	iperfLocalServer             = "iperf-local-server"
	iperfRemoteServer            = "iperf-remote-server"
	netperfLocalClient           = "netperf-local-client"
	netperfLocalServer           = "netperf-local-server"
	netperfRemoteServer          = "netperf-remote-server"
	nginxLocalClient             = "nginx-local-client"
	nginxLocalServer             = "nginx-local-server"
	nginxRemoteServer            = "nginx-remote-server"
)

type connType string

func TestIperfBenchmark(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	ipFamily := v1.IPv4Protocol
	localSvc, err := data.createMultiPortService(iperfLocalServer, map[int32]int32{iperfPort: iperfPort},
		map[string]string{"antrea-e2e": iperfLocalServer}, false, v1.ServiceTypeClusterIP, &ipFamily, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP})
	if err != nil {
		t.Fatalf("Error when creating iperf-local-server service: %v", err)
	}
	remoteSvc, err := data.createMultiPortService(iperfRemoteServer, map[int32]int32{iperfPort: iperfPort},
		map[string]string{"antrea-e2e": iperfRemoteServer}, false, v1.ServiceTypeClusterIP, &ipFamily, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP})
	if err != nil {
		t.Fatalf("Error when creating iperf-remote-server service: %v", err)
	}

	iperfCmd := []string{"iperf3", "-s"}
	if err := data.createPodOnNode(iperfLocalClient, testNamespace, controlPlaneNodeName(), iperfImage, iperfCmd, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the iperf client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, iperfLocalClient, testNamespace); err != nil {
		t.Fatalf("Error when waiting for the iperf client Pod: %v", err)
	}
	if err := data.createPodOnNode(iperfLocalServer, testNamespace, controlPlaneNodeName(), iperfImage, iperfCmd, nil, nil, []v1.ContainerPort{
		{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort},
		{Protocol: v1.ProtocolUDP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Fatalf("Error when creating the iperf local server Pod: %v", err)
	}
	localSvrIPs, err := data.podWaitForIPs(defaultTimeout, iperfLocalServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the iperf local server Pod: %v", err)
	}
	if err := data.createPodOnNode(iperfRemoteServer, testNamespace, workerNodeName(1), iperfImage, iperfCmd, nil, nil, []v1.ContainerPort{
		{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort},
		{Protocol: v1.ProtocolUDP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Fatalf("Error when creating the iperf remote server Pod: %v", err)
	}
	remoteSvrIPs, err := data.podWaitForIPs(defaultTimeout, iperfRemoteServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the iperf remote server Pod: %v", err)
	}

	t.Run("testIperfIntraNode", func(t *testing.T) { testIperf(t, data, localSvrIPs, localSvc, IntraNode) })
	t.Run("testIperfInterNode", func(t *testing.T) { testIperf(t, data, remoteSvrIPs, remoteSvc, InterNode) })
}

func TestNetperfBenchmark(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	ipFamily := v1.IPv4Protocol
	netperfPorts := map[int32]int32{
		netperfControlPort: netperfControlPort,
		netperfDataPort1:   netperfDataPort1,
		netperfDataPort2:   netperfDataPort2,
		netperfDataPort3:   netperfDataPort3,
	}
	localSvc, err := data.createMultiPortService(netperfLocalServer, netperfPorts, map[string]string{"antrea-e2e": netperfLocalServer},
		false, v1.ServiceTypeClusterIP, &ipFamily, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP})
	if err != nil {
		t.Fatalf("Error when creating netperf-local-server service: %v", err)
	}
	remoteSvc, err := data.createMultiPortService(netperfRemoteServer, netperfPorts, map[string]string{"antrea-e2e": netperfRemoteServer},
		false, v1.ServiceTypeClusterIP, &ipFamily, []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP})
	if err != nil {
		t.Fatalf("Error when creating netperf-remote-server service: %v", err)
	}

	netperfCmd := []string{"netserver", "-D"}
	if err := data.createPodOnNode(netperfLocalClient, testNamespace, controlPlaneNodeName(), netperfImage, netperfCmd, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the netperf client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, netperfLocalClient, testNamespace); err != nil {
		t.Fatalf("Error when waiting for the netperf client Pod: %v", err)
	}
	if err := data.createPodOnNode(netperfLocalServer, testNamespace, controlPlaneNodeName(), netperfImage, netperfCmd, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the netperf local server Pod: %v", err)
	}
	localSvrIPs, err := data.podWaitForIPs(defaultTimeout, netperfLocalServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the netperf local server Pod: %v", err)
	}
	if err := data.createPodOnNode(netperfRemoteServer, testNamespace, workerNodeName(1), netperfImage, netperfCmd, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the netperf remote server Pod: %v", err)
	}
	remoteSvrIPs, err := data.podWaitForIPs(defaultTimeout, netperfRemoteServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the netperf remote server Pod: %v", err)
	}

	t.Run("testNetperfTCPBandwidth, IntraNode", func(t *testing.T) { testNetperfTCPBandwidth(t, data, localSvrIPs, localSvc, IntraNode) })
	t.Run("testNetperfTCPBandwidth, InterNode", func(t *testing.T) { testNetperfTCPBandwidth(t, data, remoteSvrIPs, remoteSvc, InterNode) })
	t.Run("testNetperfTCPRR, IntraNode", func(t *testing.T) { testNetperfTCPRR(t, data, remoteSvrIPs, remoteSvc, IntraNode) })
	t.Run("testNetperfTCPRR, InterNode", func(t *testing.T) { testNetperfTCPRR(t, data, remoteSvrIPs, remoteSvc, InterNode) })
	t.Run("testNetperfTCPCRR, IntraNode", func(t *testing.T) { testNetperfTCPCRR(t, data, remoteSvrIPs, remoteSvc, IntraNode) })
	t.Run("testNetperfTCPCRR, InterNode", func(t *testing.T) { testNetperfTCPCRR(t, data, remoteSvrIPs, remoteSvc, InterNode) })
}

func TestNginxRPS(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	ipFamily := v1.IPv4Protocol

	localSvc, err := data.createService(nginxLocalServer, 80, 80, map[string]string{"antrea-e2e": nginxLocalServer},
		false, v1.ServiceTypeClusterIP, &ipFamily)
	if err != nil {
		t.Fatalf("Error when creating nginx-local-server service: %v", err)
	}
	remoteSvc, err := data.createService(nginxRemoteServer, 80, 80, map[string]string{"antrea-e2e": nginxRemoteServer},
		false, v1.ServiceTypeClusterIP, &ipFamily)
	if err != nil {
		t.Fatalf("Error when creating nginx-remote-server service: %v", err)
	}

	if err := data.createPodOnNode(nginxLocalClient, testNamespace, controlPlaneNodeName(), heyImage, []string{"sleep", "7d"}, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the nginx client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, nginxLocalClient, testNamespace); err != nil {
		t.Fatalf("Error when waiting for the nginx client Pod: %v", err)
	}
	if err := data.createPodOnNode(nginxLocalServer, testNamespace, controlPlaneNodeName(), nginxImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the nginx remote server Pod: %v", err)
	}
	localSvrIPs, err := data.podWaitForIPs(defaultTimeout, nginxLocalServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the nginx local server Pod: %v", err)
	}
	if err := data.createPodOnNode(nginxRemoteServer, testNamespace, workerNodeName(1), nginxImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the nginx remote server Pod: %v", err)
	}
	remoteSvrIPs, err := data.podWaitForIPs(defaultTimeout, nginxRemoteServer, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for the nginx remote server Pod: %v", err)
	}

	t.Run("testNginxRPS, IntraNode", func(t *testing.T) { testNginxRPS(t, data, localSvrIPs, localSvc, IntraNode) })
	t.Run("testNginxRPS, InterNode", func(t *testing.T) { testNginxRPS(t, data, remoteSvrIPs, remoteSvc, InterNode) })

}

func testIperf(t *testing.T, data *TestData, podIPs *PodIPs, svc *v1.Service, testType connType) {
	runIperf := func(cmd string) (bandwidth float64) {
		stdout, _, err := data.runCommandFromPod(testNamespace, iperfLocalClient, "iperf3", []string{"bash", "-c", cmd})
		if err != nil {
			t.Fatalf("Error when running iperf3 client: %v", err)
		}

		bandwidth, err = strconv.ParseFloat(strings.TrimSpace(stdout), 64)
		if err != nil {
			t.Errorf("Error parsing string to float64: %v", err)
		}
		return
	}

	cmd := fmt.Sprintf("iperf3 -u -b 0 -f m -w 256K -O 1 -c %s | grep receiver | awk '{print $7}'", podIPs.ipv4.String())
	var acc float64
	for i := 0; i < roundNum; i++ {
		acc += runIperf(cmd)
	}
	t.Logf("[%s] Pod to Pod UDP bandwidth: %.2f Mbits/sec", testType, acc/roundNum)

	cmd = fmt.Sprintf("iperf3 -u -b 0 -f m -w 256K -O 1 -c %s | grep receiver | awk '{print $7}'", svc.Spec.ClusterIP)
	acc = 0
	for i := 0; i < roundNum; i++ {
		acc += runIperf(cmd)
	}
	t.Logf("[%s] Pod to Svc UDP bandwidth: %.2f Mbits/sec", testType, acc/roundNum)
}

func runNetperf(t *testing.T, data *TestData, cmd string) (r float64) {
	stdout, _, err := data.runCommandFromPod(testNamespace, netperfLocalClient, "netperf-latest", []string{"bash", "-c", cmd})
	if err != nil {
		t.Fatalf("Error when running netperf client: %v", err)
	}
	r, err = strconv.ParseFloat(strings.TrimSpace(stdout), 64)
	if err != nil {
		t.Errorf("Error parsing string to float64: %v", err)
	}
	return
}

func testNetperfTCPBandwidth(t *testing.T, data *TestData, podIPs *PodIPs, svc *v1.Service, testType connType) {
	var (
		cmd string
		acc float64 = 0
	)
	for i := 10000; i <= 10002; i++ {
		cmd = fmt.Sprintf("netperf -H %s -t TCP_STREAM -P 0 -- -P %s|awk '{print $5}'", podIPs.ipv4.String(), strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Pod TCP bandwidth: %.2f Mbits/sec", testType, acc/roundNum)

	acc = 0
	for i := 10000; i <= 10002; i++ {
		cmd = fmt.Sprintf("netperf -H %s -t TCP_STREAM -P 0 -- -P %s|awk '{print $5}'", svc.Spec.ClusterIP, strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Svc TCP bandwidth: %.2f Mbits/sec", testType, acc/roundNum)
}

func testNetperfTCPRR(t *testing.T, data *TestData, podIPs *PodIPs, svc *v1.Service, testType connType) {
	var (
		cmd string
		acc float64 = 0
	)
	for i := 10000; i <= 10002; i++ {
		cmd = fmt.Sprintf("netperf -H %s -t TCP_RR -P 0 -- -P %s|awk '{print $6}'", podIPs.ipv4.String(), strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Pod TCP_RR: %.2f trans/sec", testType, acc/roundNum)

	acc = 0
	for i := 10000; i <= 10002; i++ {
		cmd = fmt.Sprintf("netperf -H %s -t TCP_RR -P 0 -- -P %s|awk '{print $6}'", svc.Spec.ClusterIP, strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Svc TCP_RR: %.2f trans/sec", testType, acc/roundNum)
}

func testNetperfTCPCRR(t *testing.T, data *TestData, podIPs *PodIPs, svc *v1.Service, testType connType) {
	var (
		cmd string
		acc float64 = 0
	)
	for i := 10000; i <= 10002; i++ {
		// Sleep 120s to wait for flush of conntrack table and ports
		t.Log("Sleeping 120 seconds")
		time.Sleep(2 * time.Minute)
		cmd = fmt.Sprintf("netperf -H %s -t TCP_CRR -P 0 -- -P %s|awk '{print $6}'", podIPs.ipv4.String(), strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Pod TCP_CRR: %.2f trans/sec", testType, acc/roundNum)

	acc = 0
	for i := 10000; i <= 10002; i++ {
		t.Log("Sleeping 120 seconds")
		time.Sleep(2 * time.Minute)
		cmd = fmt.Sprintf("netperf -H %s -t TCP_CRR -P 0 -- -P %s|awk '{print $6}'", svc.Spec.ClusterIP, strconv.Itoa(i))
		acc += runNetperf(t, data, cmd)
	}
	t.Logf("[%s] Pod to Svc TCP_CRR: %.2f trans/sec", testType, acc/roundNum)
}

func testNginxRPS(t *testing.T, data *TestData, podIPs *PodIPs, svc *v1.Service, testType connType) {
	runHey := func(cmd string) (rps float64) {
		stdout, _, err := data.runCommandFromPod(testNamespace, nginxLocalClient, "hey", []string{"sh", "-c", cmd})
		if err != nil {
			t.Fatalf("Error when running nginx client: %v", err)
		}
		rps, err = strconv.ParseFloat(strings.TrimSpace(stdout), 64)
		if err != nil {
			t.Errorf("Error parsing string to float64: %v", err)
		}
		return
	}

	var (
		cmd string
		acc float64 = 0
	)
	for i := 0; i < roundNum; i++ {
		// Sleep 120s to wait for flush of conntrack table and ports
		t.Log("Sleeping 120 seconds")
		time.Sleep(2 * time.Minute)
		cmd = fmt.Sprintf("hey -c 1 -n 5000 -disable-keepalive  http://%s  | grep Requests/sec: |awk '{print $2}'", podIPs.ipv4.String())
		acc += runHey(cmd)
	}
	t.Logf("[%s] Pod to Pod hey test: %.2f reqs/sec", testType, acc/roundNum)

	acc = 0
	for i := 10000; i <= 10002; i++ {
		t.Log("Sleeping 120 seconds")
		time.Sleep(2 * time.Minute)
		cmd = fmt.Sprintf("hey -c 1 -n 5000 -disable-keepalive  http://%s  | grep Requests/sec: |awk '{print $2}'", svc.Spec.ClusterIP)
		acc += runHey(cmd)
	}
	t.Logf("[%s] Pod to Svc hey test: %.2f reqs/sec", testType, acc/roundNum)
}

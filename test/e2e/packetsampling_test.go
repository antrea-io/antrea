// Copyright 2024 Antrea Authors.
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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

var (
	psNamespace      = "default"
	psSecretName     = "ps-secret"
	tcpServerPodName = "tcp-server"
	psToolboxPodName = "toolbox"
	udpServerPodName = "udp-server"
	nonExistPodName  = "non-existing-pod"
	dstServiceName   = "svc"
	dstServiceIP     = ""
)

type psTestCase struct {
	name           string
	ps             *crdv1alpha1.PacketSampling
	expectedPhase  crdv1alpha1.PacketSamplingPhase
	expectedReason string
	expectedNum    int32
	// required IP version, skip if not match, default is 0 (no restrict)
	ipVersion int
	// Source Pod to run ping for live-traffic PacketSampling.
	srcPod       string
	skipIfNeeded func(t *testing.T)
}

// TestPacketSampling is the top-level test which contains all subtests for
// PacketSampling related test cases so they can share setup, teardown.
func TestPacketSampling(t *testing.T) {

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var previousAgentPacketSamplingEnableState bool
	var previousControllerPacketSamplingEnableState bool

	ac := func(config *agentconfig.AgentConfig) {
		previousAgentPacketSamplingEnableState = config.FeatureGates[string(features.PacketSampling)]
		config.FeatureGates[string(features.PacketSampling)] = true
	}
	cc := func(config *controllerconfig.ControllerConfig) {
		previousControllerPacketSamplingEnableState = config.FeatureGates[string(features.PacketSampling)]
		config.FeatureGates[string(features.PacketSampling)] = true
	}
	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable PacketSampling flag: %v", err)
	}
	defer func() {
		ac := func(config *agentconfig.AgentConfig) {
			config.FeatureGates[string(features.PacketSampling)] = previousAgentPacketSamplingEnableState
		}
		cc := func(config *controllerconfig.ControllerConfig) {
			config.FeatureGates[string(features.PacketSampling)] = previousControllerPacketSamplingEnableState
		}
		if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
			t.Errorf("Failed to disable PacketSampling flag: %v", err)
		}
	}()

	// setup sftp server for test.
	sftpServiceYAML := "sftp-deployment.yml"
	secretUserName := "foo"
	secretPassword := "pass"

	applySFTPYamlCommand := fmt.Sprintf("kubectl apply -f %s -n %s", sftpServiceYAML, data.testNamespace)
	code, stdout, stderr, err := data.RunCommandOnNode(controlPlaneNodeName(), applySFTPYamlCommand)
	require.NoError(t, err)
	defer func() {
		deleteSFTPYamlCommand := fmt.Sprintf("kubectl delete -f %s -n %s", sftpServiceYAML, data.testNamespace)
		data.RunCommandOnNode(controlPlaneNodeName(), deleteSFTPYamlCommand)
	}()
	t.Logf("Stdout of the command '%s': %s", applySFTPYamlCommand, stdout)
	if code != 0 {
		t.Errorf("Error when applying %s: %v", sftpServiceYAML, stderr)
	}
	failOnError(data.waitForDeploymentReady(t, data.testNamespace, "sftp", defaultTimeout), t)

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: psSecretName,
		},
		Data: map[string][]byte{
			"username": []byte(secretUserName),
			"password": []byte(secretPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(psNamespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(psNamespace).Delete(context.TODO(), psSecretName, metav1.DeleteOptions{})

	t.Run("testPacketSamplingBasic", func(t *testing.T) {
		testPacketSamplingBasic(t, data)
	})
	t.Run("testPacketSampling", func(t *testing.T) {
		testPacketSampling(t, data)
	})
}

func testPacketSampling(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	err := data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(psToolboxPodName, data.testNamespace, node1, false)
	require.NoError(t, err)

	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, dstServiceName, data.testNamespace, node1, v1.ServiceTypeClusterIP)
	defer cleanup()
	t.Logf("%s Service is ready", dstServiceName)
	dstServiceIP = svc.Spec.ClusterIP

	podIPs := waitForPodIPs(t, data, []PodInfo{
		{tcpServerPodName, getOSString(), "", data.testNamespace},
		{psToolboxPodName, getOSString(), "", data.testNamespace},
	})

	// Give a little time for Windows containerd Nodes to setup OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	testcases := []psTestCase{
		{
			name:      "to-ipv4-ip",
			ipVersion: 4,
			srcPod:    psToolboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, psToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						IP: podIPs[tcpServerPodName].IPv4.String(),
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},

			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{
			name:      "to-svc",
			ipVersion: 4,
			srcPod:    psToolboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, psToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Service:   dstServiceName,
						Namespace: data.testNamespace,
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},

			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
	}
	t.Run("testPacketSampling", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketSamplingTest(t, data, tc)
			})
		}
	})

}

// testPacketSamplingTCP verifies if PacketSampling can capture tcp packets. this function only contains basic
// cases with pod-to-pod.
func testPacketSamplingBasic(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	node1Pods, _, _ := createTestAgnhostPods(t, data, 3, data.testNamespace, node1)
	err := data.createUDPServerPod(udpServerPodName, data.testNamespace, serverPodPort, node1)
	defer data.DeletePodAndWait(defaultTimeout, udpServerPodName, data.testNamespace)
	require.NoError(t, err)
	// test tcp server pod
	err = data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	defer data.DeletePodAndWait(defaultTimeout, tcpServerPodName, data.testNamespace)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(psToolboxPodName, data.testNamespace, node1, false)
	defer data.DeletePodAndWait(defaultTimeout, psToolboxPodName, data.testNamespace)
	require.NoError(t, err)

	// Give a little time for Windows containerd Nodes to setup OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	testcases := []psTestCase{
		{
			name:      "ipv4-tcp",
			ipVersion: 4,
			srcPod:    psToolboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, psToolboxPodName, data.testNamespace, tcpServerPodName)),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       tcpServerPodName,
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolTCP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv4-udp",
			ipVersion: 4,
			srcPod:    psToolboxPodName,
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, psToolboxPodName, data.testNamespace, udpServerPodName)),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       psToolboxPodName,
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       udpServerPodName,
					},

					Type:    crdv1alpha1.FirstNSampling,
					Timeout: 300,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolUDP,
						},
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
								DstPort: serverPodPort,
							},
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv4-icmp",
			ipVersion: 4,
			srcPod:    node1Pods[0],
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       node1Pods[1],
					},

					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPHeader: crdv1alpha1.IPHeader{
							Protocol: protocolICMP,
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{
			name:      "ipv6-icmp",
			ipVersion: 6,
			srcPod:    node1Pods[0],
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-ipv6", data.testNamespace, node1Pods[0], data.testNamespace, node1Pods[1])),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       node1Pods[1],
					},

					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
					Packet: crdv1alpha1.Packet{
						IPv6Header: &crdv1alpha1.IPv6Header{
							NextHeader: &protocolICMPv6,
						},
					},
				},
			},
			expectedPhase: crdv1alpha1.PacketSamplingSucceeded,
			expectedNum:   5,
		},
		{

			name:      "non-exist-pod",
			ipVersion: 4,
			srcPod:    node1Pods[0],
			ps: &crdv1alpha1.PacketSampling{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-to-%s-%s-", data.testNamespace, node1Pods[0], data.testNamespace, nonExistPodName)),
				},
				Spec: crdv1alpha1.PacketSamplingSpec{
					Source: crdv1alpha1.Source{
						Namespace: data.testNamespace,
						Pod:       node1Pods[0],
					},
					Destination: crdv1alpha1.Destination{
						Namespace: data.testNamespace,
						Pod:       nonExistPodName,
					},
					Type: crdv1alpha1.FirstNSampling,
					FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
						Number: 5,
					},
					FileServer: crdv1alpha1.BundleFileServer{
						URL: fmt.Sprintf("%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Authentication: crdv1alpha1.BundleServerAuthConfiguration{
						AuthType: "BasicAuthentication",
						AuthSecret: &v1.SecretReference{
							Name:      psSecretName,
							Namespace: psNamespace,
						},
					},
				},
			},
			expectedPhase:  crdv1alpha1.PacketSamplingFailed,
			expectedReason: fmt.Sprintf("Node: %s, error:failed to get the destination pod %s/%s: pods \"%s\" not found", node1, data.testNamespace, nonExistPodName, nonExistPodName),
		},
	}
	t.Run("testPacketSamplingBasic", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketSamplingTest(t, data, tc)
			})
		}
	})
}

func getOSString() string {
	if len(clusterInfo.windowsNodes) != 0 {
		return "windows"
	} else {
		return "linux"
	}
}

func runPacketSamplingTest(t *testing.T, data *TestData, tc psTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}
	if tc.skipIfNeeded != nil {
		tc.skipIfNeeded(t)
	}

	dstPodName := tc.ps.Spec.Destination.Pod
	var dstPodIPs *PodIPs
	if dstPodName != nonExistPodName && dstPodName != "" {
		// wait for pods to be ready first , or the ps will skip install flow
		podIPs := waitForPodIPs(t, data, []PodInfo{{dstPodName, getOSString(), "", data.testNamespace}})
		dstPodIPs = podIPs[dstPodName]
	}

	if _, err := data.crdClient.CrdV1alpha1().PacketSamplings().Create(context.TODO(), tc.ps, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketSampling: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().PacketSamplings().Delete(context.TODO(), tc.ps.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketSampling: %v", err)
		}
	}()

	if tc.ps.Spec.Destination.Pod != nonExistPodName {
		srcPod := tc.srcPod
		if dstIP := tc.ps.Spec.Destination.IP; dstIP != "" {
			ip := net.ParseIP(dstIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{IPv4: &ip}
			} else {
				dstPodIPs = &PodIPs{IPv6: &ip}
			}
		} else if tc.ps.Spec.Destination.Service != "" {
			ip := net.ParseIP(dstServiceIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{IPv4: &ip}
			} else {
				dstPodIPs = &PodIPs{IPv6: &ip}
			}
		}
		// Give a little time for Nodes to install OVS flows.
		time.Sleep(time.Second * 2)
		protocol := tc.ps.Spec.Packet.IPHeader.Protocol
		if tc.ps.Spec.Packet.IPv6Header != nil {
			protocol = *tc.ps.Spec.Packet.IPv6Header.NextHeader
		}
		server := dstPodIPs.IPv4.String()
		if tc.ipVersion == 6 {
			server = dstPodIPs.IPv6.String()
		}
		// Send an ICMP echo packet from the source Pod to the destination.
		if protocol == protocolICMP || protocol == protocolICMPv6 {
			if err := data.RunPingCommandFromTestPod(PodInfo{srcPod, getOSString(), "", data.testNamespace},
				data.testNamespace, dstPodIPs, agnhostContainerName, 10, 0, false); err != nil {
				t.Logf("Ping(%d) '%s' -> '%v' failed: ERROR (%v)", protocol, srcPod, *dstPodIPs, err)
			}
		} else if protocol == protocolTCP {
			for i := 1; i <= 5; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "tcp"); err != nil {
					t.Logf("Netcat(TCP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		} else if protocol == protocolUDP {
			for i := 1; i <= 5; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "udp"); err != nil {
					t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		}
	}

	ps, err := data.waitForPacketSampling(t, tc.ps.Name, tc.expectedPhase)
	if err != nil {
		t.Fatalf("Error: Get PacketSampling failed: %v", err)
	}
	if tc.expectedPhase == crdv1alpha1.PacketSamplingFailed {
		if ps.Status.Reason != tc.expectedReason {
			t.Fatalf("Error: PacketSampling Error Reason should be %v, but got %s", tc.expectedReason, ps.Status.Reason)
		}
	}
	if ps.Status.NumCapturedPackets != tc.expectedNum {
		t.Fatalf("Error: PacketSampling captured packets count should be %v, but got %v", tc.expectedNum, ps.Status.NumCapturedPackets)
	}

}

func (data *TestData) waitForPacketSampling(t *testing.T, name string, phase crdv1alpha1.PacketSamplingPhase) (*crdv1alpha1.PacketSampling, error) {
	var ps *crdv1alpha1.PacketSampling
	var err error
	timeout := 15 * time.Second
	if err = wait.PollImmediate(defaultInterval, timeout, func() (bool, error) {
		ps, err = data.crdClient.CrdV1alpha1().PacketSamplings().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || ps.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		if ps != nil {
			t.Errorf("Latest PacketSampling status: %s %v", ps.Name, ps.Status)
		}
		return nil, err
	}
	return ps, nil
}

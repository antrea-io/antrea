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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
)

var (
	pcSecretNamespace = "kube-system"
	// #nosec G101
	pcSecretName     = "antrea-packetcapture-fileserver-auth"
	tcpServerPodName = "tcp-server"
	pcToolboxPodName = "toolbox"
	udpServerPodName = "udp-server"
	nonExistPodName  = "non-existing-pod"

	tcpProto  = intstr.FromString("TCP")
	icmpProto = intstr.FromString("ICMP")
	udpProto  = intstr.FromString("UDP")

	testServerPort   int32 = 80
	testNonExistPort int32 = 8085

	pcTimeoutReason = "PacketCapture timeout"
	pcShortTimeout  = uint16(5)
)

type pcTestCase struct {
	name           string
	pc             *crdv1alpha1.PacketCapture
	expectedStatus crdv1alpha1.PacketCaptureStatus

	// required IP version, skip if not match.
	ipVersion int
	// Source Pod to run ping for live-traffic PacketCapture.
	srcPod string
}

func genSFTPService() *v1.Service {
	selector := map[string]string{"app": "sftp"}
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: selector,
		},
		Spec: v1.ServiceSpec{
			Type:     v1.ServiceTypeNodePort,
			Selector: selector,
			Ports: []v1.ServicePort{
				{
					Port:       22,
					TargetPort: intstr.FromInt32(22),
					NodePort:   30010,
				},
			},
		},
	}
}

func genSFTPDeployment() *appsv1.Deployment {
	replicas := int32(1)
	selector := map[string]string{"app": "sftp"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "sftp",
			Labels: selector,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: selector,
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "sftp",
					Labels: selector,
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:            "sftp",
							Image:           "antrea/sftp",
							ImagePullPolicy: v1.PullIfNotPresent,
							Args:            []string{"foo:pass:::upload"},
						},
					},
				},
			},
		},
	}
}

func createUDPServerPod(name string, ns string, portNum int32, serverNode string) error {
	port := v1.ContainerPort{Name: fmt.Sprintf("port-%d", portNum), ContainerPort: portNum}
	return NewPodBuilder(name, ns, agnhostImage).
		OnNode(serverNode).
		WithContainerName("agnhost").
		WithArgs([]string{"serve-hostname", "--udp", "--http=false", "--port", fmt.Sprint(portNum)}).
		WithPorts([]v1.ContainerPort{port}).
		Create(testData)
}

// TestPacketCapture is the top-level test which contains all subtests for
// PacketCapture related test cases, so they can share setup, teardown.
func TestPacketCapture(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	var previousAgentPacketCaptureEnableState bool
	ac := func(config *agentconfig.AgentConfig) {
		previousAgentPacketCaptureEnableState = config.FeatureGates[string(features.PacketCapture)]
		config.FeatureGates[string(features.PacketCapture)] = true
	}
	if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to enable PacketCapture flag: %v", err)
	}
	defer func() {
		ac := func(config *agentconfig.AgentConfig) {
			config.FeatureGates[string(features.PacketCapture)] = previousAgentPacketCaptureEnableState
		}
		if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
			t.Errorf("Failed to disable PacketCapture flag: %v", err)
		}
	}()

	// setup sftp server for test.
	secretUserName := "foo"
	secretPassword := "pass"
	_, err = data.clientset.AppsV1().Deployments(data.testNamespace).Create(context.TODO(), genSFTPDeployment(), metav1.CreateOptions{})
	require.NoError(t, err)
	_, err = data.clientset.CoreV1().Services(data.testNamespace).Create(context.TODO(), genSFTPService(), metav1.CreateOptions{})
	require.NoError(t, err)
	failOnError(data.waitForDeploymentReady(t, data.testNamespace, "sftp", defaultTimeout), t)

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pcSecretName,
			Namespace: pcSecretNamespace,
		},
		Data: map[string][]byte{
			"username": []byte(secretUserName),
			"password": []byte(secretPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(pcSecretNamespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(pcSecretNamespace).Delete(context.TODO(), pcSecretName, metav1.DeleteOptions{})

	t.Run("testPacketCaptureBasic", func(t *testing.T) {
		testPacketCaptureBasic(t, data)
	})
	t.Run("testPacketCapture", func(t *testing.T) {
		testPacketCapture(t, data)
	})

}

func testPacketCapture(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	err := data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(pcToolboxPodName, data.testNamespace, node1, false)
	require.NoError(t, err)

	podIPs := waitForPodIPs(t, data, []PodInfo{
		{tcpServerPodName, getOSString(), "", data.testNamespace},
		{pcToolboxPodName, getOSString(), "", data.testNamespace},
	})

	// Give a little time for Windows containerd Nodes to set up OVS.
	// Containerd configures port asynchronously, which could cause execution time of installing flow longer than docker.
	time.Sleep(time.Second * 1)

	tcpServerPodIP := podIPs[tcpServerPodName].IPv4.String()

	testcases := []pcTestCase{
		{
			name:      "timeout-case",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-timeout-case-", data.testNamespace)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Timeout: &pcShortTimeout,
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      pcToolboxPodName,
						},
					},
					Destination: crdv1alpha1.Destination{
						IP: &tcpServerPodIP,
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 500,
						},
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &tcpProto,
						IPFamily: v1.IPv4Protocol,
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: &testNonExistPort,
							},
						},
					},
				},
			},
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:               crdv1alpha1.PacketCaptureCompleted,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Timeout",
						Message:            "context deadline exceeded",
					},
				},
			},
		},
		{

			name:      nonExistPodName,
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-%s-", data.testNamespace, nonExistPodName)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      pcToolboxPodName,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      nonExistPodName,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
				},
			},

			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:               crdv1alpha1.PacketCaptureCompleted,
						Status:             metav1.ConditionStatus(v1.ConditionFalse),
						LastTransitionTime: metav1.Now(),
						Reason:             "CaptureFailed",
						Message:            fmt.Sprintf("failed to get Pod %s/%s: pods \"%s\" not found", data.testNamespace, nonExistPodName, nonExistPodName),
					},
				},
			},
		},
	}
	t.Run("testPacketCapture", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketCaptureTest(t, data, tc)
			})
		}
	})
}

// testPacketCaptureTCP verifies if PacketCapture can capture tcp packets. this function only contains basic
// cases with pod-to-pod.
func testPacketCaptureBasic(t *testing.T, data *TestData) {
	nodeIdx := 0
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIdx = clusterInfo.windowsNodes[0]
	}
	node1 := nodeName(nodeIdx)

	err := createUDPServerPod(udpServerPodName, data.testNamespace, serverPodPort, node1)
	defer data.DeletePodAndWait(defaultTimeout, udpServerPodName, data.testNamespace)
	require.NoError(t, err)
	// test tcp server pod
	err = data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil)
	defer data.DeletePodAndWait(defaultTimeout, tcpServerPodName, data.testNamespace)
	require.NoError(t, err)
	err = data.createToolboxPodOnNode(pcToolboxPodName, data.testNamespace, node1, false)
	defer data.DeletePodAndWait(defaultTimeout, pcToolboxPodName, data.testNamespace)
	require.NoError(t, err)

	testcases := []pcTestCase{
		{
			name:      "ipv4-tcp",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-ipv4-tcp-", data.testNamespace)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      pcToolboxPodName,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      tcpServerPodName,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &tcpProto,
						IPFamily: v1.IPv4Protocol,
						TransportHeader: crdv1alpha1.TransportHeader{
							TCP: &crdv1alpha1.TCPHeader{
								DstPort: &testServerPort,
							},
						},
					},
				},
			},
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:               crdv1alpha1.PacketCaptureCompleted,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
					{
						Type:               crdv1alpha1.PacketCaptureFileUploaded,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
				},
			},
		},
		{
			name:      "ipv4-udp",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-ipv4-udp-", data.testNamespace)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      pcToolboxPodName,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      udpServerPodName,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &udpProto,
						IPFamily: v1.IPv4Protocol,
						TransportHeader: crdv1alpha1.TransportHeader{
							UDP: &crdv1alpha1.UDPHeader{
								DstPort: &testServerPort,
							},
						},
					},
				},
			},
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:               crdv1alpha1.PacketCaptureCompleted,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
					{
						Type:               crdv1alpha1.PacketCaptureFileUploaded,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
				},
			},
		},
		{
			name:      "ipv4-icmp",
			ipVersion: 4,
			srcPod:    pcToolboxPodName,
			pc: &crdv1alpha1.PacketCapture{
				ObjectMeta: metav1.ObjectMeta{
					Name: randName(fmt.Sprintf("%s-ipv4-icmp-", data.testNamespace)),
				},
				Spec: crdv1alpha1.PacketCaptureSpec{
					Source: crdv1alpha1.Source{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      pcToolboxPodName,
						},
					},
					Destination: crdv1alpha1.Destination{
						Pod: &crdv1alpha1.PodReference{
							Namespace: data.testNamespace,
							Name:      tcpServerPodName,
						},
					},
					CaptureConfig: crdv1alpha1.CaptureConfig{
						FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
							Number: 5,
						},
					},
					FileServer: &crdv1alpha1.PacketCaptureFileServer{
						URL: fmt.Sprintf("sftp://%s:30010/upload", controlPlaneNodeIPv4()),
					},
					Packet: &crdv1alpha1.Packet{
						Protocol: &icmpProto,
						IPFamily: v1.IPv4Protocol,
					},
				},
			},
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:               crdv1alpha1.PacketCaptureCompleted,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
					{
						Type:               crdv1alpha1.PacketCaptureFileUploaded,
						Status:             metav1.ConditionStatus(v1.ConditionTrue),
						LastTransitionTime: metav1.Now(),
						Reason:             "Succeed",
					},
				},
			},
		},
	}
	t.Run("testPacketCaptureBasic", func(t *testing.T) {
		for _, tc := range testcases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				runPacketCaptureTest(t, data, tc)
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

func runPacketCaptureTest(t *testing.T, data *TestData, tc pcTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}
	// wait for toolbox
	waitForPodIPs(t, data, []PodInfo{{pcToolboxPodName, getOSString(), "", data.testNamespace}})

	dstPodName := ""
	if tc.pc.Spec.Destination.Pod != nil {
		dstPodName = tc.pc.Spec.Destination.Pod.Name
	}
	var dstPodIPs *PodIPs
	if dstPodName != nonExistPodName && dstPodName != "" {
		// wait for pods to be ready first
		podIPs := waitForPodIPs(t, data, []PodInfo{{dstPodName, getOSString(), "", data.testNamespace}})
		dstPodIPs = podIPs[dstPodName]
	}

	if _, err := data.crdClient.CrdV1alpha1().PacketCaptures().Create(context.TODO(), tc.pc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketCapture: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), tc.pc.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketCapture: %v", err)
		}
	}()

	if dstPodName != nonExistPodName && tc.expectedStatus.Conditions[0].Message != pcTimeoutReason {
		srcPod := tc.srcPod
		if dstIP := tc.pc.Spec.Destination.IP; dstIP != nil {
			ip := net.ParseIP(*dstIP)
			if ip.To4() != nil {
				dstPodIPs = &PodIPs{IPv4: &ip}
			} else {
				dstPodIPs = &PodIPs{IPv6: &ip}
			}
		}
		time.Sleep(time.Second * 2)
		protocol := *tc.pc.Spec.Packet.Protocol
		server := dstPodIPs.IPv4.String()
		if tc.ipVersion == 6 {
			server = dstPodIPs.IPv6.String()
		}
		// wait for CR running.

		_, err := data.waitForPacketCapture(t, tc.pc.Name, 0, isPacketCaptureRunning)
		if err != nil {
			t.Fatalf("Error: Waiting PacketCapture to Running failed: %v", err)
		}
		// Send an ICMP echo packet from the source Pod to the destination.
		if protocol == icmpProto {
			if err := data.RunPingCommandFromTestPod(PodInfo{srcPod, getOSString(), "", data.testNamespace},
				data.testNamespace, dstPodIPs, toolboxContainerName, 10, 0, false); err != nil {
				t.Logf("Ping(%s) '%s' -> '%v' failed: ERROR (%v)", protocol.StrVal, srcPod, *dstPodIPs, err)
			}
		} else if protocol == tcpProto {
			for i := 1; i <= 10; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "tcp"); err != nil {
					t.Logf("Netcat(TCP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		} else if protocol == udpProto {
			for i := 1; i <= 10; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(tc.srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "udp"); err != nil {
					t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		}
	}

	timeout := tc.pc.Spec.Timeout
	if timeout == nil {
		tv := uint16(15)
		timeout = &tv
	}

	if strings.Contains(tc.name, "timeout") {
		// wait more for status update.
		tv := *timeout + uint16(10)
		timeout = &tv
	}

	pc, err := data.waitForPacketCapture(t, tc.pc.Name, int(*timeout), isPacketCaptureReady)
	if err != nil {
		t.Fatalf("Error: Get PacketCapture failed: %v", err)
	}
	tc.expectedStatus.FilePath = pc.Status.FilePath

	// remove pending condition as it's random
	newCond := []crdv1alpha1.PacketCaptureCondition{}
	for _, cond := range pc.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCapturePending || cond.Type == crdv1alpha1.PacketCaptureRunning {
			continue
		}
		newCond = append(newCond, cond)
	}
	pc.Status.Conditions = newCond
	if !packetCaptureStatusEqual(pc.Status, tc.expectedStatus) {
		t.Errorf("CR status not match, actual: %+v, expected: %+v", pc.Status, tc.expectedStatus)
	}
}

func (data *TestData) waitForPacketCapture(t *testing.T, name string, specTimeout int, fn func(*crdv1alpha1.PacketCapture) bool) (*crdv1alpha1.PacketCapture, error) {
	var pc *crdv1alpha1.PacketCapture
	var err error
	var timeout = time.Duration(60) * time.Second
	if specTimeout > 0 {
		timeout = time.Duration(specTimeout) * time.Second
	}
	if err = wait.PollUntilContextTimeout(context.Background(), defaultInterval, timeout, true, func(ctx context.Context) (bool, error) {
		pc, err = data.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if fn(pc) {
			return true, nil
		}
		return false, nil

	}); err != nil {
		if pc != nil {
			t.Errorf("Latest PacketCapture status: %s %+v", pc.Name, pc.Status)
		}
		return nil, err
	}
	return pc, nil
}

func isPacketCaptureReady(pc *crdv1alpha1.PacketCapture) bool {
	if len(pc.Status.Conditions) == 0 {
		return false
	}

	for _, cond := range pc.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCaptureCompleted {
			return true
		}
	}
	return false

}

func isPacketCaptureRunning(pc *crdv1alpha1.PacketCapture) bool {
	if len(pc.Status.Conditions) == 0 {
		return false
	}

	for _, cond := range pc.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCaptureRunning && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false

}

func conditionEqualsIgnoreLastTransitionTime(a, b crdv1alpha1.PacketCaptureCondition) bool {
	a1 := a
	a1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	b1 := b
	b1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return a1 == b1
}

var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	conditionSliceEqualsIgnoreLastTransitionTime,
)

func packetCaptureStatusEqual(oldStatus, newStatus crdv1alpha1.PacketCaptureStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

func conditionSliceEqualsIgnoreLastTransitionTime(as, bs []crdv1alpha1.PacketCaptureCondition) bool {

	sort.Slice(as, func(i, j int) bool {
		return as[i].Type < as[j].Type
	})
	sort.Slice(bs, func(i, j int) bool {
		return bs[i].Type < bs[j].Type
	})

	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		a := as[i]
		b := bs[i]
		if !conditionEqualsIgnoreLastTransitionTime(a, b) {
			return false
		}
	}
	return true
}

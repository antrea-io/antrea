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
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

var (
	icmpProto = intstr.FromString("ICMP")
	udpProto  = intstr.FromString("UDP")
	tcpProto  = intstr.FromString("TCP")
)

type pcTestCase struct {
	name           string
	pc             *crdv1alpha1.PacketCapture
	expectedStatus crdv1alpha1.PacketCaptureStatus

	// required IP version, skip if not match.
	ipVersion int
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
	skipIfFeatureDisabled(t, features.PacketCapture, true, false)
	skipIfHasWindowsNodes(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	deployment, svc, pubKeys, err := data.deploySFTPServer(context.TODO(), 0)
	require.NoError(t, err, "failed to deploy SFTP server")
	require.Len(t, pubKeys, 2)
	pubKey1, pubKey2 := pubKeys[0], pubKeys[1]
	require.NoError(t, data.waitForDeploymentReady(t, deployment.Namespace, deployment.Name, defaultTimeout))
	require.NotEmpty(t, svc.Spec.ClusterIP)

	sec := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// #nosec G101
			Name:      "antrea-packetcapture-fileserver-auth",
			Namespace: "kube-system",
		},
		Data: map[string][]byte{
			"username": []byte(sftpUser),
			"password": []byte(sftpPassword),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(sec.Namespace).Create(context.TODO(), sec, metav1.CreateOptions{})
	require.NoError(t, err)
	defer data.clientset.CoreV1().Secrets(sec.Namespace).Delete(context.TODO(), sec.Name, metav1.DeleteOptions{})

	t.Run("testPacketCaptureBasic", func(t *testing.T) {
		testPacketCaptureBasic(t, data, svc.Spec.ClusterIP, pubKey1.Marshal(), pubKey2.Marshal())
	})

}

// getLocalPcapFilepath returns the path of the local pcap file present inside the Pod, for the
// Antrea Agent which ran the packet capture.
func getLocalPcapFilepath(pcName string) string {
	return path.Join("/tmp", "antrea", "packetcapture", "packets", pcName+".pcapng")
}

type packetCaptureOption func(pc *crdv1alpha1.PacketCapture)

func packetCaptureTimeout(timeout *int32) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.Timeout = timeout
	}
}

func packetCaptureFirstN(firstN int32) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.CaptureConfig.FirstN = &crdv1alpha1.PacketCaptureFirstNConfig{
			Number: firstN,
		}
	}
}

func packetCaptureHostPublicKey(pubKey []byte) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.FileServer.HostPublicKey = pubKey
	}
}

// testPacketCaptureTCP verifies if PacketCapture can capture tcp packets. this function only contains basic
// cases with pod-to-pod.
func testPacketCaptureBasic(t *testing.T, data *TestData, sftpServerIP string, pubKey1, pubKey2 []byte) {
	node1 := nodeName(0)
	clientPodName := "client"
	tcpServerPodName := "tcp-server"
	udpServerPodName := "udp-server"
	nonExistingPodName := "non-existing-pod"
	sftpURL := fmt.Sprintf("sftp://%s:22/%s", sftpServerIP, sftpUploadDir)
	invalidPubKey, _, err := sftptesting.GenerateEd25519Key()
	require.NoError(t, err)

	require.NoError(t, data.createToolboxPodOnNode(clientPodName, data.testNamespace, node1, false))
	defer data.DeletePodAndWait(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil))
	defer data.DeletePodAndWait(defaultTimeout, tcpServerPodName, data.testNamespace)
	require.NoError(t, createUDPServerPod(udpServerPodName, data.testNamespace, serverPodPort, node1))
	defer data.DeletePodAndWait(defaultTimeout, udpServerPodName, data.testNamespace)

	waitForPodIPs(t, data, []PodInfo{
		{Name: clientPodName},
		{Name: tcpServerPodName},
		{Name: udpServerPodName},
	})

	// This is the name of the Antrea Pod which performs the capture. The capture is performed
	// on the Node where the source Pod (clientPodName) is running, which is node1.
	antreaPodName, err := data.getAntreaPodOnNode(node1)
	require.NoError(t, err)

	getPcapURL := func(name string) string {
		p, err := url.JoinPath(sftpURL, name+".pcapng")
		require.NoError(t, err)
		return p
	}

	getPacketCaptureCR := func(name string, destinationPodName string, packet *crdv1alpha1.Packet, options ...packetCaptureOption) *crdv1alpha1.PacketCapture {
		pc := &crdv1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: crdv1alpha1.PacketCaptureSpec{
				Source: crdv1alpha1.Source{
					Pod: &crdv1alpha1.PodReference{
						Namespace: data.testNamespace,
						Name:      clientPodName,
					},
				},
				Destination: crdv1alpha1.Destination{
					Pod: &crdv1alpha1.PodReference{
						Namespace: data.testNamespace,
						Name:      destinationPodName,
					},
				},
				CaptureConfig: crdv1alpha1.CaptureConfig{
					FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
						Number: 5,
					},
				},
				FileServer: &crdv1alpha1.PacketCaptureFileServer{
					URL: sftpURL,
				},
				Packet: packet,
			},
		}
		for _, option := range options {
			option(pc)
		}
		return pc
	}

	testcases := []pcTestCase{
		{
			name:      "ipv4-icmp-timeout",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-icmp-timeout",
				udpServerPodName,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				packetCaptureTimeout(ptr.To[int32](15)),
				packetCaptureFirstN(500),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 10,
				FilePath:       getPcapURL("ipv4-icmp-timeout"),
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:    crdv1alpha1.PacketCaptureComplete,
						Status:  metav1.ConditionStatus(v1.ConditionTrue),
						Reason:  "Timeout",
						Message: "context deadline exceeded",
					},
					{
						Type:   crdv1alpha1.PacketCaptureFileUploaded,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
				},
			},
		},
		{
			name:      nonExistingPodName,
			ipVersion: 4,
			pc: getPacketCaptureCR(
				nonExistingPodName,
				nonExistingPodName,
				nil,
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:    crdv1alpha1.PacketCaptureComplete,
						Status:  metav1.ConditionStatus(v1.ConditionTrue),
						Reason:  "Failed",
						Message: fmt.Sprintf("failed to get Pod %s/%s: pods \"%s\" not found", data.testNamespace, nonExistingPodName, nonExistingPodName),
					},
				},
			},
		},
		{
			name:      "ipv4-tcp",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-tcp",
				tcpServerPodName,
				&crdv1alpha1.Packet{
					Protocol: &tcpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				packetCaptureHostPublicKey(pubKey1),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-tcp"),
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:   crdv1alpha1.PacketCaptureComplete,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
					{
						Type:   crdv1alpha1.PacketCaptureFileUploaded,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
				},
			},
		},
		{
			name:      "ipv4-udp",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-udp",
				udpServerPodName,
				&crdv1alpha1.Packet{
					Protocol: &udpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						UDP: &crdv1alpha1.UDPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				packetCaptureHostPublicKey(pubKey2),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-udp"),
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:   crdv1alpha1.PacketCaptureComplete,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
					{
						Type:   crdv1alpha1.PacketCaptureFileUploaded,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
				},
			},
		},
		{
			name:      "ipv4-icmp",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-icmp",
				tcpServerPodName,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-icmp"),
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:   crdv1alpha1.PacketCaptureComplete,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
					{
						Type:   crdv1alpha1.PacketCaptureFileUploaded,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
				},
			},
		},
		{
			// The key is correctly formatted but does not match the server's keys.
			name:      "invalid-host-public-key",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"invalid-host-public-key",
				tcpServerPodName,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				packetCaptureHostPublicKey(invalidPubKey.Marshal()),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       antreaPodName + ":" + getLocalPcapFilepath("invalid-host-public-key"),
				Conditions: []crdv1alpha1.PacketCaptureCondition{
					{
						Type:   crdv1alpha1.PacketCaptureStarted,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Started",
					},
					{
						Type:   crdv1alpha1.PacketCaptureComplete,
						Status: metav1.ConditionStatus(v1.ConditionTrue),
						Reason: "Succeed",
					},
					{
						Type:    crdv1alpha1.PacketCaptureFileUploaded,
						Status:  metav1.ConditionStatus(v1.ConditionFalse),
						Reason:  "Failed",
						Message: "failed to upload file after 5 attempts",
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
	return "linux"
}

func runPacketCaptureTest(t *testing.T, data *TestData, tc pcTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}

	var dstPodIPs *PodIPs
	if tc.pc.Spec.Destination.IP != nil {
		ip := net.ParseIP(*tc.pc.Spec.Destination.IP)
		if ip.To4() != nil {
			dstPodIPs = &PodIPs{IPv4: &ip}
		} else {
			dstPodIPs = &PodIPs{IPv6: &ip}
		}
	} else if tc.pc.Spec.Destination.Pod != nil {
		pod, err := data.clientset.CoreV1().Pods(tc.pc.Spec.Destination.Pod.Namespace).Get(context.TODO(), tc.pc.Spec.Destination.Pod.Name, metav1.GetOptions{})
		if err != nil {
			require.True(t, errors.IsNotFound(err))
		} else {
			dstPodIPs, err = parsePodIPs(pod)
			require.NoError(t, err)
		}
	}
	var srcPodIPs *PodIPs
	if tc.pc.Spec.Source.IP != nil {
		ip := net.ParseIP(*tc.pc.Spec.Source.IP)
		srcPodIPs = &PodIPs{IPv4: &ip}
	} else if tc.pc.Spec.Source.Pod != nil {
		pod, err := data.clientset.CoreV1().Pods(tc.pc.Spec.Source.Pod.Namespace).Get(context.TODO(), tc.pc.Spec.Source.Pod.Name, metav1.GetOptions{})
		if err != nil {
			require.True(t, errors.IsNotFound(err))
		} else {
			srcPodIPs, err = parsePodIPs(pod)
			require.NoError(t, err)
		}
	}

	if _, err := data.crdClient.CrdV1alpha1().PacketCaptures().Create(context.TODO(), tc.pc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketCapture: %v", err)
	}
	defer func() {
		if err := data.crdClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), tc.pc.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketCapture: %v", err)
		}
	}()

	// The destination is unset or invalid, do not generate traffic as the test expects to fail.
	if dstPodIPs != nil {
		srcPod := tc.pc.Spec.Source.Pod.Name
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
				if err := data.runNetcatCommandFromTestPodWithProtocol(srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "tcp"); err != nil {
					t.Logf("Netcat(TCP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		} else if protocol == udpProto {
			for i := 1; i <= 10; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "udp"); err != nil {
					t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		}
	}

	timeout := tc.pc.Spec.Timeout
	if timeout == nil {
		// It may take some time to upload.
		timeout = ptr.To[int32](15)
	}

	if strings.Contains(tc.name, "timeout") {
		// wait more for status update.
		timeout = ptr.To[int32](*timeout + 5)
	}

	pc, err := data.waitForPacketCapture(t, tc.pc.Name, int(*timeout), isPacketCaptureComplete)
	if err != nil {
		t.Fatalf("Error: Get PacketCapture failed: %v", err)
	}
	if !packetCaptureStatusEqual(pc.Status, tc.expectedStatus) {
		t.Errorf("CR status not match, actual: %+v, expected: %+v", pc.Status, tc.expectedStatus)
	}

	if tc.expectedStatus.NumberCaptured == 0 {
		return
	}
	// verify packets.
	antreaPodName, err := data.getAntreaPodOnNode(nodeName(0))
	require.NoError(t, err)
	tmpDir := t.TempDir()
	dstFileName := filepath.Join(tmpDir, tc.pc.Name+".pcapng")
	packetFile := getLocalPcapFilepath(tc.pc.Name)
	require.NoError(t, data.copyPodFile(antreaPodName, "antrea-agent", "kube-system", packetFile, tmpDir))
	defer os.Remove(dstFileName)
	file, err := os.Open(dstFileName)
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, verifyPacketFile(t, tc.pc, file, tc.expectedStatus.NumberCaptured, *srcPodIPs.IPv4, *dstPodIPs.IPv4))
}

func (data *TestData) waitForPacketCapture(t *testing.T, name string, specTimeout int, fn func(*crdv1alpha1.PacketCapture) bool) (*crdv1alpha1.PacketCapture, error) {
	var pc *crdv1alpha1.PacketCapture
	var err error
	var timeout = time.Duration(60) * time.Second
	if specTimeout > 0 {
		timeout = time.Duration(specTimeout) * time.Second
	}
	if err = wait.PollUntilContextTimeout(context.Background(), defaultInterval, timeout, true, func(ctx context.Context) (bool, error) {
		c, err := data.crdClient.CrdV1alpha1().PacketCaptures().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		pc = c
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

func isPacketCaptureComplete(pc *crdv1alpha1.PacketCapture) bool {
	for _, cond := range pc.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCaptureComplete && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false

}

func isPacketCaptureRunning(pc *crdv1alpha1.PacketCapture) bool {
	for _, cond := range pc.Status.Conditions {
		if cond.Type == crdv1alpha1.PacketCaptureStarted && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false

}

func packetCaptureConditionEqual(c1, c2 crdv1alpha1.PacketCaptureCondition) bool {
	c1.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	c2.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	return c1 == c2
}

var packetCaptureStatusSemanticEquality = conversion.EqualitiesOrDie(
	packetCaptureConditionSliceEqual,
)

func packetCaptureStatusEqual(status1, status2 crdv1alpha1.PacketCaptureStatus) bool {
	return packetCaptureStatusSemanticEquality.DeepEqual(status1, status2)
}

func packetCaptureConditionSliceEqual(s1, s2 []crdv1alpha1.PacketCaptureCondition) bool {
	sort.Slice(s1, func(i, j int) bool {
		return s1[i].Type < s1[j].Type
	})
	sort.Slice(s2, func(i, j int) bool {
		return s2[i].Type < s2[j].Type
	})

	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		a := s1[i]
		b := s2[i]
		if !packetCaptureConditionEqual(a, b) {
			return false
		}
	}
	return true
}

// verifyPacketFile will read the packets file and check if packet count and packet data match with CR.
func verifyPacketFile(t *testing.T, pc *crdv1alpha1.PacketCapture, reader io.Reader, targetNum int32, srcIP net.IP, dstIP net.IP) (err error) {
	ngReader, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return err
	}

	for i := int32(0); i < targetNum; i++ {
		data, _, err := ngReader.ReadPacketData()
		if err != nil {
			return err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		require.NotNil(t, ipLayer)
		ip, _ := ipLayer.(*layers.IPv4)
		assert.Equal(t, srcIP.String(), ip.SrcIP.String())
		assert.Equal(t, dstIP.String(), ip.DstIP.String())

		if pc.Spec.Packet == nil {
			continue
		}

		packetSpec := pc.Spec.Packet
		proto := packetSpec.Protocol
		if proto == nil {
			continue
		}
		if strings.ToUpper(proto.StrVal) == "TCP" || proto.IntVal == 6 {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			require.NotNil(t, tcpLayer)
			tcp, _ := tcpLayer.(*layers.TCP)
			if packetSpec.TransportHeader.TCP != nil {
				ports := packetSpec.TransportHeader.TCP
				if ports.DstPort != nil {
					assert.Equal(t, *ports.DstPort, int32(tcp.DstPort))
				}
				if ports.SrcPort != nil {
					assert.Equal(t, *ports.SrcPort, int32(tcp.SrcPort))
				}
			}
		} else if strings.ToUpper(proto.StrVal) == "UDP" || proto.IntVal == 17 {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			require.NotNil(t, udpLayer)
			udp, _ := udpLayer.(*layers.UDP)
			if packetSpec.TransportHeader.UDP != nil {
				ports := packetSpec.TransportHeader.UDP
				if ports.DstPort != nil {
					assert.Equal(t, *ports.DstPort, int32(udp.DstPort))
				}
				if ports.SrcPort != nil {
					assert.Equal(t, *ports.SrcPort, int32(udp.SrcPort))
				}
			}
		} else if strings.ToUpper(proto.StrVal) == "ICMP" || proto.IntVal == 1 {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			require.NotNil(t, icmpLayer)
		}
	}
	return nil
}

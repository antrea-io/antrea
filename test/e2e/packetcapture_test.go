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

	capture "antrea.io/antrea/pkg/agent/packetcapture/capture"
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

	// optional timeout in seconds. If omitted, we will use a reasonable default for the test
	// case. Note that this is the timeout used by the test when polling for the desired
	// PacketCapture Status. It is different from the PacketCapture Timeout, which can be set as
	// part of the pc field.
	timeoutSeconds int

	// number of netcat connections to make from the client to server
	numConnections int
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
func aaaaTestPacketCapture(t *testing.T) {
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
	t.Run("testPacketCaptureL4Filters", func(t *testing.T) {
		testPacketCaptureL4Filters(t, data, svc.Spec.ClusterIP, pubKey1.Marshal())
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

func getPacketCaptureCR(name string, namespace string, clientPodName string, destinationPodName string, sftpURL string, packet *crdv1alpha1.Packet, direction crdv1alpha1.CaptureDirection, options ...packetCaptureOption) *crdv1alpha1.PacketCapture {
	pc := &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: crdv1alpha1.PacketCaptureSpec{
			Source: crdv1alpha1.Source{
				Pod: &crdv1alpha1.PodReference{
					Namespace: namespace,
					Name:      clientPodName,
				},
			},
			Destination: crdv1alpha1.Destination{
				Pod: &crdv1alpha1.PodReference{
					Namespace: namespace,
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
			Packet:    packet,
			Direction: direction,
		},
	}
	for _, option := range options {
		option(pc)
	}
	return pc
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

	testcases := []pcTestCase{
		{
			name:      "ipv4-icmp-timeout",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-icmp-timeout",
				data.testNamespace,
				clientPodName,
				udpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
				data.testNamespace,
				clientPodName,
				nonExistingPodName,
				sftpURL,
				nil,
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &tcpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
				data.testNamespace,
				clientPodName,
				udpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &udpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						UDP: &crdv1alpha1.UDPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
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
			// Takes into account retries and delay between retries for upload failures.
			timeoutSeconds: 30,
		},
		{
			name:      "ipv4-udp-dst-to-src",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-udp-dst-to-src",
				data.testNamespace,
				clientPodName,
				udpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &udpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						UDP: &crdv1alpha1.UDPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				crdv1alpha1.CaptureDirectionDestinationToSource,
				packetCaptureHostPublicKey(pubKey2),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-udp-dst-to-src"),
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
			name:      "ipv4-tcp-both",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-tcp-both",
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &tcpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureHostPublicKey(pubKey1),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-tcp-both"),
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

// testPacketCaptureL4Filters is for test cases involving L4 protocol-specific filters.
// Separating these from testPacketCaptureBasic ensures isolation of more advanced filtering scenarios, preventing
// potential interference with other test cases.
func testPacketCaptureL4Filters(t *testing.T, data *TestData, sftpServerIP string, pubKey1 []byte) {
	node1 := nodeName(0)
	clientPodName := "client-2"
	tcpServerPodName := "tcp-server-2"
	sftpURL := fmt.Sprintf("sftp://%s:22/%s", sftpServerIP, sftpUploadDir)

	require.NoError(t, data.createToolboxPodOnNode(clientPodName, data.testNamespace, node1, false))
	defer data.DeletePodAndWait(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, data.createServerPodWithLabels(tcpServerPodName, data.testNamespace, serverPodPort, nil))
	defer data.DeletePodAndWait(defaultTimeout, tcpServerPodName, data.testNamespace)

	waitForPodIPs(t, data, []PodInfo{
		{Name: clientPodName},
		{Name: tcpServerPodName},
	})

	getPcapURL := func(name string) string {
		p, err := url.JoinPath(sftpURL, name+".pcapng")
		require.NoError(t, err)
		return p
	}

	testcases := []pcTestCase{
		{
			name:      "ipv4-tcp-syn-both-timeout",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-tcp-syn-both-timeout",
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &tcpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: ptr.To(serverPodPort),
							Flags: []crdv1alpha1.TCPFlagsMatcher{
								{Value: 0x2}, // +syn
							},
						},
					},
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureTimeout(ptr.To[int32](10)), // setting a high timeout to ensure capture ends due to timeout
				packetCaptureFirstN(500),                // ensures packet capture doesn't complete early due to packet count before timeout
				packetCaptureHostPublicKey(pubKey1),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 2,
				FilePath:       getPcapURL("ipv4-tcp-syn-both-timeout"),
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
			numConnections: 1, // creating one netcat connection to capture only a syn and a syn+ack packet
		},
		{
			name:      "ipv4-icmp-echoreply-both",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-icmp-echoreply-both",
				data.testNamespace,
				clientPodName,
				tcpServerPodName,
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						ICMP: &crdv1alpha1.ICMPHeader{
							Messages: []crdv1alpha1.ICMPMsgMatcher{
								{Type: intstr.FromString("icmp-echoreply")},
							},
						},
					},
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureFirstN(1),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 1,
				FilePath:       getPcapURL("ipv4-icmp-echoreply-both"),
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
			numConnections: 1, // running ping command once to capture only an echo reply packet
		},
	}
	t.Run("testPacketCaptureL4Filters", func(t *testing.T) {
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

	if _, err := data.CRDClient.CrdV1alpha1().PacketCaptures().Create(context.TODO(), tc.pc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketCapture: %v", err)
	}
	defer func() {
		if err := data.CRDClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), tc.pc.Name, metav1.DeleteOptions{}); err != nil {
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
		connections := 10
		if tc.numConnections != 0 {
			connections = tc.numConnections
		}
		// Send an ICMP echo packet from the source Pod to the destination.
		switch protocol {
		case icmpProto:
			if err := data.RunPingCommandFromTestPod(PodInfo{srcPod, getOSString(), "", data.testNamespace},
				data.testNamespace, dstPodIPs, toolboxContainerName, connections, 0, false); err != nil {
				t.Logf("Ping(%s) '%s' -> '%v' failed: ERROR (%v)", protocol.StrVal, srcPod, *dstPodIPs, err)
			}
		case tcpProto:
			for i := 1; i <= connections; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "tcp"); err != nil {
					t.Logf("Netcat(TCP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		case udpProto:
			for i := 1; i <= connections; i++ {
				if err := data.runNetcatCommandFromTestPodWithProtocol(srcPod, data.testNamespace, toolboxContainerName, server, serverPodPort, "udp"); err != nil {
					t.Logf("Netcat(UDP) '%s' -> '%v' failed: ERROR (%v)", srcPod, server, err)
				}
			}
		}
	}

	const defaultTimeoutSeconds = 15
	timeoutSeconds := tc.timeoutSeconds
	// If timeout is not explicitly provided by test case...
	if timeoutSeconds == 0 {
		if tc.pc.Spec.Timeout != nil {
			timeoutSeconds = int(*tc.pc.Spec.Timeout)
		} else {
			timeoutSeconds = defaultTimeoutSeconds
		}
		if strings.Contains(tc.name, "timeout") {
			// wait more for status update.
			timeoutSeconds += 5
		}
	}

	pc, err := data.waitForPacketCapture(t, tc.pc.Name, timeoutSeconds, isPacketCaptureComplete)
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
		c, err := data.CRDClient.CrdV1alpha1().PacketCaptures().Get(ctx, name, metav1.GetOptions{})
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
		direction := pc.Spec.Direction
		switch direction {
		case crdv1alpha1.CaptureDirectionDestinationToSource:
			assert.Equal(t, srcIP.String(), ip.DstIP.String())
			assert.Equal(t, dstIP.String(), ip.SrcIP.String())
		case crdv1alpha1.CaptureDirectionBoth:
			assert.Contains(t, []string{srcIP.String(), dstIP.String()}, ip.SrcIP.String())
			assert.Contains(t, []string{srcIP.String(), dstIP.String()}, ip.DstIP.String())
		default:
			assert.Equal(t, srcIP.String(), ip.SrcIP.String())
			assert.Equal(t, dstIP.String(), ip.DstIP.String())
		}

		if pc.Spec.Packet == nil {
			continue
		}

		packetSpec := pc.Spec.Packet
		proto := packetSpec.Protocol
		if proto == nil {
			continue
		}

		// addPortExpectations compares CRD ports with packet header ports based on capture direction
		addPortExpectations := func(crdSrcPort, crdDstPort *int32, hdrSrcPort, hdrDstPort int32) {
			t.Helper()
			switch direction {
			case crdv1alpha1.CaptureDirectionSourceToDestination:
				if crdDstPort != nil {
					assert.Equal(t, *crdDstPort, hdrDstPort)
				}
				if crdSrcPort != nil {
					assert.Equal(t, *crdSrcPort, hdrSrcPort)
				}
			case crdv1alpha1.CaptureDirectionDestinationToSource:
				if crdDstPort != nil {
					assert.Equal(t, *crdDstPort, hdrSrcPort)
				}
				if crdSrcPort != nil {
					assert.Equal(t, *crdSrcPort, hdrDstPort)
				}
			case crdv1alpha1.CaptureDirectionBoth:
				if crdDstPort != nil {
					assert.Contains(t, []int32{hdrSrcPort, hdrDstPort}, *crdDstPort)
				}
				if crdSrcPort != nil {
					assert.Contains(t, []int32{hdrSrcPort, hdrDstPort}, *crdSrcPort)
				}
			default:
				require.Fail(t, "Invalid direction value")
			}
		}

		if strings.ToUpper(proto.StrVal) == "TCP" || proto.IntVal == 6 {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			require.NotNil(t, tcpLayer)
			tcp, _ := tcpLayer.(*layers.TCP)
			if packetSpec.TransportHeader.TCP != nil {
				ports := packetSpec.TransportHeader.TCP
				addPortExpectations(ports.SrcPort, ports.DstPort, int32(tcp.SrcPort), int32(tcp.DstPort))
				if packetSpec.TransportHeader.TCP.Flags != nil {
					matched := false
					for _, f := range packetSpec.TransportHeader.TCP.Flags {
						m := f.Value
						if f.Mask != nil {
							m = *f.Mask
						}
						if tcp.Contents[13]&uint8(m) == uint8(f.Value) {
							matched = true
							break
						}
					}
					assert.True(t, matched)
				}
			}
		} else if strings.ToUpper(proto.StrVal) == "UDP" || proto.IntVal == 17 {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			require.NotNil(t, udpLayer)
			udp, _ := udpLayer.(*layers.UDP)
			if packetSpec.TransportHeader.UDP != nil {
				ports := packetSpec.TransportHeader.UDP
				addPortExpectations(ports.SrcPort, ports.DstPort, int32(udp.SrcPort), int32(udp.DstPort))
			}
		} else if strings.ToUpper(proto.StrVal) == "ICMP" || proto.IntVal == 1 {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			require.NotNil(t, icmpLayer)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if packetSpec.TransportHeader.ICMP != nil {
				matched := false
				for _, f := range packetSpec.TransportHeader.ICMP.Messages {
					var typeValue uint8
					switch f.Type.Type {
					case intstr.Int:
						if f.Type.IntVal < 0 || f.Type.IntVal > 255 {
							require.Fail(t, "Invalid ICMP type number value")
						}
						typeValue = uint8(f.Type.IntVal)
					case intstr.String:
						if _, ok := capture.ICMPMsgTypeMap[crdv1alpha1.ICMPMsgType(strings.ToLower(f.Type.StrVal))]; !ok {
							require.Fail(t, "Invalid ICMP type string value")
						}
						typeValue = uint8(capture.ICMPMsgTypeMap[crdv1alpha1.ICMPMsgType(strings.ToLower(f.Type.StrVal))])
					}

					if icmp.TypeCode.Type() == typeValue {
						if f.Code == nil || icmp.TypeCode.Code() == uint8(*f.Code) {
							matched = true
							break
						}
					}
				}
				assert.True(t, matched)
			}
		}
	}
	return nil
}

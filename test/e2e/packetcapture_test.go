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
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	capture "antrea.io/antrea/pkg/agent/packetcapture/capture"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	sftptesting "antrea.io/antrea/pkg/util/sftp/testing"
)

var (
	icmpProto   = intstr.FromString("ICMP")
	icmpv6Proto = intstr.FromString("ICMPv6")
	udpProto    = intstr.FromString("UDP")
	tcpProto    = intstr.FromString("TCP")
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

	// set to true if the PacketCapture is expected to fail due to an invalid destination.
	invalidDestination bool
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

func packetCaptureSourcePod(namespace, name string) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.Source.Pod = &crdv1alpha1.PodReference{
			Namespace: namespace,
			Name:      name,
		}
	}
}

func packetCaptureDestinationPod(namespace, name string) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.Destination.Pod = &crdv1alpha1.PodReference{
			Namespace: namespace,
			Name:      name,
		}
	}
}

func packetCaptureCapturePoint(point crdv1alpha1.CapturePoint) packetCaptureOption {
	return func(pc *crdv1alpha1.PacketCapture) {
		pc.Spec.CapturePoint = point
	}
}

func getPacketCaptureCR(name string, sftpURL string, packet *crdv1alpha1.Packet, direction crdv1alpha1.CaptureDirection, options ...packetCaptureOption) *crdv1alpha1.PacketCapture {
	pc := &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: crdv1alpha1.PacketCaptureSpec{
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
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, udpServerPodName),
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
				sftpURL,
				nil,
				crdv1alpha1.CaptureDirectionSourceToDestination,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, nonExistingPodName),
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
			invalidDestination: true,
		},
		{
			name:      "ipv4-tcp",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-tcp",
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, udpServerPodName),
				packetCaptureHostPublicKey(pubKey2),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
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
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
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
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpProto,
					IPFamily: v1.IPv4Protocol,
				},
				crdv1alpha1.CaptureDirectionSourceToDestination,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, udpServerPodName),
				packetCaptureHostPublicKey(pubKey2),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
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
		{
			name:      "ipv4-tcp-src-only",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-tcp-src-only",
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureHostPublicKey(pubKey1),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-tcp-src-only"),
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
			name:      "ipv4-udp-dst-only-direction-both",
			ipVersion: 4,
			pc: getPacketCaptureCR(
				"ipv4-udp-dst-only-direction-both",
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
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureDestinationPod(data.testNamespace, udpServerPodName),
				packetCaptureHostPublicKey(pubKey2),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv4-udp-dst-only-direction-both"),
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
			name:      "ipv6-tcp-both",
			ipVersion: 6,
			pc: getPacketCaptureCR(
				"ipv6-tcp-both",
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &tcpProto,
					IPFamily: v1.IPv6Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						TCP: &crdv1alpha1.TCPHeader{
							DstPort: ptr.To(serverPodPort),
						},
					},
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv6-tcp-both"),
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
			name:      "ipv6-icmpv6-both",
			ipVersion: 6,
			pc: getPacketCaptureCR(
				"ipv6-icmpv6-both",
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpv6Proto,
					IPFamily: v1.IPv6Protocol,
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 5,
				FilePath:       getPcapURL("ipv6-icmpv6-both"),
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
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
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureFirstN(1),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
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
		{
			name:      "ipv6-icmpv6-echo-echoreply-both",
			ipVersion: 6,
			pc: getPacketCaptureCR(
				"ipv6-icmpv6-echo-echoreply-both",
				sftpURL,
				&crdv1alpha1.Packet{
					Protocol: &icmpv6Proto,
					IPFamily: v1.IPv6Protocol,
					TransportHeader: crdv1alpha1.TransportHeader{
						ICMPv6: &crdv1alpha1.ICMPv6Header{
							Messages: []crdv1alpha1.ICMPv6MsgMatcher{
								{Type: intstr.FromString("icmpv6-echo")},
								{Type: intstr.FromString("icmpv6-echoreply")},
							},
						},
					},
				},
				crdv1alpha1.CaptureDirectionBoth,
				packetCaptureSourcePod(data.testNamespace, clientPodName),
				packetCaptureDestinationPod(data.testNamespace, tcpServerPodName),
				packetCaptureHostPublicKey(pubKey1),
				packetCaptureFirstN(2),
				packetCaptureCapturePoint(crdv1alpha1.CapturePointDestination),
			),
			expectedStatus: crdv1alpha1.PacketCaptureStatus{
				NumberCaptured: 2,
				FilePath:       getPcapURL("ipv6-icmpv6-echo-echoreply-both"),
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
			numConnections: 1,
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

// determineExpectedCaptureNode determines which Node is expected to perform a packet
// capture based on the source/destination Pods and the CapturePoint specified in
// the test case.
func determineExpectedCaptureNode(t *testing.T, data *TestData, tc pcTestCase) string {
	getNodeName := func(targetPodRef *crdv1alpha1.PodReference) string {
		targetPod, err := data.clientset.CoreV1().Pods(targetPodRef.Namespace).Get(context.TODO(), targetPodRef.Name, metav1.GetOptions{})
		require.NoError(t, err, "Failed to get the target Pod for the packet capture")
		return targetPod.Spec.NodeName
	}

	if tc.pc.Spec.CapturePoint == "" {
		if tc.pc.Spec.Source.Pod != nil {
			tc.pc.Spec.CapturePoint = crdv1alpha1.CapturePointSource
		} else {
			tc.pc.Spec.CapturePoint = crdv1alpha1.CapturePointDestination
		}
	}

	var node string
	if tc.pc.Spec.Source.Pod != nil && tc.pc.Spec.CapturePoint == crdv1alpha1.CapturePointSource {
		node = getNodeName(tc.pc.Spec.Source.Pod)
	} else if tc.pc.Spec.Destination.Pod != nil && tc.pc.Spec.CapturePoint == crdv1alpha1.CapturePointDestination {
		node = getNodeName(tc.pc.Spec.Destination.Pod)
	}
	return node
}

func getOSString() string {
	return "linux"
}

func resolveEndpointToPodIPs(t *testing.T, data *TestData, podRef *crdv1alpha1.PodReference, ipStr *string) *PodIPs {
	if ipStr != nil {
		ip := net.ParseIP(*ipStr)
		if ip.To4() != nil {
			return &PodIPs{IPv4: &ip}
		}
		return &PodIPs{IPv6: &ip}
	} else if podRef != nil {
		pod, err := data.clientset.CoreV1().Pods(podRef.Namespace).Get(context.TODO(), podRef.Name, metav1.GetOptions{})
		require.NoError(t, err)
		podIPs, err := parsePodIPs(pod)
		require.NoError(t, err)
		return podIPs
	}
	return nil
}

// If the source Pod is not specified in the PacketCapture CR (i.e., dst-only capture), we
// default to using the "client" Pod to verify whether traffic can be captured from any source.
func determineSrcPod(tc pcTestCase) string {
	if tc.pc.Spec.Source.Pod != nil {
		return tc.pc.Spec.Source.Pod.Name
	}
	return "client"
}

// If the destination Pod is not specified in the PacketCapture CR (i.e., src-only capture),
// we select a default server Pod based on the test protocol (TCP/UDP/ICMP) to verify whether
// traffic can be captured from any destination.
func determineDstPodIPs(t *testing.T, data *TestData, tc pcTestCase, dstPodIPs *PodIPs) *PodIPs {
	if dstPodIPs == nil {
		protocol := *tc.pc.Spec.Packet.Protocol
		var podName string
		switch protocol {
		case tcpProto, icmpProto, icmpv6Proto:
			podName = "tcp-server"
		case udpProto:
			podName = "udp-server"
		}
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		require.NoError(t, err)
		dstPodIPs, err = parsePodIPs(pod)
		require.NoError(t, err)
	}
	return dstPodIPs
}

func generateTraffic(t *testing.T, data *TestData, tc pcTestCase, srcPod string, dstPodIPs *PodIPs) {
	protocol := *tc.pc.Spec.Packet.Protocol
	var server string
	if tc.ipVersion == 6 {
		server = dstPodIPs.IPv6.String()
	} else {
		server = dstPodIPs.IPv4.String()
	}
	connections := 10
	if tc.numConnections != 0 {
		connections = tc.numConnections
	}

	switch protocol {
	case icmpProto, icmpv6Proto:
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

func runPacketCaptureTest(t *testing.T, data *TestData, tc pcTestCase) {
	switch tc.ipVersion {
	case 4:
		skipIfNotIPv4Cluster(t)
	case 6:
		skipIfNotIPv6Cluster(t)
	}

	if _, err := data.CRDClient.CrdV1alpha1().PacketCaptures().Create(context.TODO(), tc.pc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Error when creating PacketCapture: %v", err)
	}
	defer func() {
		if err := data.CRDClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), tc.pc.Name, metav1.DeleteOptions{}); err != nil {
			t.Errorf("Error when deleting PacketCapture: %v", err)
		}
	}()

	// wait for CR running.
	_, err := data.waitForPacketCapture(t, tc.pc.Name, 0, isPacketCaptureRunning)
	require.NoError(t, err, "Waiting PacketCapture to Running failed")

	var srcPodIPs, dstPodIPs *PodIPs

	if tc.invalidDestination {
		return
	}

	// Load the source and destination IPs from the Pod or IP specified in the CR
	srcPodIPs = resolveEndpointToPodIPs(t, data, tc.pc.Spec.Source.Pod, tc.pc.Spec.Source.IP)
	dstPodIPs = resolveEndpointToPodIPs(t, data, tc.pc.Spec.Destination.Pod, tc.pc.Spec.Destination.IP)

	// For single-endpoint captures, it determines the source Pod and destination Pod
	// for traffic generation by falling back to default Pods to ensure that
	// traffic can be sent to validate the capture.
	srcPod := determineSrcPod(tc)
	dstPodIPs = determineDstPodIPs(t, data, tc, dstPodIPs)
	generateTraffic(t, data, tc, srcPod, dstPodIPs)

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
	if !crdv1alpha1.PacketCaptureStatusEqual(pc.Status, tc.expectedStatus) {
		t.Errorf("CR status not match, actual: %+v, expected: %+v", pc.Status, tc.expectedStatus)
	}

	if tc.expectedStatus.NumberCaptured == 0 {
		return
	}

	captureNodeName := determineExpectedCaptureNode(t, data, tc)
	require.NotEmpty(t, captureNodeName, "Could not determine any node for packet capture")

	// verify packets.
	antreaPodName, err := data.getAntreaPodOnNode(captureNodeName)
	require.NoError(t, err)
	tmpDir := t.TempDir()
	dstFileName := filepath.Join(tmpDir, tc.pc.Name+".pcapng")
	packetFile := getLocalPcapFilepath(tc.pc.Name)

	// Copy the pcap file from the agent Pod, retrying for a short bounded
	// period to handle the case where the file is still being written.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		copyErr := data.copyPodFile(antreaPodName, "antrea-agent", "kube-system", packetFile, tmpDir)
		if copyErr != nil {
			// The file may still be in the process of being written; retry.
			return false, nil
		}
		return true, nil
	})
	require.NoError(t, err)

	defer os.Remove(dstFileName)
	file, err := os.Open(dstFileName)
	require.NoError(t, err)
	defer file.Close()
	var srcIP, dstIP net.IP
	if srcPodIPs != nil {
		if tc.ipVersion == 6 {
			srcIP = *srcPodIPs.IPv6
		} else {
			srcIP = *srcPodIPs.IPv4
		}
	}
	if dstPodIPs != nil {
		if tc.ipVersion == 6 {
			dstIP = *dstPodIPs.IPv6
		} else {
			dstIP = *dstPodIPs.IPv4
		}
	}
	require.NoError(t, verifyPacketFile(t, tc.pc, file, tc.expectedStatus.NumberCaptured, srcIP, dstIP))
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
		var ipSrcIP, ipDstIP net.IP
		if pc.Spec.Packet.IPFamily == v1.IPv6Protocol {
			ipLayer := packet.Layer(layers.LayerTypeIPv6)
			require.NotNil(t, ipLayer, "Packet should have an IPv6 layer")
			ip, _ := ipLayer.(*layers.IPv6)
			ipSrcIP, ipDstIP = ip.SrcIP, ip.DstIP
		} else {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			require.NotNil(t, ipLayer, "Packet should have an IPv4 layer")
			ip, _ := ipLayer.(*layers.IPv4)
			ipSrcIP, ipDstIP = ip.SrcIP, ip.DstIP
		}
		direction := pc.Spec.Direction
		switch direction {
		case crdv1alpha1.CaptureDirectionDestinationToSource:
			if srcIP != nil {
				assert.Equal(t, srcIP.String(), ipDstIP.String())
			}
			if dstIP != nil {
				assert.Equal(t, dstIP.String(), ipSrcIP.String())
			}
		case crdv1alpha1.CaptureDirectionBoth:
			if srcIP != nil && dstIP != nil {
				assert.Contains(t, []string{srcIP.String(), dstIP.String()}, ipSrcIP.String())
				assert.Contains(t, []string{srcIP.String(), dstIP.String()}, ipDstIP.String())
			} else if srcIP != nil {
				targetIPStr := srcIP.String()
				isEgress := ipSrcIP.String() == targetIPStr
				isIngress := ipDstIP.String() == targetIPStr
				assert.True(t, isEgress || isIngress, "Packet (src=%s, dst=%s) does not involve target source Pod %s", ipSrcIP.String(), ipDstIP.String(), targetIPStr)
			} else if dstIP != nil {
				targetIPStr := dstIP.String()
				isEgress := ipSrcIP.String() == targetIPStr
				isIngress := ipDstIP.String() == targetIPStr
				assert.True(t, isEgress || isIngress, "Packet (src=%s, dst=%s) does not involve target destination Pod %s", ipSrcIP.String(), ipDstIP.String(), targetIPStr)
			}
		default:
			if srcIP != nil {
				assert.Equal(t, srcIP.String(), ipSrcIP.String())
			}
			if dstIP != nil {
				assert.Equal(t, dstIP.String(), ipDstIP.String())
			}
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
		} else if strings.ToUpper(proto.StrVal) == "ICMPV6" || proto.IntVal == 58 {
			icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
			require.NotNil(t, icmpv6Layer)
			icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)
			if packetSpec.TransportHeader.ICMPv6 != nil {
				matched := false
				for _, f := range packetSpec.TransportHeader.ICMPv6.Messages {
					var typeValue uint8
					switch f.Type.Type {
					case intstr.Int:
						if f.Type.IntVal < 0 || f.Type.IntVal > 255 {
							require.Fail(t, "Invalid ICMPv6 type number value")
						}
						typeValue = uint8(f.Type.IntVal)
					case intstr.String:
						if _, ok := capture.ICMPv6MsgTypeMap[crdv1alpha1.ICMPv6MsgType(strings.ToLower(f.Type.StrVal))]; !ok {
							require.Fail(t, "Invalid ICMPv6 type string value")
						}
						typeValue = uint8(capture.ICMPv6MsgTypeMap[crdv1alpha1.ICMPv6MsgType(strings.ToLower(f.Type.StrVal))])
					}

					if icmpv6.TypeCode.Type() == typeValue {
						if f.Code == nil || icmpv6.TypeCode.Code() == uint8(*f.Code) {
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

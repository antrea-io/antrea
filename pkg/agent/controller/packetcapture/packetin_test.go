// Copyright 2024 Antrea Authors
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

package packetcapture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/pkg/agent/config"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	maxNum = 5
)

const (
	testTag     = uint8(3)
	testUID     = "1-2-3-4"
	testSFTPUrl = "sftp://127.0.0.1:22/root/packetcaptures"
)

// generatePacketInMatchFromTag reverse the packetIn message/matcher -> REG4/tag value path
// to generate test matchers. It follows the following process:
// 1. shift bits to generate uint32, which represents data in REG4 and another REG (unrelated)
// 2. convert uint32 to bytes(bigEndian), which will be the Match value/mask.
// 3. generate MatchField from the bytes.
func generatePacketInMatchFromTag(tag uint8) *openflow15.MatchField {
	value := uint32(tag) << 28
	regID := 4
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data, value)

	m := openflow15.MatchField{
		Class:   openflow15.OXM_CLASS_PACKET_REGS,
		Field:   uint8(regID / 2),
		HasMask: false,
		Value:   &openflow15.ByteArrayField{Data: data},
	}
	return &m
}

func genMatchers() []openflow15.MatchField {
	// m := generateMatch(openflow.PacketCaptureMark.GetRegID(), testTagData)
	matchers := []openflow15.MatchField{*generatePacketInMatchFromTag(testTag)}
	return matchers
}

func getTestPacketBytes(dstIP string) []byte {
	ipPacket := &protocol.IPv4{
		Version:  0x4,
		IHL:      5,
		Protocol: uint8(8),
		Length:   20,
		NWSrc:    net.IP(pod1IPv4),
		NWDst:    net.IP(dstIP),
	}
	ethernetPkt := protocol.NewEthernet()
	ethernetPkt.HWSrc = pod1MAC
	ethernetPkt.Ethertype = protocol.IPv4_MSG
	ethernetPkt.Data = ipPacket
	pktBytes, _ := ethernetPkt.MarshalBinary()
	return pktBytes
}

func generateTestPCState(name string, pcapngFile afero.File, writer *pcapgo.NgWriter, num int32) *packetCaptureState {
	return &packetCaptureState{
		name:                  name,
		maxNumCapturedPackets: maxNum,
		numCapturedPackets:    num,
		tag:                   testTag,
		pcapngWriter:          writer,
		pcapngFile:            pcapngFile,
		shouldCapturePackets:  true,
		updateRateLimiter:     rate.NewLimiter(rate.Every(captureStatusUpdatePeriod), 1),
	}
}

func generatePacketCapture(name string) *crdv1alpha1.PacketCapture {
	return &crdv1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  testUID,
		},
		Status: crdv1alpha1.PacketCaptureStatus{},
		Spec: crdv1alpha1.PacketCaptureSpec{
			CaptureConfig: crdv1alpha1.CaptureConfig{
				FirstN: &crdv1alpha1.PacketCaptureFirstNConfig{
					Number: 5,
				},
			},
			FileServer: &crdv1alpha1.BundleFileServer{
				URL: testSFTPUrl,
			},
		},
	}
}

func generateTestSecret() *v1.Secret {
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "AAA",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("AAA"),
			"password": []byte("BBBCCC"),
		},
	}
}

type testUploader struct {
	url      string
	fileName string
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error {
	if url != uploader.url {
		return fmt.Errorf("expected url: %s for uploader, got: %s", uploader.url, url)
	}
	if fileName != uploader.fileName {
		return fmt.Errorf("expected filename: %s for uploader, got: %s", uploader.fileName, fileName)
	}
	return nil
}

func TestHandlePacketCapturePacketIn(t *testing.T) {

	invalidPktBytes := getTestPacketBytes("89.207.132.170")
	pktBytesPodToPod := getTestPacketBytes(pod2IPv4)

	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/packetcapture/packets", 0755)
	file, err := defaultFS.Create(uidToPath(testUID))
	if err != nil {
		t.Fatal("create pcapng file error: ", err)
	}

	testWriter, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("create test pcapng writer failed: ", err)
	}

	tests := []struct {
		name             string
		networkConfig    *config.NetworkConfig
		nodeConfig       *config.NodeConfig
		pcState          *packetCaptureState
		pktIn            *ofctrl.PacketIn
		expectedPC       *crdv1alpha1.PacketCapture
		expectedErrStr   string
		expectedCalls    func(mockOFClient *openflowtest.MockClient)
		expectedNum      int32
		expectedUploader *testUploader
	}{
		{
			name:       "invalid packets",
			pcState:    generateTestPCState("pc-with-invalid-packet", nil, testWriter, 0),
			expectedPC: generatePacketCapture("pc-with-invalid-packet"),
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					Data: util.NewBuffer(invalidPktBytes),
				},
			},
			expectedErrStr: "parsePacketIn error: PacketCapture for dataplane tag 0 not found in cache",
		},
		{
			name:        "not hitting target number",
			pcState:     generateTestPCState("pc-with-less-num", nil, testWriter, 1),
			expectedPC:  generatePacketCapture("pc-with-less-num"),
			expectedNum: 2,
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					Data: util.NewBuffer(pktBytesPodToPod),
					Match: openflow15.Match{
						Fields: genMatchers(),
					},
				},
			},
		},
		{
			name:        "hit target number",
			pcState:     generateTestPCState("pc-with-max-num", file, testWriter, maxNum-1),
			expectedPC:  generatePacketCapture("pc-with-max-num"),
			expectedNum: maxNum,
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					Data: util.NewBuffer(pktBytesPodToPod),
					Match: openflow15.Match{
						Fields: genMatchers(),
					},
				},
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallPacketCaptureFlows(testTag)
			},
			expectedUploader: &testUploader{
				fileName: testUID + ".pcapng",
				url:      testSFTPUrl,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcc := newFakePacketCaptureController(t, nil, []runtime.Object{tt.expectedPC}, &config.NodeConfig{Name: "node1"})
			if tt.expectedCalls != nil {
				tt.expectedCalls(pcc.mockOFClient)
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			pcc.crdInformerFactory.Start(stopCh)
			pcc.crdInformerFactory.WaitForCacheSync(stopCh)
			pcc.runningPacketCaptures[tt.pcState.tag] = tt.pcState
			pcc.sftpUploader = tt.expectedUploader

			err := pcc.HandlePacketIn(tt.pktIn)
			if err == nil {
				assert.Equal(t, tt.expectedErrStr, "")
				// check target num in status
				pc, err := pcc.crdClient.CrdV1alpha1().PacketCaptures().Get(context.TODO(), tt.expectedPC.Name, metav1.GetOptions{})
				require.Nil(t, err)
				assert.Equal(t, tt.expectedNum, *pc.Status.NumCapturedPackets)
			} else {
				assert.Equal(t, tt.expectedErrStr, err.Error())
			}

		})
	}
}

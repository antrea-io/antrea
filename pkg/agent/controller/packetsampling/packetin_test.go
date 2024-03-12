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

package packetsampling

import (
	"context"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"

	"antrea.io/antrea/pkg/agent/config"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	maxNum = 5
)

var (
	testTag     = int8(1)
	testUID     = "1-2-3-4"
	testSFTPUrl = "sftp://10.220.175.92:22/root/packetsamplings"
	// parse to tag(1)
	testTagData = []byte{0x11, 0x00, 0x00, 0x11}
)

func genMatchers() []openflow15.MatchField {
	m := generateMatch(openflow.PacketSamplingMark.GetRegID(), testTagData)
	matchers := []openflow15.MatchField{m}
	return matchers
}

func generateMatch(regID int, data []byte) openflow15.MatchField {
	baseData := make([]byte, 8, 8)
	if regID%2 == 0 {
		copy(baseData[0:4], data)
	} else {
		copy(baseData[4:8], data)
	}
	return openflow15.MatchField{
		Class: openflow15.OXM_CLASS_PACKET_REGS,
		// convert reg (4-byte) ID to xreg (8-byte) ID
		Field:   uint8(regID / 2),
		HasMask: false,
		Value:   &openflow15.ByteArrayField{Data: baseData},
	}
}

func getTestPacketBytes(dstIP string, dscp int8) []byte {
	ipPacket := &protocol.IPv4{
		Version:  0x4,
		IHL:      5,
		Protocol: uint8(8),
		DSCP:     uint8(dscp),
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

func generateTestPsState(name string, writer *pcapgo.NgWriter, num int32) *packetSamplingState {
	return &packetSamplingState{
		name:                  name,
		maxNumCapturedPackets: maxNum,
		numCapturedPackets:    num,
		tag:                   testTag,
		pcapngWriter:          writer,
		shouldSyncPackets:     true,
		updateRateLimiter:     rate.NewLimiter(rate.Every(samplingStatusUpdatePeriod), 1),
	}
}

func generatePacketSampling(name string) *crdv1alpha1.PacketSampling {
	return &crdv1alpha1.PacketSampling{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(testUID),
		},
		Status: crdv1alpha1.PacketSamplingStatus{
			DataplaneTag: int8(testTag),
		},
		Spec: crdv1alpha1.PacketSamplingSpec{
			FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
				Number: 5,
			},
			FileServer: crdv1alpha1.BundleFileServer{
				URL: testSFTPUrl,
			},
			Authentication: crdv1alpha1.BundleServerAuthConfiguration{
				AuthType: crdv1alpha1.BasicAuthentication,
				AuthSecret: &v1.SecretReference{
					Name:      "AAA",
					Namespace: "default",
				},
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
}

func (uploader *testUploader) Upload(url string, fileName string, config *ssh.ClientConfig, outputFile afero.File) error {
	klog.Info("Called test uploader")
	return nil
}

func TestHandlePacketSamplingPacketIn(t *testing.T) {

	invalidPktBytes := getTestPacketBytes("89.207.132.170", 0)
	pktBytesPodToPod := getTestPacketBytes(pod2IPv4, testTag)

	// create test os
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll("/tmp/packetsampling/packets", 0755)
	file, err := defaultFS.Create(uidToPath(testUID))
	if err != nil {
		t.Fatal("create pcapng file error: ", err)
	}

	testWriter, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("create test pcapng writer failed: ", err)
	}

	tests := []struct {
		name           string
		networkConfig  *config.NetworkConfig
		nodeConfig     *config.NodeConfig
		psState        *packetSamplingState
		pktIn          *ofctrl.PacketIn
		expectedPS     *crdv1alpha1.PacketSampling
		expectedErrStr string
		expectedCalls  func(mockOFClient *openflowtest.MockClient)
		expectedNum    int32
	}{
		{
			name:       "unrelated packets",
			psState:    generateTestPsState("ps-with-invalid-packet", testWriter, 0),
			expectedPS: generatePacketSampling("ps-with-invalid-packet"),
			pktIn: &ofctrl.PacketIn{
				PacketIn: &openflow15.PacketIn{
					Data: util.NewBuffer(invalidPktBytes),
				},
			},
			expectedErrStr: "parsePacketIn error: PacketSampling for dataplane tag 0 not found in cache",
		},
		{
			name:        "not hitting target number",
			psState:     generateTestPsState("ps-with-less-num", testWriter, 1),
			expectedPS:  generatePacketSampling("ps-with-less-num"),
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
			psState:     generateTestPsState("ps-with-max-num", testWriter, maxNum-1),
			expectedPS:  generatePacketSampling("ps-with-max-num"),
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
				mockOFClient.EXPECT().UninstallPacketSamplingFlows(uint8(testTag))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			psc := newFakePacketSamplingController(t, nil, []runtime.Object{tt.expectedPS}, nil, &config.NodeConfig{Name: "node1"})
			if tt.expectedCalls != nil {
				tt.expectedCalls(psc.mockOFClient)
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			psc.crdInformerFactory.Start(stopCh)
			psc.crdInformerFactory.WaitForCacheSync(stopCh)
			psc.runningPacketSamplings[tt.expectedPS.Status.DataplaneTag] = tt.psState

			err := psc.HandlePacketIn(tt.pktIn)
			if err == nil {
				assert.Equal(t, tt.expectedErrStr, "")
				// check target num in status
				ps, err := psc.crdClient.CrdV1alpha1().PacketSamplings().Get(context.TODO(), tt.expectedPS.Name, metav1.GetOptions{})
				assert.Nil(t, err)
				assert.Equal(t, tt.expectedNum, ps.Status.NumCapturedPackets)
			} else {
				assert.Equal(t, tt.expectedErrStr, err.Error())
			}

		})
	}
}

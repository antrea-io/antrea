// Copyright 2023 Antrea Authors
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

package ovsctl

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"
)

var (
	testDatapath1 = []byte(
		`system@ovs-system:
lookups: hit:37994604 missed:218759 lost:0
flows: 5
masks: hit:39862430 total:5 hit/pkt:1.04
port 0: ovs-system (internal)
port 1: vbr0 (internal)
port 2: gre_sys (gre)
port 3: net2`)
	testDatapath2 = []byte(
		`system@ovs-system:
lookups: hit:37994604 missed:218759 lost:0
flows: 5
masks: hit:39862430 total:5 hit/pkt:1.04
port 1: vbr0 (internal)
port 2: gre_sys (gre)
port 3: net2`)
	testDumpFlows = []string{
		"cookie=0xa000000000000, duration=13489003.061s, table=0, priority=200, n_packets=143, n_bytes=6006, idle_age=15512, hard_age=65534,arp actions=resubmit(,1)",
		"cookie=0xa010000000000, duration=13489003.042s, table=1, priority=200, n_packets=12, n_bytes=504, idle_age=17282, hard_age=65534,arp,in_port=2,arp_spa=192.168.1.1,arp_sha=16:92:82:a4:69:50 actions=resubmit(,2)",
		"cookie=0xa000000000000, duration=13489003.061s, table=2, priority=0, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, actions=drop",
		"cookie=0xa010000000000, duration=13489003.042s, table=3, priority=200, n_packets=29233419, n_bytes=2703471860, idle_age=8, hard_age=65534,in_port=2 actions=load:0x2->NXM_NX_REG0[0..3],resubmit(,4)",
		"cookie=0xa010000000000, duration=13489003.042s, table=3, priority=200, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534,in_port=1 actions=load:0x1->reg0",
	}
	testDumpFlowsWithoutTableNames = []string{
		"cookie=0xa000000000000, duration=13489003.061s, table=0, priority=200, n_packets=143, n_bytes=6006, idle_age=15512, hard_age=65534,arp actions=resubmit(,1)",
		"cookie=0xa010000000000, duration=13489003.042s, table=1, priority=200, n_packets=12, n_bytes=504, idle_age=17282, hard_age=65534,arp,in_port=2,arp_spa=192.168.1.1,arp_sha=16:92:82:a4:69:50 actions=resubmit(,2)",
		"cookie=0xa010000000000, duration=13489003.042s, table=3, priority=200, n_packets=29233419, n_bytes=2703471860, idle_age=8, hard_age=65534,in_port=2 actions=load:0x2->NXM_NX_REG0[0..3],resubmit(,4)",
	}
	testDumpGroups = []string{
		"",
		"group_id=1,type=select,bucket=bucket_id:1,weight:100,actions=load:0xa0a0002->NXM_NX_REG3[],load:0x23c1->NXM_NX_REG4[0..15],resubmit(,EndpointDNAT),bucket=bucket_id:2,weight:100,actions=load:0xa0a0007->NXM_NX_REG3[],load:0x23c1->NXM_NX_REG4[0..15],resubmit(,EndpointDNAT)",
		"group_id=2,type=indirect,bucket=bucket_id:1,mod_dl_src=00:00:00:99:11:11,mod_dl_dst=00:00:00:99:22:22,output:2",
		"group_id=3,type=select,bucket=bucket_id:1,output:1,bucket=bucket_id:2,output:2,bucket=bucket_id:3,output:3,bucket=bucket_id:4,output:4",
		"group_id=4,type=ff,bucket=bucket_id:1,watch_port:2,watch_group:2,output:3,bucket=bucket_id:2,watch_port:3,watch_group:3,output:4",
	}
	testDumpPortsDesc = []string{
		"OFPST_PORT_DESC reply (xid=0x2):",
		"1(p2p1): addr:b8:59:9f:d2:1c:ba",
		"     config:     0",
		"     state:      0",
		"    current:    AUTO_NEG",
		"     advertised: 1GB-FD 10GB-FD AUTO_NEG",
		"    supported:  1GB-FD 10GB-FD AUTO_NEG AUTO_PAUSE",
		"     speed: 0 Mbps now, 10000 Mbps max",
		"2(vnet0): addr:fe:54:00:11:8f:ea",
		"     config:     0",
		"     state:      0",
		"     current:    10MB-FD COPPER",
		"    speed: 10 Mbps now, 0 Mbps max",
		"LOCAL(ovs_pvp_br0): addr:b8:59:9f:d2:1c:ba",
		"     config:     PORT_DOWN",
		"     state:      LINK_DOWN",
		"     speed: 0 Mbps now, 0 Mbps max",
	}
)

func TestOvsCtlClientGetDPFeatures(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockOVSAppctlRunner := NewMockOVSAppctlRunner(ctrl)
	tests := []struct {
		name   string
		output string
		want   map[DPFeature]bool
	}{
		{
			name: "fully supported",
			output: `Masked set action: Yes
Tunnel push pop: No
Ufid: Yes
Truncate action: Yes
Clone action: No
Sample nesting: 10
Conntrack eventmask: Yes
Conntrack clear: Yes
Max dp_hash algorithm: 0
Check pkt length action: No
Conntrack timeout policy: No
Explicit Drop action: No
Optimized Balance TCP mode: No
Max VLAN headers: 2
Max MPLS depth: 1
Recirc: Yes
CT state: Yes
CT zone: Yes
CT mark: Yes
CT label: Yes
CT state NAT: Yes
CT orig tuple: Yes
CT orig tuple for IPv6: Yes
IPv6 ND Extension: No`,
			want: map[DPFeature]bool{
				CTStateFeature:    true,
				CTZoneFeature:     true,
				CTMarkFeature:     true,
				CTLabelFeature:    true,
				CTStateNATFeature: true,
			},
		},
		{
			name: "partially supported",
			output: `Masked set action: Yes
Tunnel push pop: No
Ufid: Yes
Truncate action: No
Clone action: No
Sample nesting: 3
Conntrack eventmask: No
Conntrack clear: No
Max dp_hash algorithm: 0
Check pkt length action: No
Conntrack timeout policy: No
Explicit Drop action: No
Optimized Balance TCP mode: No
Max VLAN headers: 1
Max MPLS depth: 1
Recirc: Yes
CT state: Yes
CT zone: Yes
CT mark: Yes
CT label: Yes
CT state NAT: No
CT orig tuple: No
CT orig tuple for IPv6: No
IPv6 ND Extension: No`,
			want: map[DPFeature]bool{
				CTStateFeature:    true,
				CTZoneFeature:     true,
				CTMarkFeature:     true,
				CTLabelFeature:    true,
				CTStateNATFeature: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ovsCtlClient{
				bridge:          "br-int",
				ovsAppctlRunner: mockOVSAppctlRunner,
			}
			mockOVSAppctlRunner.EXPECT().RunAppctlCmd("dpif/show-dp-features", true).Return([]byte(tt.output), nil)
			got, err := c.GetDPFeatures()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrace(t *testing.T) {
	srcMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	dstMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	srcIP := net.ParseIP("1.1.1.2")
	dstIP := net.ParseIP("2.2.2.2")
	tc := []struct {
		name          string
		req           *TracingRequest
		expectedFlow  string
		expectedError string
	}{
		{
			name: "Trace IP Packet-success",
			req: &TracingRequest{
				InPort:              "3",
				SrcIP:               srcIP,
				DstIP:               dstIP,
				SrcMAC:              srcMAC,
				DstMAC:              dstMAC,
				Flow:                "in_port=3,tcp,tcp_dst=22,",
				AllowOverrideInPort: true,
			},
			expectedFlow: "dl_src=11:11:11:11:11:11,dl_dst=11:11:11:11:11:22,in_port=3,tcp,tcp_dst=22,,nw_ttl=64,nw_src=1.1.1.2,nw_dst=2.2.2.2,",
		},
		{
			name: "no-ops due to source and destination IP error for non-IP packet",
			req: &TracingRequest{
				InPort: "9",
				SrcIP:  srcIP,
				Flow:   "table=10, n_packets=0, n_bytes=0, priority=200,arp,actions=resubmit(,20)",
			},
			expectedError: "source and destination must not be specified for non-IP packet",
		},
		{
			name: "no-ops due to duplicated source IP error",
			req: &TracingRequest{
				InPort: "9",
				SrcIP:  srcIP,
				Flow:   "nw_src=1.1.1.2,tcp,tcp_dst=22,",
			},
			expectedError: "duplicated 'nw_src' in flow",
		},
		{
			name: "no-ops due to duplicated destination IP error",
			req: &TracingRequest{
				InPort: "9",
				DstIP:  dstIP,
				Flow:   "nw_dst=2.2.2.2,tcp,tcp_dst=22,",
			},
			expectedError: "duplicated 'nw_dst' in flow",
		},
		{
			name: "no-ops due to duplicated in_port error",
			req: &TracingRequest{
				InPort:              "9",
				Flow:                "in_port=3,tcp,tcp_dst=22,",
				AllowOverrideInPort: false,
			},
			expectedError: "duplicated 'in_port' in flow",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockOVSAppctlRunner := NewMockOVSAppctlRunner(ctrl)
			client := &ovsCtlClient{
				bridge:          "br-int",
				ovsAppctlRunner: mockOVSAppctlRunner,
			}
			if tt.expectedFlow != "" {
				mockOVSAppctlRunner.EXPECT().RunAppctlCmd("ofproto/trace", true, tt.expectedFlow)
			}
			_, err := client.Trace(tt.req)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDeleteDPInterface(t *testing.T) {
	t.Run("delete interface", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSAppctlRunner := NewMockOVSAppctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:          "br-int",
			ovsAppctlRunner: mockOVSAppctlRunner,
		}
		mockOVSAppctlRunner.EXPECT().RunAppctlCmd("dpctl/show ovs-system", false).Return(testDatapath1, nil)
		mockOVSAppctlRunner.EXPECT().RunAppctlCmd("dpctl/del-if ovs-system 0", false).Return([]byte{}, nil)
		err := client.DeleteDPInterface("ovs-system")
		require.NoError(t, err)
	})
	t.Run("unknown interface", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSAppctlRunner := NewMockOVSAppctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:          "br-int",
			ovsAppctlRunner: mockOVSAppctlRunner,
		}
		mockOVSAppctlRunner.EXPECT().RunAppctlCmd("dpctl/show ovs-system", false).Return(testDatapath2, nil)
		err := client.DeleteDPInterface("ovs-system")
		require.NoError(t, err)
	})
}

func TestOfCtl(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	t.Run("Dump Flows", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpFlows := func() ([]byte, error) {
			return []byte(strings.Join(testDumpFlows, "\n")), nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-flows", "--names").Return(DumpFlows())
		got, err := client.DumpFlows()
		require.NoError(err)
		expectedFlows := []string{
			"table=0, priority=200, n_packets=143, n_bytes=6006, idle_age=15512, hard_age=65534,arp actions=resubmit(,1)",
			"table=1, priority=200, n_packets=12, n_bytes=504, idle_age=17282, hard_age=65534,arp,in_port=2,arp_spa=192.168.1.1,arp_sha=16:92:82:a4:69:50 actions=resubmit(,2)",
			"table=2, priority=0, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, actions=drop",
			"table=3, priority=200, n_packets=29233419, n_bytes=2703471860, idle_age=8, hard_age=65534,in_port=2 actions=load:0x2->NXM_NX_REG0[0..3],resubmit(,4)",
			"table=3, priority=200, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534,in_port=1 actions=load:0x1->reg0",
		}
		assert.Equal(expectedFlows, got)
	})
	t.Run("Dump Flows Without Table Names", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpFlowsWithoutTableNames := func() ([]byte, error) {
			return []byte(strings.Join(testDumpFlowsWithoutTableNames, "\n")), nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-flows", "--no-names").Return(DumpFlowsWithoutTableNames())
		got, err := client.DumpFlowsWithoutTableNames()
		require.NoError(err)
		expectedFlows := []string{
			"table=0, priority=200, n_packets=143, n_bytes=6006, idle_age=15512, hard_age=65534,arp actions=resubmit(,1)",
			"table=1, priority=200, n_packets=12, n_bytes=504, idle_age=17282, hard_age=65534,arp,in_port=2,arp_spa=192.168.1.1,arp_sha=16:92:82:a4:69:50 actions=resubmit(,2)",
			"table=3, priority=200, n_packets=29233419, n_bytes=2703471860, idle_age=8, hard_age=65534,in_port=2 actions=load:0x2->NXM_NX_REG0[0..3],resubmit(,4)",
		}
		assert.Equal(expectedFlows, got)
	})
	t.Run("Dump Matched Flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpMatchedFlow := func() ([]byte, error) {
			return []byte(strings.Join(testDumpFlows, "\n")), nil
		}
		matchFlow := "cookie=0xa000000000000, duration=13489003.061s, table=2, priority=0, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, actions=drop"
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-flows", matchFlow, "--names").Return(DumpMatchedFlow())
		out, err := client.DumpMatchedFlow(matchFlow)
		require.NoError(err)
		expectedFlow := "table=2, priority=0, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, actions=drop"
		assert.Equal(expectedFlow, out)

	})
	t.Run("Dump Table Flows", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpTableFlows := func() ([]byte, error) {
			var x = []byte{}
			table := "table=3"
			for i := 0; i < len(testDumpFlows); i++ {
				if !strings.Contains(testDumpFlows[i], table) {
					continue
				}
				x = append(x, []byte(testDumpFlows[i])...)
				x = append(x, "\n"...)
			}
			return x, nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-flows", []string{"table=3", "--names"}).Return(DumpTableFlows())
		out, err := client.DumpTableFlows(uint8(3))
		require.NoError(err)
		expectedFlows := []string{
			"table=3, priority=200, n_packets=29233419, n_bytes=2703471860, idle_age=8, hard_age=65534,in_port=2 actions=load:0x2->NXM_NX_REG0[0..3],resubmit(,4)",
			"table=3, priority=200, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534,in_port=1 actions=load:0x1->reg0",
		}
		assert.Equal(expectedFlows, out)
	})
	t.Run("Dump Groups", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpGroups := func() ([]byte, error) {
			return []byte(strings.Join(testDumpGroups, "\n")), nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-groups").Return(DumpGroups())
		out, err := client.DumpGroups()
		require.NoError(err)
		expectedGroups := []string{
			"group_id=1,type=select,bucket=bucket_id:1,weight:100,actions=load:0xa0a0002->NXM_NX_REG3[],load:0x23c1->NXM_NX_REG4[0..15],resubmit(,EndpointDNAT),bucket=bucket_id:2,weight:100,actions=load:0xa0a0007->NXM_NX_REG3[],load:0x23c1->NXM_NX_REG4[0..15],resubmit(,EndpointDNAT)",
			"group_id=2,type=indirect,bucket=bucket_id:1,mod_dl_src=00:00:00:99:11:11,mod_dl_dst=00:00:00:99:22:22,output:2",
			"group_id=3,type=select,bucket=bucket_id:1,output:1,bucket=bucket_id:2,output:2,bucket=bucket_id:3,output:3,bucket=bucket_id:4,output:4",
			"group_id=4,type=ff,bucket=bucket_id:1,watch_port:2,watch_group:2,output:3,bucket=bucket_id:2,watch_port:3,watch_group:3,output:4",
		}
		assert.Equal(expectedGroups, out)
	})
	t.Run("Dump Group", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		groupID := 3
		DumpGroup := func(id string) ([]byte, error) {
			var x = []byte{}
			for i := 0; i < len(testDumpGroups); i++ {
				if !strings.Contains(testDumpGroups[i], id) {
					continue
				}
				x = append(x, []byte(testDumpGroups[i])...)
				x = append(x, "\n"...)
			}
			return x, nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-groups", strconv.FormatUint(uint64(groupID), 10)).Return(DumpGroup(fmt.Sprintf("%d", groupID)))
		out, err := client.DumpGroup(uint32(groupID))
		require.NoError(err)
		expectedGroup := "group_id=3,type=select,bucket=bucket_id:1,output:1,bucket=bucket_id:2,output:2,bucket=bucket_id:3,output:3,bucket=bucket_id:4,output:4"
		assert.Equal(expectedGroup, out)
	})
	t.Run("Dump Ports Desc", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockOVSOfctlRunner := NewMockOVSOfctlRunner(ctrl)
		client := &ovsCtlClient{
			bridge:         "br-int",
			ovsOfctlRunner: mockOVSOfctlRunner,
		}
		DumpPortsDesc := func() ([]byte, error) {
			return []byte(strings.Join(testDumpPortsDesc, "\n")), nil
		}
		mockOVSOfctlRunner.EXPECT().RunOfctlCmd("dump-ports-desc").Return(DumpPortsDesc())
		out, err := client.DumpPortsDesc()
		require.NoError(err)
		expectedDesc := [][]string([][]string{
			{
				"1(p2p1): addr:b8:59:9f:d2:1c:ba",
				"     config:     0", "     state:      0",
				"    current:    AUTO_NEG",
				"     advertised: 1GB-FD 10GB-FD AUTO_NEG",
				"    supported:  1GB-FD 10GB-FD AUTO_NEG AUTO_PAUSE",
				"     speed: 0 Mbps now, 10000 Mbps max",
			},
			{
				"2(vnet0): addr:fe:54:00:11:8f:ea",
				"     config:     0", "     state:      0",
				"     current:    10MB-FD COPPER",
				"    speed: 10 Mbps now, 0 Mbps max",
			},
			{
				"LOCAL(ovs_pvp_br0): addr:b8:59:9f:d2:1c:ba",
				"     config:     PORT_DOWN",
				"     state:      LINK_DOWN",
				"     speed: 0 Mbps now, 0 Mbps max",
			},
		})
		assert.Equal(expectedDesc, out)
	})
}

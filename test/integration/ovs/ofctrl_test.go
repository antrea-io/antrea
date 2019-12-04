// Copyright 2019 Antrea Authors
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

package ovs

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

var (
	br                            = "br02"
	tableID   binding.TableIDType = 1
	nextTable binding.TableIDType = 2
	maxRetry                      = 5

	table binding.Table

	priorityNormal = uint16(200)

	portFoundMark = uint32(0x1)
	portCacheReg  = 1

	marksReg               = 0
	markTrafficFromLocal   = uint32(2)
	markTrafficFromGateway = uint32(1)
	gatewayCTMark          = uint32(0x20)
	ctZone                 = 0xfff0

	ofportRegRange  = binding.Range{0, 31}
	ofportMarkRange = binding.Range{16, 16}

	count uint64

	podIP             = net.ParseIP("192.168.1.3")
	podMAC, _         = net.ParseMAC("aa:aa:aa:aa:aa:13")
	podOFport         = uint32(3)
	gwOFPort          = uint32(1)
	_, serviceCIDR, _ = net.ParseCIDR("172.16.0.0/16")

	gwMAC, _         = net.ParseMAC("aa:aa:aa:aa:aa:11")
	gwIP             = net.ParseIP("192.168.1.1")
	_, peerSubnet, _ = net.ParseCIDR("192.168.2.0/24")
	tunnelPeer       = net.ParseIP("10.1.1.2")
	peerGW           = net.ParseIP("192.168.2.1")
	vMAC, _          = net.ParseMAC("aa:bb:cc:dd:ee:ff")
)

func TestDeleteFlowStrict(t *testing.T) {
	err := PrepareOVSBridge(br)
	if err != nil {
		t.Fatalf("Failed to prepare OVS bridge: %v", br)
	}
	defer func() {
		err = DeleteOVSBridge(br)
		if err != nil {
			t.Errorf("error while deleting OVS bridge: %v", err)
		}
	}()

	bridge := binding.NewOFBridge(br)
	table = bridge.CreateTable(tableID, nextTable, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	if err != nil {
		t.Fatal("Failed to start OFService")
	}
	defer bridge.Disconnect()

	flows, expectFlows := prepareOverlapFlows("1.1.1.1", true)
	testDeleteSingleFlow(t, flows, expectFlows)

	flows2, expectFlows2 := prepareOverlapFlows("2.2.2.2", false)
	testDeleteSingleFlow(t, flows2, expectFlows2)
}

func prepareOverlapFlows(ipStr string, sameCookie bool) ([]binding.Flow, []*ExpectFlow) {
	srcIP := net.ParseIP(ipStr)
	cookie1 := getCookieID()
	var cookie2 uint64
	if sameCookie {
		cookie2 = cookie1
	} else {
		cookie2 = getCookieID()
	}
	flows := []binding.Flow{
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(cookie1).
			Action().Drop().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(cookie2).
			MatchSrcIP(srcIP).
			Action().ResubmitToTable(nextTable).
			Done(),
	}
	expectFlows := []*ExpectFlow{
		{"priority=200,ip", "drop"},
		{fmt.Sprintf("priority=200,ip,nw_src=%s", ipStr), "resubmit(,2)"},
	}
	return flows, expectFlows
}

func testDeleteSingleFlow(t *testing.T, flows []binding.Flow, expectFlows []*ExpectFlow) {
	for id, flow := range flows {
		if err := flow.Add(); err != nil {
			t.Fatalf("Failed to install flow%d: %v", id, err)
		}
	}
	dumpTable := uint8(tableID)
	CheckFlowExists(t, br, dumpTable, true, expectFlows)

	err := flows[0].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, br, dumpTable, false, []*ExpectFlow{expectFlows[0]})
	flowList := CheckFlowExists(t, br, dumpTable, true, []*ExpectFlow{expectFlows[1]})
	if len(flowList) != 1 {
		t.Errorf("Failed to delete flow with strict mode")
	}
	err = flows[1].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, br, dumpTable, false, []*ExpectFlow{expectFlows[1]})
}

func TestOFctrlFlow(t *testing.T) {
	err := PrepareOVSBridge(br)
	if err != nil {
		t.Fatalf("Failed to prepare OVS bridge: %v", err)
	}
	defer func() {
		err = DeleteOVSBridge(br)
		if err != nil {
			t.Errorf("error while deleting OVS bridge: %v", err)
		}
	}()

	bridge := binding.NewOFBridge(br)
	table = bridge.CreateTable(tableID, nextTable, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	if err != nil {
		t.Fatal("Failed to start OFService")
	}
	defer bridge.Disconnect()

	flows, expectflows := prepareFlows(table)
	for id, flow := range flows {
		if err := flow.Add(); err != nil {
			t.Errorf("Failed to install flow%d: %v", id, err)
		}
	}

	dumpTable := uint8(tableID)
	flowList := CheckFlowExists(t, br, dumpTable, true, expectflows)

	// Test: DumpTableStatus
	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}

	// Test: DumpFlows
	dumpCookieID, dumpCookieMask := getCookieIDMask()
	flowStates := bridge.DumpFlows(dumpCookieID, dumpCookieMask)
	if len(flowStates) != len(flowList) {
		t.Errorf("Flow count in dump result is incorrect")
	}

	// Test: Flow.Delete
	for _, f := range flows[0:4] {
		if err := f.Delete(); err != nil {
			t.Errorf("Failed to uninstall flow1 %v", err)
		}
	}
	CheckFlowExists(t, br, dumpTable, false, expectflows[0:4])

	// Test: DeleteFlowsByCookie
	err = bridge.DeleteFlowsByCookie(dumpCookieID, dumpCookieMask)
	if err != nil {
		t.Errorf("Failed to DeleteFlowsByCookie: %v", err)
	}
	flowList, _ = OfctlDumpFlows(br, uint8(tableID))
	if len(flowList) > 0 {
		t.Errorf("Failed to delete flows by CookieID")
	}
}

func prepareFlows(table binding.Table) ([]binding.Flow, []*ExpectFlow) {
	var flows []binding.Flow
	_, AllIPs, _ := net.ParseCIDR("0.0.0.0/0")
	_, conjSrcIPNet, _ := net.ParseCIDR("192.168.3.0/24")
	flows = append(flows,
		table.BuildFlow(priorityNormal-10).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			Action().LoadRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchARPSha(podMAC).
			MatchARPSpa(podIP).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchSrcMAC(podMAC).
			MatchSrcIP(podIP).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			Cookie(getCookieID()).
			MatchARPOp(1).
			MatchARPTpa(peerGW).
			Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
			Action().SetSrcMAC(vMAC).
			Action().LoadARPOperation(2).
			Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
			Action().SetARPSha(vMAC).
			Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
			Action().SetARPSpa(peerGW).
			Action().OutputInPort().
			Done(),
		table.BuildFlow(priorityNormal-10).MatchProtocol(binding.ProtocolARP).
			Cookie(getCookieID()).
			Action().Normal().Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			Action().CT(false, nextTable, ctZone).CTDone().
			Done(),
		table.BuildFlow(priorityNormal+10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(
			true,
			nextTable,
			ctZone).
			LoadToMark(uint32(gatewayCTMark)).
			MoveToLabel(binding.NxmFieldSrcMAC, &binding.Range{0, 47}, &binding.Range{0, 47}).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().MoveRange(binding.NxmFieldCtLabel, binding.NxmFieldDstMAC, binding.Range{0, 47}, binding.Range{0, 47}).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateInv(true).
			Action().Drop().
			Done(),
		table.BuildFlow(priorityNormal-10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, nextTable, ctZone).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstMAC(vMAC).
			MatchDstIP(podIP).
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(podMAC).
			Action().DecTTL().
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIPNet(*peerSubnet).
			Action().DecTTL().
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(vMAC).
			Action().SetTunnelDst(tunnelPeer).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIP(gwIP).
			Action().SetDstMAC(gwMAC).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchDstMAC(podMAC).
			Action().LoadRegRange(portCacheReg, podOFport, ofportRegRange).
			Action().LoadRegRange(int(marksReg), portFoundMark, ofportMarkRange).
			Action().ResubmitToTable(nextTable).
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(int(marksReg), portFoundMark, ofportMarkRange).
			Action().OutputRegRange(int(portCacheReg), ofportRegRange).
			Done(), table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIPNet(*serviceCIDR).
			Action().Output(int(gwOFPort)).
			Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchTCPDstPort(uint16(8080)).
			Action().Conjunction(uint32(1001), uint8(3), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchSrcIP(podIP).
			Action().Conjunction(uint32(1001), uint8(1), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchDstIPNet(*conjSrcIPNet).
			Action().Conjunction(uint32(1001), uint8(2), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchSrcIPNet(*AllIPs).
			Action().Conjunction(uint32(1001), uint8(1), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchRegRange(int(portCacheReg), podOFport, ofportRegRange).
			Action().Conjunction(uint32(1001), uint8(2), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchConjID(1001).
			Action().ResubmitToTable(nextTable).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchConjID(1001).MatchSrcIP(gwIP).
			Action().ResubmitToTable(nextTable).Done(),
	)

	var flowStrs []*ExpectFlow
	flowStrs = append(flowStrs,
		&ExpectFlow{"priority=190,in_port=3", "load:0x2->NXM_NX_REG0[0..15],resubmit(,2)"},
		&ExpectFlow{"priority=200,arp,in_port=3,arp_spa=192.168.1.3,arp_sha=aa:aa:aa:aa:aa:13", "resubmit(,2)"},
		&ExpectFlow{"priority=200,ip,in_port=3,dl_src=aa:aa:aa:aa:aa:13,nw_src=192.168.1.3", "resubmit(,2)"},
		&ExpectFlow{"priority=200,arp,arp_tpa=192.168.2.1,arp_op=1", "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:192.168.2.1->arp_spa,IN_PORT"},
		&ExpectFlow{"priority=190,arp", "NORMAL"},
		&ExpectFlow{"priority=200,ip", "ct(table=2,zone=65520)"},
		&ExpectFlow{"priority=210,ct_state=-new+trk,ct_mark=0x20,ip,reg0=0x1/0xffff", "resubmit(,2)"},
		&ExpectFlow{"priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", "ct(commit,table=2,zone=65520,exec(load:0x20->NXM_NX_CT_MARK[],move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47]))"},
		&ExpectFlow{"priority=200,ct_state=-new+trk,ct_mark=0x20,ip", "move:NXM_NX_CT_LABEL[0..47]->NXM_OF_ETH_DST[],resubmit(,2)"},
		&ExpectFlow{"priority=200,ct_state=+new+inv,ip", "drop"},
		&ExpectFlow{"priority=190,ct_state=+new+trk,ip", "ct(commit,table=2,zone=65520)"},
		&ExpectFlow{"priority=200,ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=192.168.1.3", "set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:aa:aa:aa:aa:13->eth_dst,dec_ttl,resubmit(,2)"},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.2.0/24", "dec_ttl,set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:10.1.1.2->tun_dst,resubmit(,2)"},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.1.1", "set_field:aa:aa:aa:aa:aa:11->eth_dst,resubmit(,2)"},
		&ExpectFlow{"priority=200,dl_dst=aa:aa:aa:aa:aa:13", "load:0x3->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],resubmit(,2)"},
		&ExpectFlow{"priority=200,ip,reg0=0x10000/0x10000", "output:NXM_NX_REG1[]"},
		&ExpectFlow{"priority=200,ip,nw_dst=172.16.0.0/16", "output:1"},
		&ExpectFlow{"priority=220,tcp,tp_dst=8080", "conjunction(1001,3/3)"},
		&ExpectFlow{"priority=220,ip,nw_src=192.168.1.3", "conjunction(1001,1/3)"},
		&ExpectFlow{"priority=220,ip,nw_dst=192.168.3.0/24", "conjunction(1001,2/3)"},
		&ExpectFlow{"priority=220,ip", "conjunction(1001,1/3)"},
		&ExpectFlow{"priority=220,ip,reg1=0x3", "conjunction(1001,2/3)"},
		&ExpectFlow{"priority=220,conj_id=1001,ip", "resubmit(,2)"},
		&ExpectFlow{"priority=220,conj_id=1001,ip,nw_src=192.168.1.1", "resubmit(,2)"},
	)

	return flows, flowStrs
}

func getCookieID() uint64 {
	roundID := uint64(100) << 48
	cateID := uint64(2) << 40
	fID := atomic.AddUint64(&count, 1)
	return roundID | cateID | fID
}

func getCookieIDMask() (uint64, uint64) {
	cookieID := uint64(100)<<48 | uint64(2)<<40
	cookieMask := uint64(^uint16(0))<<48 | uint64(^uint8(0))<<40
	return cookieID, cookieMask
}

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

var (
	maxRetry = 5

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

	ipDSCP = uint8(10)
)

func newOFBridge(brName string) binding.Bridge {
	bridgeMgmtAddr := binding.GetMgmtAddress(ovsconfig.DefaultOVSRunDir, brName)
	return binding.NewOFBridge(brName, bridgeMgmtAddr)
}

func TestDeleteFlowStrict(t *testing.T) {
	br := "br02"
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

	bridge := newOFBridge(br)
	table = bridge.CreateTable(3, 4, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	if err != nil {
		t.Fatal("Failed to start OFService")
	}
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	flows, expectFlows := prepareOverlapFlows(table, "1.1.1.1", true)
	testDeleteSingleFlow(t, ovsCtlClient, table, flows, expectFlows)

	flows2, expectFlows2 := prepareOverlapFlows(table, "2.2.2.2", false)
	testDeleteSingleFlow(t, ovsCtlClient, table, flows2, expectFlows2)
}

func prepareOverlapFlows(table binding.Table, ipStr string, sameCookie bool) ([]binding.Flow, []*ExpectFlow) {
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
			Action().GotoTable(table.GetNext()).
			Done(),
	}
	expectFlows := []*ExpectFlow{
		{"priority=200,ip", "drop"},
		{fmt.Sprintf("priority=200,ip,nw_src=%s", ipStr),
			fmt.Sprintf("goto_table:%d", table.GetNext())},
	}
	return flows, expectFlows
}

func testDeleteSingleFlow(t *testing.T, ovsCtlClient ovsctl.OVSCtlClient, table binding.Table, flows []binding.Flow, expectFlows []*ExpectFlow) {
	for id, flow := range flows {
		if err := flow.Add(); err != nil {
			t.Fatalf("Failed to install flow%d: %v", id, err)
		}
	}
	dumpTable := uint8(table.GetID())
	CheckFlowExists(t, ovsCtlClient, dumpTable, true, expectFlows)

	err := flows[0].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, ovsCtlClient, dumpTable, false, []*ExpectFlow{expectFlows[0]})
	flowList := CheckFlowExists(t, ovsCtlClient, dumpTable, true, []*ExpectFlow{expectFlows[1]})
	if len(flowList) != 1 {
		t.Errorf("Failed to delete flow with strict mode")
	}
	err = flows[1].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, ovsCtlClient, dumpTable, false, []*ExpectFlow{expectFlows[1]})
}

type tableFlows struct {
	table         binding.Table
	flowGenerator func(table binding.Table) ([]binding.Flow, []*ExpectFlow)
}

func TestOFctrlFlow(t *testing.T) {
	br := "br03"
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

	bridge := newOFBridge(br)
	table1 := bridge.CreateTable(1, 2, binding.TableMissActionNext)
	table2 := bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	if err != nil {
		t.Fatal("Failed to start OFService")
	}
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	for _, test := range []tableFlows{
		{table: table1, flowGenerator: prepareFlows},
		{table: table2, flowGenerator: prepareNATflows},
	} {
		myTable := test.table
		myFunc := test.flowGenerator
		flows, expectflows := myFunc(myTable)
		for id, flow := range flows {
			if err := flow.Add(); err != nil {
				t.Errorf("Failed to install flow%d: %v", id, err)
			}
		}

		dumpTable := uint8(myTable.GetID())
		flowList := CheckFlowExists(t, ovsCtlClient, dumpTable, true, expectflows)

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
		flowStates, err := bridge.DumpFlows(dumpCookieID, dumpCookieMask)
		require.Nil(t, err, "no error returns in DumpFlows")
		if len(flowStates) != len(flowList) {
			t.Errorf("Flow count in dump result is incorrect")
		}

		// Test: Flow.Delete
		for _, f := range flows[0:2] {
			if err := f.Delete(); err != nil {
				t.Errorf("Failed to uninstall flow1 %v", err)
			}
		}
		CheckFlowExists(t, ovsCtlClient, dumpTable, false, expectflows[0:2])

		// Test: DeleteFlowsByCookie
		err = bridge.DeleteFlowsByCookie(dumpCookieID, dumpCookieMask)
		if err != nil {
			t.Errorf("Failed to DeleteFlowsByCookie: %v", err)
		}
		flowList, _ = OfctlDumpTableFlows(ovsCtlClient, uint8(myTable.GetID()))
		if len(flowList) > 0 {
			t.Errorf("Failed to delete flows by CookieID")
		}
	}
}

func TestOFctrlGroup(t *testing.T) {
	brName := "br05"
	err := PrepareOVSBridge(brName)
	if err != nil {
		t.Fatalf("Failed to prepare OVS bridge: %v", err)
	}
	defer func() {
		err = DeleteOVSBridge(brName)
		if err != nil {
			t.Errorf("error while deleting OVS bridge: %v", err)
		}
	}()

	br := newOFBridge(brName)
	err = br.Connect(maxRetry, make(chan struct{}))
	if err != nil {
		t.Fatal("Failed to start OFService")
	}
	defer br.Disconnect()

	ovsCtlClient := ovsctl.NewClient(brName)

	for name, buckets := range map[string][]struct {
		weight        uint16      // Must have non-zero value.
		reg2reg       [][4]uint32 // regNum, data, startIndex, endIndex
		resubmitTable binding.TableIDType
	}{
		"Normal": {
			{weight: 100, reg2reg: [][4]uint32{{0, 1, 0, 31}, {1, 2, 15, 31}}, resubmitTable: 31},
			{weight: 110, resubmitTable: 42},
		},
	} {
		t.Run(name, func(t *testing.T) {
			group := br.CreateGroup(1)
			for _, bucket := range buckets {
				require.NotZero(t, bucket.weight, "Weight value of a bucket must be specified")
				bucketBuilder := group.Bucket().Weight(bucket.weight)
				if bucket.resubmitTable != 0 {
					bucketBuilder = bucketBuilder.ResubmitToTable(bucket.resubmitTable)
				}
				for _, loading := range bucket.reg2reg {
					bucketBuilder = bucketBuilder.LoadRegRange(int(loading[0]), loading[1], [2]uint32{loading[2], loading[3]})
				}
				group = bucketBuilder.Done()
			}
			// Check if the group could be added.
			require.Nil(t, group.Add())
			groups, err := OfCtlDumpGroups(ovsCtlClient)
			require.Nil(t, err)
			require.Len(t, groups, 1)
			dumpedGroup := groups[0]
			for i, bucket := range buckets {
				// Must have weight
				assert.True(t, strings.Contains(dumpedGroup[i+1], fmt.Sprintf("weight:%d", bucket.weight)))
				for _, loading := range bucket.reg2reg {
					rngStr := "[]"
					if !(loading[2] == 0 && loading[3] == 31) {
						rngStr = fmt.Sprintf("[%d..%d]", loading[2], loading[3])
					}
					loadStr := fmt.Sprintf("load:0x%x->NXM_NX_REG%d%s", loading[1], loading[0], rngStr)
					assert.Contains(t, dumpedGroup[i+1], loadStr)
				}
				if bucket.resubmitTable != 0 {
					resubmitStr := fmt.Sprintf("resubmit(,%d)", bucket.resubmitTable)
					assert.Contains(t, dumpedGroup[i+1], resubmitStr)
				}
			}
			// Check if the group could be deleted.
			require.Nil(t, group.Delete())
			groups, err = OfCtlDumpGroups(ovsCtlClient)
			require.Nil(t, err)
			require.Len(t, groups, 0)
		})
	}
}

func TestTransactions(t *testing.T) {
	br := "br04"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = DeleteOVSBridge(br)
		require.Nil(t, err, fmt.Sprintf("error while deleting OVS bridge: %v", err))
	}()

	bridge := newOFBridge(br)
	table = bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	flows, expectflows := prepareFlows(table)
	err = bridge.AddFlowsInBundle(flows, nil, nil)
	require.Nil(t, err, fmt.Sprintf("Failed to add flows in a transaction: %v", err))
	dumpTable := uint8(table.GetID())
	flowList := CheckFlowExists(t, ovsCtlClient, dumpTable, true, expectflows)

	// Test: DumpTableStatus
	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}

	// Delete flows in a bundle
	err = bridge.AddFlowsInBundle(nil, nil, flows)
	require.Nil(t, err, fmt.Sprintf("Failed to delete flows in a transaction: %v", err))
	dumpTable = uint8(table.GetID())
	flowList = CheckFlowExists(t, ovsCtlClient, dumpTable, false, expectflows)

	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}

	// Invoke AddFlowsInBundle with no Flow to add/modify/delete.
	err = bridge.AddFlowsInBundle(nil, nil, nil)
	require.Nil(t, err, fmt.Sprintf("Not compatible with none flows in the request: %v", err))
	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}
}

func TestBundleErrorWhenOVSRestart(t *testing.T) {
	br := "br06"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer func() {
		err = DeleteOVSBridge(br)
		require.Nil(t, err, fmt.Sprintf("error while deleting OVS bridge: %v", err))
	}()

	bridge := newOFBridge(br)
	table = bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	// Ensure OVS is connected before sending bundle messages.
	select {
	case <-time.Tick(1 * time.Second):
		if bridge.IsConnected() {
			break
		}
	}

	// Restart OVS in another goroutine.
	go func() {
		select {
		case <-time.After(100 * time.Millisecond):
			DeleteOVSBridge(br)
			PrepareOVSBridge(br)
		}
	}()

	expectedErrorMsgs := map[string]bool{
		"bundle reply is timeout": true,
		"bundle reply is canceled because of disconnection from the Switch": true,
		"message is timeout": true,
		"message is canceled because of disconnection from the Switch": true,
	}

	var failCount, successCount int
	loop := 10000
	var wg sync.WaitGroup
	wg.Add(loop)
	i := 0
	for i < loop {
		// Sending Bundle message in parallel.
		go func() {
			defer wg.Done()
			// Sending OpenFlow messages when OVS is disconnected is not in this case's scope.
			if !bridge.IsConnected() {
				return
			}
			ch := make(chan struct{})
			go func() {
				flows := []binding.Flow{table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
					Cookie(getCookieID()).
					MatchInPort(uint32(count + 1)).
					Action().GotoTable(table.GetNext()).
					Done()}
				err = bridge.AddFlowsInBundle(flows, nil, nil)
				if err != nil {
					errMsg := err.Error()
					_, found := expectedErrorMsgs[errMsg]
					// Check if the bundle message is canceled or the Bundle reply is timeout.
					require.True(t, found, errMsg)
				}
				ch <- struct{}{}
			}()

			select {
			// Wait for Bundle timeout or canceled.
			case <-time.After(15 * time.Second):
				failCount++
			case <-ch:
				successCount++
			}
		}()
		i++
	}

	wg.Wait()
	require.Equal(t, 0, failCount, "No fail case expected")
}

// TestReconnectOFSwitch verifies that the OpenFlow connection to OVS can be restored, even when OVS is down for a long
// amount of time.
func TestReconnectOFSwitch(t *testing.T) {
	br := "br07"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	reconnectCh := make(chan struct{})
	var connectCount int
	go func() {
		for range reconnectCh {
			connectCount++
		}
	}()
	err = bridge.Connect(maxRetry, reconnectCh)
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	require.Equal(t, connectCount, 1)
	// The max delay for the initial connection is 5s. Here we assume the OVS is stopped then started after 8s, and
	// check that we can re-connect to it after that delay.
	go func() {
		DeleteOVSBridge(br)
		time.Sleep(8 * time.Second)
		err := PrepareOVSBridge(br)
		require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	}()

	err = DeleteOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to delete bridge: %v", err))
	time.Sleep(12 * time.Second)
	require.Equal(t, 2, connectCount)
}

// Verify install/uninstall Flow and its dependent Group in the same Bundle.
func TestBundleWithGroupAndFlow(t *testing.T) {
	br := "br08"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	groupID := binding.GroupIDType(4)
	group := bridge.CreateGroup(groupID).
		Bucket().Weight(100).
		LoadReg(1, uint32(0xa0a0002)).
		LoadReg(2, uint32(0x35)).
		LoadReg(3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done().
		Bucket().Weight(100).
		LoadReg(1, uint32(0xa0a0202)).
		LoadReg(2, uint32(0x35)).
		LoadReg(3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done()

	flow := table.BuildFlow(priorityNormal).
		Cookie(getCookieID()).
		MatchProtocol(binding.ProtocolTCP).
		MatchDstIP(net.ParseIP("10.96.0.10")).
		MatchDstPort(uint16(53), nil).
		MatchReg(3, uint32(0xfff2)).
		Action().Group(groupID).Done()
	expectedFlows := []*ExpectFlow{
		{
			MatchStr: "priority=200,tcp,reg3=0xfff2,nw_dst=10.96.0.10,tp_dst=53",
			ActStr:   fmt.Sprintf("group:%d", groupID),
		},
	}

	bucket0 := "weight:100,actions=load:0xa0a0002->NXM_NX_REG1[],load:0x35->NXM_NX_REG2[],load:0xfff1->NXM_NX_REG3[],resubmit(,3)"
	bucket1 := "weight:100,actions=load:0xa0a0202->NXM_NX_REG1[],load:0x35->NXM_NX_REG2[],load:0xfff1->NXM_NX_REG3[],resubmit(,3)"
	expectedGroupBuckets := []string{bucket0, bucket1}
	err = bridge.AddOFEntriesInBundle([]binding.OFEntry{flow, group}, nil, nil)
	require.Nil(t, err)
	CheckFlowExists(t, ovsCtlClient, uint8(table.GetID()), true, expectedFlows)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)

	err = bridge.AddOFEntriesInBundle(nil, nil, []binding.OFEntry{flow, group})
	require.Nil(t, err)
	CheckFlowExists(t, ovsCtlClient, uint8(table.GetID()), false, expectedFlows)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, false)
}

func TestPacketOutIn(t *testing.T) {
	br := "br09"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table0 := bridge.CreateTable(0, 1, binding.TableMissActionNext)
	table1 := bridge.CreateTable(1, 2, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	reason := uint8(1)
	pktInQueue := binding.NewPacketInQueue(200, rate.Limit(100))
	err = bridge.SubscribePacketIn(reason, pktInQueue)
	require.Nil(t, err)

	srcMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	dstcMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	srcIP := net.ParseIP("1.1.1.2")
	dstIP := net.ParseIP("2.2.2.2")
	tunDst := net.ParseIP("10.10.10.2")
	srcPort := uint16(10001)
	dstPort := uint16(8080)
	reg2Data := uint32(0x1234)
	reg2Range := binding.Range{0, 15}
	reg3Data := uint32(0x1234)
	reg3Range := binding.Range{0, 31}
	stopCh := make(chan struct{})

	go func() {
		pktIn := pktInQueue.GetRateLimited(make(chan struct{}))
		matchers := pktIn.GetMatches()

		reg2Match := matchers.GetMatchByName("NXM_NX_REG2")
		assert.NotNil(t, reg2Match)
		reg2Value := reg2Match.GetValue()
		assert.NotNil(t, reg2Value)
		value2, ok2 := reg2Value.(*ofctrl.NXRegister)
		assert.True(t, ok2)
		assert.Equal(t, reg2Data, ofctrl.GetUint32ValueWithRange(value2.Data, reg2Range.ToNXRange()))

		reg3Match := matchers.GetMatchByName("NXM_NX_REG3")
		assert.NotNil(t, reg3Match)
		reg3Value := reg3Match.GetValue()
		assert.NotNil(t, reg3Value)
		value3, ok3 := reg3Value.(*ofctrl.NXRegister)
		assert.True(t, ok3)
		assert.Equal(t, reg3Data, value3.Data)

		tunDstMatch := matchers.GetMatchByName("NXM_NX_TUN_IPV4_DST")
		assert.NotNil(t, tunDstMatch)
		tunDstValue := tunDstMatch.GetValue()
		assert.NotNil(t, tunDstValue)
		value4, ok4 := tunDstValue.(net.IP)
		assert.True(t, ok4)
		assert.Equal(t, tunDst, value4)

		close(stopCh)
	}()

	pktBuilder := bridge.BuildPacketOut()
	pkt := pktBuilder.SetSrcMAC(srcMAC).SetDstMAC(dstcMAC).
		SetDstIP(dstIP).SetSrcIP(srcIP).SetIPProtocol(binding.ProtocolTCP).
		SetTCPSrcPort(srcPort).SetTCPDstPort(dstPort).
		AddLoadAction("NXM_NX_REG0", uint64(0x1), binding.Range{18, 18}).
		Done()
	require.Nil(t, err)
	flow0 := table0.BuildFlow(100).
		MatchSrcMAC(srcMAC).MatchDstMAC(dstcMAC).
		MatchSrcIP(srcIP).MatchDstIP(dstIP).MatchProtocol(binding.ProtocolTCP).
		MatchRegRange(0, 0x1, binding.Range{18, 18}).
		Action().LoadRegRange(2, reg2Data, reg2Range).
		Action().LoadRegRange(3, reg3Data, reg3Range).
		Action().SetTunnelDst(tunDst).
		Action().ResubmitToTable(table0.GetNext()).
		Done()
	flow1 := table1.BuildFlow(100).
		MatchSrcMAC(srcMAC).MatchDstMAC(dstcMAC).
		MatchSrcIP(srcIP).MatchDstIP(dstIP).MatchProtocol(binding.ProtocolTCP).
		MatchRegRange(0, 0x1, binding.Range{18, 18}).
		Action().SendToController(0x1).
		Done()
	err = bridge.AddFlowsInBundle([]binding.Flow{flow0, flow1}, nil, nil)
	require.Nil(t, err)
	err = bridge.SendPacketOut(pkt)
	require.NoError(t, err)
	<-stopCh
}

func TestTLVMap(t *testing.T) {
	br := "br10"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table := bridge.CreateTable(0, 1, binding.TableMissActionNext)

	ch := make(chan struct{})
	err = bridge.Connect(maxRetry, ch)
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	// Wait until the OVS Bridge is connected.
	<-ch

	err = bridge.AddTLVMap(0xffff, 0x1, 4, 0)
	require.Nil(t, err)
	time.Sleep(1 * time.Second)
	flow1 := table.BuildFlow(100).
		MatchProtocol(binding.ProtocolIP).MatchTunMetadata(0, 0x1234).
		Action().ResubmitToTable(table.GetNext()).
		Done()
	err = bridge.AddFlowsInBundle([]binding.Flow{flow1}, nil, nil)
	require.Nil(t, err)
	expectedFlows := []*ExpectFlow{
		{
			MatchStr: "priority=100,ip,tun_metadata0=0x1234",
			ActStr:   fmt.Sprintf("resubmit(,%d)", table.GetNext()),
		},
	}
	ovsCtlClient := ovsctl.NewClient(br)
	CheckFlowExists(t, ovsCtlClient, uint8(table.GetID()), true, expectedFlows)
}

func TestMoveTunMetadata(t *testing.T) {
	br := "br11"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	//defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table := bridge.CreateTable(0, 1, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	err = bridge.AddTLVMap(0xffff, 0x1, 4, 0)
	require.Nil(t, err)
	time.Sleep(1 * time.Second)
	flow1 := table.BuildFlow(100).
		MatchProtocol(binding.ProtocolIP).MatchTunMetadata(0, 0x1234).
		Action().MoveRange("NXM_NX_TUN_METADATA0", "NXM_NX_REG0", binding.Range{28, 31}, binding.Range{28, 31}).
		Action().ResubmitToTable(table.GetNext()).
		Done()
	err = bridge.AddFlowsInBundle([]binding.Flow{flow1}, nil, nil)
	require.Nil(t, err)
	expectedFlows := []*ExpectFlow{
		{
			MatchStr: "priority=100,ip,tun_metadata0=0x1234",
			ActStr:   fmt.Sprintf("move:NXM_NX_TUN_METADATA0[28..31]->NXM_NX_REG0[28..31],resubmit(,%d)", table.GetNext()),
		},
	}
	ovsCtlClient := ovsctl.NewClient(br)
	CheckFlowExists(t, ovsCtlClient, uint8(table.GetID()), true, expectedFlows)
}

func TestFlowWithCTMatchers(t *testing.T) {
	br := "br09"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ofctlClient := ovsctl.NewClient(br)
	ctIpSrc, ctIpSrcNet, _ := net.ParseCIDR("1.1.1.1/24")
	ctIpDst, ctIpDstNet, _ := net.ParseCIDR("2.2.2.2/24")
	ctPortSrc := uint16(10001)
	ctPortDst := uint16(20002)
	priority := uint16(200)
	flow1 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(true).
		MatchCTSrcIP(ctIpSrc).
		MatchCTDstIP(ctIpDst).
		MatchCTSrcPort(ctPortSrc).
		MatchCTDstPort(ctPortDst).
		MatchCTProtocol(binding.ProtocolTCP).
		Action().ResubmitToTable(table.GetNext()).
		Done()
	flow2 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchCTStateEst(true).
		MatchCTSrcIPNet(*ctIpSrcNet).
		MatchCTDstIPNet(*ctIpDstNet).
		MatchCTProtocol(binding.ProtocolTCP).
		Action().ResubmitToTable(table.GetNext()).
		Done()
	expectFlows := []*ExpectFlow{
		{fmt.Sprintf("priority=%d,ct_state=+new,ct_nw_src=%s,ct_nw_dst=%s,ct_nw_proto=6,ct_tp_src=%d,ct_tp_dst=%d,ip",
			priority, ctIpSrc.String(), ctIpDst.String(), ctPortSrc, ctPortDst),
			fmt.Sprintf("resubmit(,%d)", table.GetNext()),
		},
		{
			fmt.Sprintf("priority=%d,ct_state=+est,ct_nw_src=%s,ct_nw_dst=%s,ct_nw_proto=6,ip",
				priority, ctIpSrcNet.String(), ctIpDstNet.String()),
			fmt.Sprintf("resubmit(,%d)", table.GetNext()),
		},
	}
	for _, f := range []binding.Flow{flow1, flow2} {
		err = f.Add()
		assert.Nil(t, err, "no error returned when adding flow")
	}
	CheckFlowExists(t, ofctlClient, uint8(table.GetID()), true, expectFlows)
	for _, f := range []binding.Flow{flow1, flow2} {
		err = f.Delete()
		assert.Nil(t, err, "no error returned when deleting flow")
	}
	CheckFlowExists(t, ofctlClient, uint8(table.GetID()), false, expectFlows)
}

func TestNoteAction(t *testing.T) {
	br := "br10"
	err := PrepareOVSBridge(br)
	require.Nil(t, err, fmt.Sprintf("Failed to prepare OVS bridge: %v", err))
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.CreateTable(2, 3, binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.Nil(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ofctlClient := ovsctl.NewClient(br)
	priority := uint16(1001)
	srcIP := net.ParseIP("1.1.1.2")
	testNotes := "test for noteActions."
	flow1 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchSrcIP(srcIP).
		Action().Note(testNotes).
		Action().GotoTable(table.GetNext()).
		Done()

	convertNoteToHex := func(note string) string {
		byteSlice := make([]byte, (len(note)/8)*8+6)
		copy(byteSlice, note)
		var bytesStrs []string
		for i := range byteSlice {
			if byteSlice[i] < 16 {
				bytesStrs = append(bytesStrs, fmt.Sprintf("0%x", byteSlice[i]))
			} else {
				bytesStrs = append(bytesStrs, fmt.Sprintf("%x", byteSlice[i]))
			}
		}
		return strings.Join(bytesStrs, ".")
	}
	notesStr := convertNoteToHex(testNotes)
	expectFlows := []*ExpectFlow{
		{fmt.Sprintf("priority=%d,ip,nw_src=%s", priority, srcIP.String()),
			fmt.Sprintf("note:%s,goto_table:%d", notesStr, table.GetNext())},
	}

	err = flow1.Add()
	assert.Nil(t, err, "expected no error when adding flow")
	CheckFlowExists(t, ofctlClient, uint8(table.GetID()), true, expectFlows)
	err = flow1.Delete()
	assert.Nil(t, err, "expected no error when deleting flow")
	CheckFlowExists(t, ofctlClient, uint8(table.GetID()), false, expectFlows)
}

func prepareFlows(table binding.Table) ([]binding.Flow, []*ExpectFlow) {
	var flows []binding.Flow
	_, AllIPs, _ := net.ParseCIDR("0.0.0.0/0")
	_, conjSrcIPNet, _ := net.ParseCIDR("192.168.3.0/24")
	gwMACData, _ := strconv.ParseUint(strings.Replace(gwMAC.String(), ":", "", -1), 16, 64)
	_, peerSubnetIPv6, _ := net.ParseCIDR("fd74:ca9b:172:21::/64")
	tunnelPeerIPv6 := net.ParseIP("20:ca9b:172:35::3")
	flows = append(flows,
		table.BuildFlow(priorityNormal-10).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			Action().LoadRegRange(int(marksReg), markTrafficFromLocal, binding.Range{0, 15}).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchARPSha(podMAC).
			MatchARPSpa(podIP).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchSrcMAC(podMAC).
			MatchSrcIP(podIP).
			Action().GotoTable(table.GetNext()).
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
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolTCP).
			Cookie(getCookieID()).
			Action().Learn(table.GetID(), priorityNormal-10, 10, 0, 1).
			DeleteLearned().
			MatchLearnedTCPDstPort().
			MatchReg(0, 0x0fff, binding.Range{0, 15}).
			LoadRegToReg(0, 0, binding.Range{0, 15}, binding.Range{0, 15}).
			LoadReg(0, 0x0ffe, binding.Range{16, 31}).
			Done(). // Finish learn action.
			Action().ResubmitToTable(table.GetID()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			Action().CT(false, table.GetNext(), ctZone).CTDone().
			Done(),
		table.BuildFlow(priorityNormal+10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTMark(gatewayCTMark, nil).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegRange(int(marksReg), markTrafficFromGateway, binding.Range{0, 15}).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(
			true,
			table.GetNext(),
			ctZone).
			LoadToMark(uint32(gatewayCTMark)).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTMark(gatewayCTMark, nil).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().LoadRange(binding.NxmFieldDstMAC, gwMACData, binding.Range{0, 47}).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateInv(true).
			Action().Drop().
			Done(),
		table.BuildFlow(priorityNormal-10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, table.GetNext(), ctZone).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstMAC(vMAC).
			MatchDstIP(podIP).
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(podMAC).
			Action().DecTTL().
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIPNet(*peerSubnet).
			Action().DecTTL().
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(vMAC).
			Action().SetTunnelDst(tunnelPeer).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			Cookie(getCookieID()).
			MatchDstIPNet(*peerSubnetIPv6).
			Action().DecTTL().
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(vMAC).
			Action().SetTunnelDst(tunnelPeerIPv6).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIP(gwIP).
			Action().SetDstMAC(gwMAC).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchDstMAC(podMAC).
			Action().LoadRegRange(portCacheReg, podOFport, ofportRegRange).
			Action().LoadRegRange(int(marksReg), portFoundMark, ofportMarkRange).
			Action().GotoTable(table.GetNext()).
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
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchProtocol(binding.ProtocolIP).
			MatchSrcIP(podIP).
			MatchIPDSCP(ipDSCP).
			Action().GotoTable(table.GetNext()).
			Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolTCP).Cookie(getCookieID()).MatchDstPort(uint16(8080), nil).
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
			Action().GotoTable(table.GetNext()).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchConjID(1001).MatchSrcIP(gwIP).
			Action().GotoTable(table.GetNext()).Done(),
	)

	gotoTableAction := fmt.Sprintf("goto_table:%d", table.GetNext())
	var flowStrs []*ExpectFlow
	flowStrs = append(flowStrs,
		&ExpectFlow{"priority=190,in_port=3", fmt.Sprintf("load:0x2->NXM_NX_REG0[0..15],%s", gotoTableAction)},
		&ExpectFlow{"priority=200,arp,in_port=3,arp_spa=192.168.1.3,arp_sha=aa:aa:aa:aa:aa:13", gotoTableAction},
		&ExpectFlow{"priority=200,ip,in_port=3,dl_src=aa:aa:aa:aa:aa:13,nw_src=192.168.1.3", gotoTableAction},
		&ExpectFlow{"priority=200,arp,arp_tpa=192.168.2.1,arp_op=1", "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:192.168.2.1->arp_spa,IN_PORT"},
		&ExpectFlow{"priority=190,arp", "NORMAL"},
		&ExpectFlow{"priority=200,tcp", fmt.Sprintf("learn(table=%d,idle_timeout=10,priority=190,delete_learned,cookie=0x1,eth_type=0x800,nw_proto=6,NXM_OF_TCP_DST[],NXM_NX_REG0[0..15]=0xfff,load:NXM_NX_REG0[0..15]->NXM_NX_REG0[0..15],load:0xffe->NXM_NX_REG0[16..31]),resubmit(,%d)", table.GetID(), table.GetID())},
		&ExpectFlow{"priority=200,ip", fmt.Sprintf("ct(table=%d,zone=65520)", table.GetNext())},
		&ExpectFlow{"priority=210,ct_state=-new+trk,ct_mark=0x20,ip,reg0=0x1/0xffff", gotoTableAction},
		&ExpectFlow{"priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", fmt.Sprintf("ct(commit,table=%d,zone=65520,exec(load:0x20->NXM_NX_CT_MARK[])", table.GetNext())},
		&ExpectFlow{"priority=200,ct_state=-new+trk,ct_mark=0x20,ip", fmt.Sprintf("load:0xaaaaaaaaaa11->NXM_OF_ETH_DST[],%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ct_state=+new+inv,ip", "drop"},
		&ExpectFlow{"priority=190,ct_state=+new+trk,ip", fmt.Sprintf("ct(commit,table=%d,zone=65520)", table.GetNext())},
		&ExpectFlow{"priority=200,ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=192.168.1.3", fmt.Sprintf("set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:aa:aa:aa:aa:13->eth_dst,dec_ttl,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.2.0/24", fmt.Sprintf("dec_ttl,set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:10.1.1.2->tun_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ipv6,ipv6_dst=fd74:ca9b:172:21::/64", fmt.Sprintf("dec_ttl,set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:20:ca9b:172:35::3->tun_ipv6_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.1.1", fmt.Sprintf("set_field:aa:aa:aa:aa:aa:11->eth_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,dl_dst=aa:aa:aa:aa:aa:13", fmt.Sprintf("load:0x3->NXM_NX_REG1[],load:0x1->NXM_NX_REG0[16],%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ip,reg0=0x10000/0x10000", "output:NXM_NX_REG1[]"},
		&ExpectFlow{"priority=200,ip,nw_dst=172.16.0.0/16", "output:1"},
		&ExpectFlow{fmt.Sprintf("priority=200,ip,nw_src=192.168.1.3,nw_tos=%d", ipDSCP<<2), gotoTableAction},
		&ExpectFlow{"priority=220,tcp,tp_dst=8080", "conjunction(1001,3/3)"},
		&ExpectFlow{"priority=220,ip,nw_src=192.168.1.3", "conjunction(1001,1/3)"},
		&ExpectFlow{"priority=220,ip,nw_dst=192.168.3.0/24", "conjunction(1001,2/3)"},
		&ExpectFlow{"priority=220,ip", "conjunction(1001,1/3)"},
		&ExpectFlow{"priority=220,ip,reg1=0x3", "conjunction(1001,2/3)"},
		&ExpectFlow{"priority=220,conj_id=1001,ip", gotoTableAction},
		&ExpectFlow{"priority=220,conj_id=1001,ip,nw_src=192.168.1.1", gotoTableAction},
	)

	return flows, flowStrs
}

func prepareNATflows(table binding.Table) ([]binding.Flow, []*ExpectFlow) {
	natedIP1 := net.ParseIP("10.10.0.1")
	natedIP2 := net.ParseIP("10.10.0.10")
	natIPRange1 := &binding.IPRange{StartIP: natedIP1, EndIP: natedIP1}
	natIPRange2 := &binding.IPRange{StartIP: natedIP1, EndIP: natedIP2}
	snatCTMark := uint32(0x40)
	natRequireMark := uint32(0x1)
	snatMarkRange1 := binding.Range{17, 17}
	snatMarkRange2 := binding.Range{18, 18}
	dnatMarkRange1 := binding.Range{19, 19}
	dnatMarkRange2 := binding.Range{20, 20}
	flows := []binding.Flow{
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, table.GetNext(), ctZone).NAT().CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(marksReg, natRequireMark, snatMarkRange1).
			Action().CT(true, table.GetNext(), ctZone).
			SNAT(natIPRange1, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(marksReg, natRequireMark, snatMarkRange2).
			Action().CT(true, table.GetNext(), ctZone).
			SNAT(natIPRange2, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(marksReg, natRequireMark, dnatMarkRange1).
			Action().CT(true, table.GetNext(), ctZone).
			DNAT(natIPRange1, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegRange(marksReg, natRequireMark, dnatMarkRange2).
			Action().CT(true, table.GetNext(), ctZone).
			DNAT(natIPRange2, nil).
			LoadToMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
	}

	flowStrs := []*ExpectFlow{
		{"priority=200,ip", fmt.Sprintf("ct(table=%d,zone=65520,nat)", table.GetNext())},
		{"priority=200,ip,reg0=0x20000/0x20000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(src=%s),exec(load:0x40->NXM_NX_CT_MARK[]))",
				table.GetNext(), natedIP1.String()),
		},
		{"priority=200,ip,reg0=0x40000/0x40000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(src=%s-%s),exec(load:0x40->NXM_NX_CT_MARK[]))",
				table.GetNext(), natedIP1.String(), natedIP2.String()),
		},
		{"priority=200,ip,reg0=0x80000/0x80000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(dst=%s),exec(load:0x40->NXM_NX_CT_MARK[]))",
				table.GetNext(), natedIP1.String()),
		},
		{"priority=200,ip,reg0=0x100000/0x100000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(dst=%s-%s),exec(load:0x40->NXM_NX_CT_MARK[]))",
				table.GetNext(), natedIP1.String(), natedIP2.String()),
		},
	}

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

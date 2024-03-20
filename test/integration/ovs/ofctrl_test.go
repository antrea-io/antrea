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
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
)

var (
	maxRetry = 5

	table binding.Table

	priorityNormal = uint16(200)

	portFoundMark   = binding.NewOneBitRegMark(0, 16)
	portCacheField  = binding.NewRegField(1, 0, 31)
	sourceField     = binding.NewRegField(0, 0, 15)
	fromLocalMark   = binding.NewRegMark(sourceField, 2)
	fromGatewayMark = binding.NewRegMark(sourceField, 1)

	marksReg      = 0
	gatewayCTMark = binding.NewOneBitCTMark(1)
	ctZone        = 0xfff0

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
	t0     = binding.NewOFTable(0, "t0", 0, 0, 0)
	t1     = binding.NewOFTable(1, "t1", 0, 0, 0)
	t2     = binding.NewOFTable(2, "t2", 0, 0, 0)
	t3     = binding.NewOFTable(3, "t3", 0, 0, 0)
	t4     = binding.NewOFTable(4, "t4", 0, 0, 0)
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
	table = bridge.NewTable(t3, t4.GetID(), binding.TableMissActionNext)

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
			Action().NextTable().
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
	dumpTable := table.GetID()
	CheckFlowExists(t, ovsCtlClient, "", dumpTable, true, expectFlows)

	err := flows[0].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, ovsCtlClient, "", dumpTable, false, []*ExpectFlow{expectFlows[0]})
	flowList := CheckFlowExists(t, ovsCtlClient, "", dumpTable, true, []*ExpectFlow{expectFlows[1]})
	if len(flowList) != 1 {
		t.Errorf("Failed to delete flow with strict mode")
	}
	err = flows[1].Delete()
	if err != nil {
		t.Fatalf("Failed to delete 'match-all' flow")
	}
	CheckFlowExists(t, ovsCtlClient, "", dumpTable, false, []*ExpectFlow{expectFlows[1]})
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
	table1 := bridge.NewTable(t1, t2.GetID(), binding.TableMissActionNext)
	table2 := bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

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

		dumpTable := myTable.GetID()
		flowList := CheckFlowExists(t, ovsCtlClient, "", dumpTable, true, expectflows)

		// Test: DumpTableStatus
		for _, tableStates := range bridge.DumpTableStatus() {
			if tableStates.ID == uint(myTable.GetID()) {
				if int(tableStates.FlowCount) != len(flowList) {
					t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
				}
			}
		}

		// Test: DumpFlows
		dumpCookieID, dumpCookieMask := getCookieIDMask()
		flowStates, err := bridge.DumpFlows(dumpCookieID, dumpCookieMask)
		require.NoError(t, err, "no error returns in DumpFlows")
		if len(flowStates) != len(flowList) {
			t.Errorf("Flow count in dump result is incorrect")
		}

		// Test: Flow.Delete
		for _, f := range flows[0:2] {
			if err := f.Delete(); err != nil {
				t.Errorf("Failed to uninstall flow1 %v", err)
			}
		}
		CheckFlowExists(t, ovsCtlClient, "", dumpTable, false, expectflows[0:2])

		// Test: DeleteFlowsByCookie
		err = bridge.DeleteFlowsByCookie(dumpCookieID, dumpCookieMask)
		if err != nil {
			t.Errorf("Failed to DeleteFlowsByCookie: %v", err)
		}
		require.Eventually(t, func() bool {
			flowList, err := OfctlDumpTableFlowsWithoutName(ovsCtlClient, myTable.GetID())
			require.NoError(t, err)
			return len(flowList) == 0
		}, time.Second, time.Millisecond*100, "Failed to delete flows by CookieID")
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

	id := 1

	for name, buckets := range map[string][]struct {
		weight        uint16      // Must have non-zero value.
		reg2reg       [][4]uint32 // regNum, data, startIndex, endIndex
		resubmitTable uint8
	}{
		"Normal": {
			{weight: 100, reg2reg: [][4]uint32{{0, 1, 0, 31}, {1, 2, 15, 31}}, resubmitTable: 31},
			{weight: 110, resubmitTable: 42},
		},
		"TypeAll": {
			{weight: 100, reg2reg: [][4]uint32{{0, 1, 0, 31}, {1, 2, 15, 31}}, resubmitTable: 31},
			{weight: 110, resubmitTable: 42},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var group binding.Group
			gid := binding.GroupIDType(id)
			if name == "TypeAll" {
				group = br.NewGroupTypeAll(gid)
			} else {
				group = br.NewGroup(gid)
			}
			for _, bucket := range buckets {
				require.NotZero(t, bucket.weight, "Weight value of a bucket must be specified")
				bucketBuilder := group.Bucket()
				if name == "Normal" {
					bucketBuilder = bucketBuilder.Weight(bucket.weight)
				}
				if bucket.resubmitTable != 0 {
					bucketBuilder = bucketBuilder.ResubmitToTable(bucket.resubmitTable)
				}
				for _, loading := range bucket.reg2reg {
					regField := binding.NewRegField(int(loading[0]), loading[2], loading[3])
					bucketBuilder = bucketBuilder.LoadToRegField(regField, loading[1])
				}
				group = bucketBuilder.Done()
			}
			// Check if the group could be added.
			require.NoError(t, group.Add())
			var groups [][]string
			require.NoError(t, wait.PollUntilContextTimeout(context.Background(), openFlowCheckInterval, openFlowCheckTimeout, true,
				func(ctx context.Context) (done bool, err error) {
					groups, err = OfCtlDumpGroups(ovsCtlClient)
					require.Nil(t, err)
					return len(groups) == 1, nil
				}), "Failed to install group")
			dumpedGroup := groups[0]
			for i, bucket := range buckets {
				if name == "Normal" {
					// Must have weight
					assert.True(t, strings.Contains(dumpedGroup[i+1], fmt.Sprintf("weight:%d", bucket.weight)))
				}
				for _, loading := range bucket.reg2reg {
					rngStr := ""
					data := loading[1]
					if !(loading[2] == 0 && loading[3] == 31) {
						length := loading[3] - loading[2] + 1
						mask := ^uint32(0) >> (32 - length) << loading[2]
						rngStr = fmt.Sprintf("/0x%x", mask)
						data = data << loading[2]
					}
					loadStr := fmt.Sprintf("set_field:0x%x%s->reg%d", data, rngStr, loading[0])
					assert.Contains(t, dumpedGroup[i+1], loadStr)
				}
				if bucket.resubmitTable != 0 {
					resubmitStr := fmt.Sprintf("resubmit(,%d)", bucket.resubmitTable)
					assert.Contains(t, dumpedGroup[i+1], resubmitStr)
				}
			}
			// Check if the group could be deleted.
			require.NoError(t, group.Delete())
			require.Eventually(t, func() bool {
				groups, err := OfCtlDumpGroups(ovsCtlClient)
				require.NoError(t, err)
				return len(groups) == 0
			}, openFlowCheckTimeout, openFlowCheckInterval, "Failed to delete group")
		})
		id++
	}
}

func TestTransactions(t *testing.T) {
	br := "br04"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer func() {
		err = DeleteOVSBridge(br)
		require.NoError(t, err, "error while deleting OVS bridge")
	}()

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	require.NoError(t, bridge.Connect(maxRetry, make(chan struct{})), "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	flows, expectflows := prepareFlows(table)
	err = bridge.AddFlowsInBundle(openflow.GetFlowModMessages(flows, binding.AddMessage), nil, nil)
	require.NoError(t, err, "Failed to add flows in a transaction")
	dumpTable := table.GetID()
	flowList := CheckFlowExists(t, ovsCtlClient, "", dumpTable, true, expectflows)

	// Test: DumpTableStatus
	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}

	// Delete flows in a bundle
	err = bridge.AddFlowsInBundle(nil, nil, openflow.GetFlowModMessages(flows, binding.DeleteMessage))
	require.NoError(t, err, "Failed to delete flows in a transaction")
	dumpTable = table.GetID()
	flowList = CheckFlowExists(t, ovsCtlClient, "", dumpTable, false, expectflows)

	for _, tableStates := range bridge.DumpTableStatus() {
		if tableStates.ID == uint(dumpTable) {
			if int(tableStates.FlowCount) != len(flowList) {
				t.Errorf("Flow count of table %d in the cache is incorrect, expect: %d, actual %d", dumpTable, len(flowList), tableStates.FlowCount)
			}
		}
	}

	// Invoke AddFlowsInBundle with no Flow to add/modify/delete.
	err = bridge.AddFlowsInBundle(nil, nil, nil)
	require.NoError(t, err, "Not compatible with none flows in the request")
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
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer func() {
		err = DeleteOVSBridge(br)
		require.NoError(t, err, "Failed to delete bridge")
	}()

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
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
					Action().NextTable().
					Done()}
				err = bridge.AddFlowsInBundle(openflow.GetFlowModMessages(flows, binding.AddMessage), nil, nil)
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
	require.NoError(t, err, "Failed to prepare OVS bridge")
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
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	require.Equal(t, connectCount, 1)
	// The max delay for the initial connection is 5s. Here we assume the OVS is stopped then started after 8s, and
	// check that we can re-connect to it after that delay.
	go func() {
		DeleteOVSBridge(br)
		time.Sleep(8 * time.Second)
		err := PrepareOVSBridge(br)
		require.NoError(t, err, "Failed to prepare OVS bridge")
	}()

	err = DeleteOVSBridge(br)
	require.NoError(t, err, "Failed to delete bridge")
	time.Sleep(12 * time.Second)
	require.Equal(t, 2, connectCount)
}

// Verify install/uninstall Flow and its dependent Group in the same Bundle.
func TestBundleWithGroupAndFlow(t *testing.T) {
	br := "br08"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)

	groupID := binding.GroupIDType(4)
	field1 := binding.NewRegField(1, 0, 31)
	field2 := binding.NewRegField(2, 0, 31)
	field3 := binding.NewRegField(3, 0, 31)
	group := bridge.NewGroup(groupID).
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0002)).
		LoadToRegField(field2, uint32(0x35)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done().
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0202)).
		LoadToRegField(field2, uint32(0x35)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done()

	reg3Field := binding.NewRegField(3, 0, 31)
	flow := table.BuildFlow(priorityNormal).
		Cookie(getCookieID()).
		MatchProtocol(binding.ProtocolTCP).
		MatchDstIP(net.ParseIP("10.96.0.10")).
		MatchDstPort(uint16(53), nil).
		MatchRegFieldWithValue(reg3Field, uint32(0xfff2)).
		Action().Group(groupID).Done()
	expectedFlows := []*ExpectFlow{
		{
			MatchStr: "priority=200,tcp,reg3=0xfff2,nw_dst=10.96.0.10,tp_dst=53",
			ActStr:   fmt.Sprintf("group:%d", groupID),
		},
	}

	bucket0 := "weight:100,actions=set_field:0xa0a0002->reg1,set_field:0x35->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	bucket1 := "weight:100,actions=set_field:0xa0a0202->reg1,set_field:0x35->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	expectedGroupBuckets := []string{bucket0, bucket1}
	err = bridge.AddOFEntriesInBundle([]binding.OFEntry{flow, group}, nil, nil)
	require.NoError(t, err)
	CheckFlowExists(t, ovsCtlClient, "", table.GetID(), true, expectedFlows)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)

	err = bridge.AddOFEntriesInBundle(nil, nil, []binding.OFEntry{flow, group})
	require.NoError(t, err)
	CheckFlowExists(t, ovsCtlClient, "", table.GetID(), false, expectedFlows)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, false)
}

func TestPacketOutIn(t *testing.T) {
	br := "br09"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table0 := bridge.NewTable(t0, t1.GetID(), binding.TableMissActionNext)
	table1 := bridge.NewTable(t1, t2.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	category := uint8(1)
	pktInQueue := binding.NewPacketInQueue(200, rate.Limit(100))
	err = bridge.SubscribePacketIn(category, pktInQueue)
	require.NoError(t, err)

	srcMAC, _ := net.ParseMAC("11:11:11:11:11:11")
	dstcMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	srcIP := net.ParseIP("1.1.1.2")
	dstIP := net.ParseIP("2.2.2.2")
	tunDst := net.ParseIP("10.10.10.2")
	srcPort := uint16(10001)
	dstPort := uint16(8080)
	reg2Data := uint32(0x1234)
	reg2Field := binding.NewRegField(2, 0, 15)
	reg3Data := uint32(0x1234)
	reg3Field := binding.NewRegField(3, 0, 31)
	stopCh := make(chan struct{})

	go func() {
		pktIn := pktInQueue.GetRateLimited(make(chan struct{}))
		matchers := pktIn.GetMatches()

		reg2Match := openflow.GetMatchFieldByRegID(matchers, 2)
		assert.NotNil(t, reg2Match)
		reg2Value := reg2Match.GetValue()
		assert.NotNil(t, reg2Value)
		value2, ok2 := reg2Value.(*ofctrl.NXRegister)
		assert.True(t, ok2)
		assert.Equal(t, reg2Data, ofctrl.GetUint32ValueWithRange(value2.Data, reg2Field.GetRange().ToNXRange()))

		reg3Match := openflow.GetMatchFieldByRegID(matchers, 3)
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
	regField := binding.NewRegField(0, 18, 18)
	mark := binding.NewRegMark(regField, 0x1)
	pkt := pktBuilder.SetSrcMAC(srcMAC).SetDstMAC(dstcMAC).
		SetDstIP(dstIP).SetSrcIP(srcIP).SetIPProtocol(binding.ProtocolTCP).
		SetTCPSrcPort(srcPort).SetTCPDstPort(dstPort).
		AddLoadRegMark(mark).
		Done()
	require.NoError(t, err)
	flow0 := table0.BuildFlow(100).
		MatchSrcMAC(srcMAC).MatchDstMAC(dstcMAC).
		MatchSrcIP(srcIP).MatchDstIP(dstIP).MatchProtocol(binding.ProtocolTCP).
		MatchRegFieldWithValue(regField, 0x1).
		Action().LoadToRegField(reg2Field, reg2Data).
		Action().LoadToRegField(reg3Field, reg3Data).
		Action().SetTunnelDst(tunDst).
		Action().ResubmitToTables(table0.GetNext()).
		Done()
	flow1 := table1.BuildFlow(100).
		MatchSrcMAC(srcMAC).MatchDstMAC(dstcMAC).
		MatchSrcIP(srcIP).MatchDstIP(dstIP).MatchProtocol(binding.ProtocolTCP).
		MatchRegFieldWithValue(regField, 0x1).
		Action().SendToController([]byte{0x1}, false).
		Done()
	err = bridge.AddFlowsInBundle(openflow.GetFlowModMessages([]binding.Flow{flow0, flow1}, binding.AddMessage), nil, nil)
	require.NoError(t, err)
	err = bridge.SendPacketOut(pkt)
	require.NoError(t, err)
	<-stopCh
}

func TestFlowWithCTMatchers(t *testing.T) {
	br := "br09"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ofctlClient := ovsctl.NewClient(br)
	ctIPSrc, ctIPSrcNet, _ := net.ParseCIDR("1.1.1.1/24")
	ctIPDst, ctIPDstNet, _ := net.ParseCIDR("2.2.2.2/24")
	ctIPv6Src, ctIPv6SrcNet, _ := net.ParseCIDR("1:1:1::1/64")
	ctIPv6Dst, ctIPv6DstNet, _ := net.ParseCIDR("2:2:2::2/64")
	ctPortSrc := uint16(10001)
	ctPortDst := uint16(20002)
	priority := uint16(200)
	flow1 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchCTStateNew(true).
		MatchCTSrcIP(ctIPSrc).
		MatchCTDstIP(ctIPDst).
		MatchCTSrcPort(ctPortSrc).
		MatchCTDstPort(ctPortDst).
		MatchCTProtocol(binding.ProtocolTCP).
		Action().NextTable().
		Done()
	flow2 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchCTStateEst(true).
		MatchCTSrcIPNet(*ctIPSrcNet).
		MatchCTDstIPNet(*ctIPDstNet).
		MatchCTProtocol(binding.ProtocolTCP).
		Action().NextTable().
		Done()
	flow3 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIPv6).
		MatchCTStateNew(true).
		MatchCTSrcIP(ctIPv6Src).
		MatchCTDstIP(ctIPv6Dst).
		MatchCTSrcPort(ctPortSrc).
		MatchCTDstPort(ctPortDst).
		MatchCTProtocol(binding.ProtocolTCPv6).
		Action().NextTable().
		Done()
	flow4 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIPv6).
		MatchCTStateEst(true).
		MatchCTSrcIPNet(*ctIPv6SrcNet).
		MatchCTDstIPNet(*ctIPv6DstNet).
		MatchCTProtocol(binding.ProtocolTCPv6).
		Action().NextTable().
		Done()
	expectFlows := []*ExpectFlow{
		{fmt.Sprintf("priority=%d,ct_state=+new,ct_nw_src=%s,ct_nw_dst=%s,ct_nw_proto=6,ct_tp_src=%d,ct_tp_dst=%d,ip",
			priority, ctIPSrc.String(), ctIPDst.String(), ctPortSrc, ctPortDst),
			fmt.Sprintf("goto_table:%d", table.GetNext()),
		},
		{
			fmt.Sprintf("priority=%d,ct_state=+est,ct_nw_src=%s,ct_nw_dst=%s,ct_nw_proto=6,ip",
				priority, ctIPSrcNet.String(), ctIPDstNet.String()),
			fmt.Sprintf("goto_table:%d", table.GetNext()),
		},
		{fmt.Sprintf("priority=%d,ct_state=+new,ct_ipv6_src=%s,ct_ipv6_dst=%s,ct_nw_proto=6,ct_tp_src=%d,ct_tp_dst=%d,ipv6",
			priority, ctIPv6Src.String(), ctIPv6Dst.String(), ctPortSrc, ctPortDst),
			fmt.Sprintf("goto_table:%d", table.GetNext()),
		},
		{
			fmt.Sprintf("priority=%d,ct_state=+est,ct_ipv6_src=%s,ct_ipv6_dst=%s,ct_nw_proto=6,ipv6",
				priority, ctIPv6SrcNet.String(), ctIPv6DstNet.String()),
			fmt.Sprintf("goto_table:%d", table.GetNext()),
		},
	}
	for _, f := range []binding.Flow{flow1, flow2, flow3, flow4} {
		err = f.Add()
		assert.Nil(t, err, "no error returned when adding flow")
	}
	CheckFlowExists(t, ofctlClient, "", table.GetID(), true, expectFlows)
	for _, f := range []binding.Flow{flow1, flow2, flow3, flow4} {
		err = f.Delete()
		assert.Nil(t, err, "no error returned when deleting flow")
	}
	CheckFlowExists(t, ofctlClient, "", table.GetID(), false, expectFlows)
}

func TestNoteAction(t *testing.T) {
	br := "br10"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ofctlClient := ovsctl.NewClient(br)
	priority := uint16(1001)
	srcIP := net.ParseIP("1.1.1.2")
	testNotes := "test for noteActions."
	flow1 := table.BuildFlow(priority).
		MatchProtocol(binding.ProtocolIP).
		MatchSrcIP(srcIP).
		Action().Note(testNotes).
		Action().NextTable().
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
	CheckFlowExists(t, ofctlClient, "", table.GetID(), true, expectFlows)
	err = flow1.Delete()
	assert.Nil(t, err, "expected no error when deleting flow")
	CheckFlowExists(t, ofctlClient, "", table.GetID(), false, expectFlows)
}

func TestLoadToLabelFieldAction(t *testing.T) {
	br := "br13"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)
	priority := uint16(1001)

	testCases := []struct {
		ctLabel *binding.CtLabel
		data    uint64
	}{
		{
			ctLabel: binding.NewCTLabel(16, 31),
			data:    0x1001,
		},
		{
			ctLabel: binding.NewCTLabel(0, 63),
			data:    0x1001100110011001,
		},
		{
			ctLabel: binding.NewCTLabel(80, 95),
			data:    0x1001,
		},
		{
			ctLabel: binding.NewCTLabel(64, 127),
			data:    0x1001100110011001,
		},
	}

	srcIP := net.ParseIP("1.1.1.2")
	for _, tc := range testCases {
		maskStr := fmt.Sprintf("0x%x", ^uint64(0)>>(64-tc.ctLabel.GetRange().Length())<<(tc.ctLabel.GetRange().Offset()%64))
		dataStr := fmt.Sprintf("0x%x", tc.data<<(tc.ctLabel.GetRange().Offset()%64))
		if tc.ctLabel.GetRange().Offset() > 63 {
			maskStr += "0000000000000000"
			dataStr += "0000000000000000"
		}
		expectFlows := []*ExpectFlow{
			{fmt.Sprintf("priority=%d,ip,nw_src=%s", priority, srcIP.String()),
				fmt.Sprintf("ct(commit,table=%d,zone=65520,exec(set_field:%s/%s->ct_label))", table.GetNext(), dataStr, maskStr)},
		}
		flow1 := table.BuildFlow(priority).
			MatchProtocol(binding.ProtocolIP).
			MatchSrcIP(srcIP).
			Action().CT(true, table.GetNext(), 65520, nil).
			LoadToLabelField(tc.data, tc.ctLabel).
			CTDone().
			Done()
		err = flow1.Add()
		assert.Nil(t, err, "expected no error when adding flow")
		CheckFlowExists(t, ovsCtlClient, "", table.GetID(), true, expectFlows)
		err = flow1.Delete()
		assert.Nil(t, err, "expected no error when deleting flow")
		CheckFlowExists(t, ovsCtlClient, "", table.GetID(), false, expectFlows)
	}
}

func TestBundleWithGroupInsertBucket(t *testing.T) {
	br := "br12"
	err := PrepareOVSBridge(br)
	require.NoError(t, err, "Failed to prepare OVS bridge")
	defer DeleteOVSBridge(br)

	bridge := newOFBridge(br)
	table = bridge.NewTable(t2, t3.GetID(), binding.TableMissActionNext)
	// Set the maximum of buckets in a message to test insert_buckets.
	binding.MaxBucketsPerMessage = 2
	// In case it affects other tests, set the maximum of buckets in a message back to 800.
	defer func() {
		binding.MaxBucketsPerMessage = 800
	}()

	err = bridge.Connect(maxRetry, make(chan struct{}))
	require.NoError(t, err, "Failed to start OFService")
	defer bridge.Disconnect()

	ovsCtlClient := ovsctl.NewClient(br)
	groupID := binding.GroupIDType(4)

	group := bridge.NewGroup(groupID)
	expectedGroupBuckets := []string{}
	err = bridge.AddOFEntriesInBundle([]binding.OFEntry{group}, nil, nil)
	require.NoError(t, err)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)

	field1 := binding.NewRegField(1, 0, 31)
	field2 := binding.NewRegField(2, 0, 31)
	field3 := binding.NewRegField(3, 0, 31)
	group = group.
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0002)).
		LoadToRegField(field2, uint32(0x1)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done().
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0202)).
		LoadToRegField(field2, uint32(0x2)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done().
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0202)).
		LoadToRegField(field2, uint32(0x3)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done()

	bucket1 := "weight:100,actions=set_field:0xa0a0002->reg1,set_field:0x1->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	bucket2 := "weight:100,actions=set_field:0xa0a0202->reg1,set_field:0x2->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	bucket3 := "weight:100,actions=set_field:0xa0a0202->reg1,set_field:0x3->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	expectedGroupBuckets = []string{bucket1, bucket2, bucket3}
	err = bridge.AddOFEntriesInBundle(nil, []binding.OFEntry{group}, nil)
	require.NoError(t, err)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)

	group = group.
		Bucket().Weight(100).
		LoadToRegField(field1, uint32(0xa0a0202)).
		LoadToRegField(field2, uint32(0x4)).
		LoadToRegField(field3, uint32(0xfff1)).
		ResubmitToTable(table.GetNext()).Done()

	bucket4 := "weight:100,actions=set_field:0xa0a0202->reg1,set_field:0x4->reg2,set_field:0xfff1->reg3,resubmit(,3)"
	expectedGroupBuckets = []string{bucket1, bucket2, bucket3, bucket4}
	err = bridge.AddOFEntriesInBundle(nil, []binding.OFEntry{group}, nil)
	require.NoError(t, err)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)

	group.ResetBuckets()
	expectedGroupBuckets = []string{}
	err = bridge.AddOFEntriesInBundle(nil, []binding.OFEntry{group}, nil)
	require.NoError(t, err)
	CheckGroupExists(t, ovsCtlClient, groupID, "select", expectedGroupBuckets, true)
}

func prepareFlows(table binding.Table) ([]binding.Flow, []*ExpectFlow) {
	var flows []binding.Flow
	_, AllIPs, _ := net.ParseCIDR("0.0.0.0/0")
	_, conjSrcIPNet, _ := net.ParseCIDR("192.168.3.0/24")
	_, peerSubnetIPv6, _ := net.ParseCIDR("fd74:ca9b:172:21::/64")
	tunnelPeerIPv6 := net.ParseIP("20:ca9b:172:35::3")
	regField0 := binding.NewRegField(0, 0, 15)
	mark0 := binding.NewRegMark(regField0, 0x0fff)
	regField1 := binding.NewRegField(0, 16, 31)
	mark1 := binding.NewRegMark(regField1, 0x0ffe)
	flows = append(flows,
		table.BuildFlow(priorityNormal-10).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			Action().LoadRegMark(fromLocalMark).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchARPSha(podMAC).
			MatchARPSpa(podIP).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchInPort(podOFport).
			MatchSrcMAC(podMAC).
			MatchSrcIP(podIP).
			Action().NextTable().
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
			Action().Learn(table.GetID(), priorityNormal-10, 10, 0, 0, 0, 1).
			DeleteLearned().
			MatchEthernetProtocol(false).
			MatchIPProtocol(binding.ProtocolTCP).
			MatchLearnedDstPort(binding.ProtocolTCP).
			MatchRegMark(mark0).
			LoadFieldToField(regField0, regField0).
			LoadRegMark(mark1).
			Done(). // Finish learn action.
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			Action().CT(false, table.GetNext(), ctZone, nil).CTDone().
			Done(),
		table.BuildFlow(priorityNormal+10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegMark(fromGatewayMark).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchRegMark(fromGatewayMark).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, table.GetNext(), ctZone, nil).
			LoadToCtMark(gatewayCTMark).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTMark(gatewayCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().SetDstMAC(gwMAC).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateInv(true).
			Action().Drop().
			Done(),
		table.BuildFlow(priorityNormal-10).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			Action().CT(true, table.GetNext(), ctZone, nil).CTDone().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstMAC(vMAC).
			MatchDstIP(podIP).
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(podMAC).
			Action().DecTTL().
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIPNet(*peerSubnet).
			Action().DecTTL().
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(vMAC).
			Action().SetTunnelDst(tunnelPeer).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			Cookie(getCookieID()).
			MatchDstIPNet(*peerSubnetIPv6).
			Action().DecTTL().
			Action().SetSrcMAC(gwMAC).
			Action().SetDstMAC(vMAC).
			Action().SetTunnelDst(tunnelPeerIPv6).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIP(gwIP).
			Action().SetDstMAC(gwMAC).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchDstMAC(podMAC).
			Action().LoadToRegField(portCacheField, podOFport).
			Action().LoadRegMark(portFoundMark).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(portFoundMark).
			Action().OutputToRegField(portCacheField).
			Done(), table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Cookie(getCookieID()).
			MatchDstIPNet(*serviceCIDR).
			Action().Output(gwOFPort).
			Done(),
		table.BuildFlow(priorityNormal).
			Cookie(getCookieID()).
			MatchProtocol(binding.ProtocolIP).
			MatchSrcIP(podIP).
			MatchIPDSCP(ipDSCP).
			Action().NextTable().
			Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolTCP).Cookie(getCookieID()).MatchDstPort(uint16(8080), nil).
			Action().Conjunction(uint32(1001), uint8(3), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchSrcIP(podIP).
			Action().Conjunction(uint32(1001), uint8(1), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchDstIPNet(*conjSrcIPNet).
			Action().Conjunction(uint32(1001), uint8(2), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchSrcIPNet(*AllIPs).
			Action().Conjunction(uint32(1001), uint8(1), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchRegFieldWithValue(portCacheField, podOFport).
			Action().Conjunction(uint32(1001), uint8(2), uint8(3)).Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchConjID(1001).
			Action().NextTable().Done(),
		table.BuildFlow(priorityNormal+20).MatchProtocol(binding.ProtocolIP).Cookie(getCookieID()).MatchConjID(1001).MatchSrcIP(gwIP).
			Action().NextTable().Done(),
	)

	gotoTableAction := fmt.Sprintf("goto_table:%d", table.GetNext())
	var flowStrs []*ExpectFlow
	flowStrs = append(flowStrs,
		&ExpectFlow{"priority=190,in_port=3", fmt.Sprintf("set_field:0x2/0xffff->reg0,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,arp,in_port=3,arp_spa=192.168.1.3,arp_sha=aa:aa:aa:aa:aa:13", gotoTableAction},
		&ExpectFlow{"priority=200,ip,in_port=3,dl_src=aa:aa:aa:aa:aa:13,nw_src=192.168.1.3", gotoTableAction},
		&ExpectFlow{"priority=200,arp,arp_tpa=192.168.2.1,arp_op=1", "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:aa:bb:cc:dd:ee:ff->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],set_field:aa:bb:cc:dd:ee:ff->arp_sha,move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:192.168.2.1->arp_spa,IN_PORT"},
		&ExpectFlow{"priority=190,arp", "NORMAL"},
		&ExpectFlow{"priority=200,tcp", fmt.Sprintf("learn(table=%d,idle_timeout=10,priority=190,delete_learned,cookie=0x1,eth_type=0x800,nw_proto=6,NXM_OF_TCP_DST[],NXM_NX_REG0[0..15]=0xfff,load:NXM_NX_REG0[0..15]->NXM_NX_REG0[0..15],load:0xffe->NXM_NX_REG0[16..31]),goto_table:%d", table.GetID(), table.GetNext())},
		&ExpectFlow{"priority=200,ip", fmt.Sprintf("ct(table=%d,zone=65520)", table.GetNext())},
		&ExpectFlow{"priority=210,ct_state=-new+trk,ct_mark=0x2/0x2,ip,reg0=0x1/0xffff", gotoTableAction},
		&ExpectFlow{"priority=200,ct_state=+new+trk,ip,reg0=0x1/0xffff", fmt.Sprintf("ct(commit,table=%d,zone=65520,exec(set_field:0x2/0x2->ct_mark)", table.GetNext())},
		&ExpectFlow{"priority=200,ct_state=-new+trk,ct_mark=0x2/0x2,ip", fmt.Sprintf("set_field:aa:aa:aa:aa:aa:11->eth_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ct_state=+new+inv,ip", "drop"},
		&ExpectFlow{"priority=190,ct_state=+new+trk,ip", fmt.Sprintf("ct(commit,table=%d,zone=65520)", table.GetNext())},
		&ExpectFlow{"priority=200,ip,dl_dst=aa:bb:cc:dd:ee:ff,nw_dst=192.168.1.3", fmt.Sprintf("set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:aa:aa:aa:aa:13->eth_dst,dec_ttl,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.2.0/24", fmt.Sprintf("dec_ttl,set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:10.1.1.2->tun_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ipv6,ipv6_dst=fd74:ca9b:172:21::/64", fmt.Sprintf("dec_ttl,set_field:aa:aa:aa:aa:aa:11->eth_src,set_field:aa:bb:cc:dd:ee:ff->eth_dst,set_field:20:ca9b:172:35::3->tun_ipv6_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,ip,nw_dst=192.168.1.1", fmt.Sprintf("set_field:aa:aa:aa:aa:aa:11->eth_dst,%s", gotoTableAction)},
		&ExpectFlow{"priority=200,dl_dst=aa:aa:aa:aa:aa:13", fmt.Sprintf("set_field:0x3->reg1,set_field:0x10000/0x10000->reg0,%s", gotoTableAction)},
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
	snatCTMark := binding.NewCTMark(binding.NewCTMarkField(0, 7), 0x40)
	snatMark1 := binding.NewOneBitRegMark(marksReg, 17)
	snatMark2 := binding.NewOneBitRegMark(marksReg, 18)
	dnatMark1 := binding.NewOneBitRegMark(marksReg, 19)
	dnatMark2 := binding.NewOneBitRegMark(marksReg, 20)
	flows := []binding.Flow{
		table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			Action().CT(false, table.GetNext(), ctZone, nil).NAT().CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(snatMark1).
			Action().CT(true, table.GetNext(), ctZone, nil).
			SNAT(natIPRange1, nil).
			LoadToCtMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(snatMark2).
			Action().CT(true, table.GetNext(), ctZone, nil).
			SNAT(natIPRange2, nil).
			LoadToCtMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(dnatMark1).
			Action().CT(true, table.GetNext(), ctZone, nil).
			DNAT(natIPRange1, nil).
			LoadToCtMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
		table.BuildFlow(priorityNormal).
			MatchProtocol(binding.ProtocolIP).
			MatchRegMark(dnatMark2).
			Action().CT(true, table.GetNext(), ctZone, nil).
			DNAT(natIPRange2, nil).
			LoadToCtMark(snatCTMark).CTDone().
			Cookie(getCookieID()).
			Done(),
	}

	flowStrs := []*ExpectFlow{
		{"priority=200,ip", fmt.Sprintf("ct(table=%d,zone=65520,nat)", table.GetNext())},
		{"priority=200,ip,reg0=0x20000/0x20000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(src=%s),exec(set_field:0x40/0xff->ct_mark))",
				table.GetNext(), natedIP1.String()),
		},
		{"priority=200,ip,reg0=0x40000/0x40000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(src=%s-%s),exec(set_field:0x40/0xff->ct_mark))",
				table.GetNext(), natedIP1.String(), natedIP2.String()),
		},
		{"priority=200,ip,reg0=0x80000/0x80000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(dst=%s),exec(set_field:0x40/0xff->ct_mark))",
				table.GetNext(), natedIP1.String()),
		},
		{"priority=200,ip,reg0=0x100000/0x100000",
			fmt.Sprintf("ct(commit,table=%d,zone=65520,nat(dst=%s-%s),exec(set_field:0x40/0xff->ct_mark))",
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

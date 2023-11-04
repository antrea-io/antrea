// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/metrics"
)

// ofTable implements openflow.Table.
type ofTable struct {
	// sync.RWMutex protects ofTable status from concurrent modification and reading.
	sync.RWMutex
	id         uint8
	name       string
	next       uint8
	missAction MissActionType
	flowCount  uint
	updateTime time.Time
	stageID    StageID
	pipelineID PipelineID

	*ofctrl.Table
}

func (t *ofTable) GetID() uint8 {
	return t.id
}

func (t *ofTable) GetName() string {
	return t.name
}

func (t *ofTable) Status() TableStatus {
	t.RLock()
	defer t.RUnlock()

	return TableStatus{
		ID:         uint(t.id),
		Name:       t.name,
		FlowCount:  t.flowCount,
		UpdateTime: t.updateTime,
	}
}

func (t *ofTable) GetMissAction() MissActionType {
	return t.missAction
}

func (t *ofTable) GetNext() uint8 {
	return t.next
}

func (t *ofTable) SetNext(next uint8) {
	t.next = next
}

func (t *ofTable) SetMissAction(action MissActionType) {
	t.missAction = action
}

func (t *ofTable) GetStageID() StageID {
	return t.stageID
}

func (t *ofTable) SetTable() {
	t.Table = &ofctrl.Table{TableId: t.id}
}

func (t *ofTable) GetPipelineID() PipelineID {
	return t.pipelineID
}

func (t *ofTable) UpdateStatus(flowCountDelta int) {
	t.Lock()
	defer t.Unlock()

	if flowCountDelta < 0 {
		t.flowCount -= uint(-flowCountDelta)
	} else {
		t.flowCount += uint(flowCountDelta)
	}

	metrics.OVSTotalFlowCount.Add(float64(flowCountDelta))
	metrics.OVSFlowCount.WithLabelValues(strconv.Itoa(int(t.id)), t.name).Add(float64(flowCountDelta))

	t.updateTime = time.Now()
}

func (t *ofTable) ResetStatus() {
	t.Lock()
	defer t.Unlock()

	t.flowCount = 0

	metrics.OVSFlowCount.WithLabelValues(strconv.Itoa(int(t.id)), t.name).Set(0)

	t.updateTime = time.Now()
}

// BuildFlow returns FlowBuilder object to help construct Openflow entry.
func (t *ofTable) BuildFlow(priority uint16) FlowBuilder {
	fb := new(ofFlowBuilder)
	fb.table = t
	// Set ofctl.Table to Flow, otherwise the flow can't find OFSwitch to install.
	fb.Flow = &ofctrl.Flow{Table: t.Table, Match: ofctrl.FlowMatch{Priority: priority}}
	return fb
}

// DumpFlows dumps all existing Openflow entries from OFSwitch using cookie ID and table ID as filters.
func (t *ofTable) DumpFlows(cookieID, cookieMask uint64) (map[uint64]*FlowStates, error) {
	ofStats, err := t.Table.Switch.DumpFlowStats(cookieID, &cookieMask, nil, &t.TableId)
	if err != nil {
		return nil, err
	}
	if ofStats == nil {
		return nil, nil
	}
	return parseFlowStats(ofStats), nil
}

func parseFlowStats(ofStats []*openflow15.FlowDesc) map[uint64]*FlowStates {
	flowStats := make(map[uint64]*FlowStates)
	for _, stat := range ofStats {
		cookie := stat.Cookie
		s := &FlowStates{
			TableID: stat.TableId,
		}
		for _, field := range stat.Stats.Fields {
			switch count := field.(type) {
			case *openflow15.PBCountStatField:
				if count.Header.Field == openflow15.XST_OFB_PACKET_COUNT {
					s.PacketCount = count.Count
				}
			case *openflow15.TimeStatField:
				if count.Header.Field == openflow15.XST_OFB_DURATION {
					s.DurationNSecond = count.NSec
				}
			}
		}
		flowStats[cookie] = s
	}
	return flowStats
}

func NewOFTable(id uint8, name string, stageID StageID, pipelineID PipelineID, missAction MissActionType) Table {
	return &ofTable{
		id:         id,
		name:       name,
		stageID:    stageID,
		pipelineID: pipelineID,
		missAction: missAction,
	}
}

// OFBridge implements openflow.Bridge.
type OFBridge struct {
	bridgeName string
	// Management address
	mgmtAddr string
	// sync.RWMutex protects tableCache from concurrent modification and iteration.
	sync.RWMutex
	// tableCache is used to cache ofTables.
	tableCache map[uint8]*ofTable

	ofSwitchMutex sync.RWMutex
	// ofSwitch is the target OFSwitch.
	ofSwitch *ofctrl.OFSwitch
	// controller helps maintain connections to remote OFSwitch.
	controller *ofctrl.Controller
	// retryInterval is the interval for retry connection.
	retryInterval time.Duration
	// maxRetrySec is the seconds waiting for connection to the OFSwitch.
	maxRetrySec int

	// channel to notify agent OFSwitch is connected.
	connCh chan struct{}
	// connected is an internal channel to notify if connected to the OFSwitch or not. It is used only in Connect method.
	connected chan bool
	// pktConsumers is a map from PacketIn category to the channel that is used to publish the PacketIn message.
	pktConsumers sync.Map

	mpReplyChsMutex sync.RWMutex
	mpReplyChs      map[uint32]chan *openflow15.MultipartReply
	// tunMetadataLengthMap is used to store the tlv-map settings on the OVS bridge. Key is the index of tunnel metedata,
	// and value is the length configured in this tunnel metadata.
	tunMetadataLengthMap map[uint16]uint8
}

func (b *OFBridge) NewGroupTypeAll(id GroupIDType) Group {
	return b.newGroupWithType(id, ofctrl.GroupAll)
}

func (b *OFBridge) NewGroup(id GroupIDType) Group {
	return b.newGroupWithType(id, ofctrl.GroupSelect)
}

func (b *OFBridge) newGroupWithType(id GroupIDType, groupType ofctrl.GroupType) Group {
	ofctrlGroup := ofctrl.NewGroup(uint32(id), groupType, b.ofSwitch)
	g := &ofGroup{bridge: b, ofctrl: ofctrlGroup}
	return g
}

func (b *OFBridge) NewMeter(id MeterIDType, flags ofctrl.MeterFlag) Meter {
	ofctrlMeter := ofctrl.NewMeter(uint32(id), flags, b.ofSwitch)
	m := &ofMeter{bridge: b, ofctrl: ofctrlMeter}
	return m
}

func (b *OFBridge) DeleteMeterAll() error {
	meterMod := openflow15.NewMeterMod()
	meterMod.MeterId = openflow15.M_ALL
	meterMod.Command = openflow15.MC_DELETE
	return b.ofSwitch.Send(meterMod)
}

func (b *OFBridge) DeleteGroupAll() error {
	groupMod := openflow15.NewGroupMod()
	groupMod.GroupId = openflow15.OFPG_ALL
	groupMod.Command = openflow15.OFPGC_DELETE
	return b.ofSwitch.Send(groupMod)
}

func (b *OFBridge) GetMeterStats(handleMeterStatsReply func(meterID int, packetCount int64)) error {
	const OFPM_ALL = 0xffffffff // Represents all meters
	mpMeterStatsReq := openflow15.NewMpRequest(openflow15.MultipartType_MeterStats)
	meterMPReq := openflow15.NewMeterMultipartRequest(OFPM_ALL)
	mpMeterStatsReq.Body = append(mpMeterStatsReq.Body, meterMPReq)
	ch := make(chan *openflow15.MultipartReply, 1)
	b.registerMpReplyCh(mpMeterStatsReq.Xid, ch)
	go func() {
		defer b.unregisterMpReplyCh(mpMeterStatsReq.Xid)
		select {
		case reply := <-ch:
			if reply.Type == openflow15.MultipartType_MeterStats {
				for _, entry := range reply.Body {
					stats := entry.(*openflow15.MeterStats)
					if len(stats.BandStats) > 0 {
						handleMeterStatsReply(int(stats.MeterId), int64(stats.BandStats[0].PacketBandCount))
					}
				}
			}
		case <-time.After(5 * time.Second):
			klog.InfoS("Timeout waiting for OVS MeterStats reply")
		}
	}()
	return b.ofSwitch.Send(mpMeterStatsReq)
}

func (b *OFBridge) NewTable(table Table, next uint8, missAction MissActionType) Table {
	table.SetNext(next)
	table.SetMissAction(missAction)
	t, ok := table.(*ofTable)
	if !ok {
		return nil
	}
	b.Lock()
	defer b.Unlock()
	b.tableCache[t.id] = t
	return t
}

// GetTableByID returns the existing table by the given id. If no table exists, an error is returned.
func (b *OFBridge) GetTableByID(id uint8) (Table, error) {
	b.Lock()
	defer b.Unlock()
	t, ok := b.tableCache[id]
	if !ok {
		return nil, fmt.Errorf("no table exists with ID %d", id)
	}
	return t, nil
}

// DumpTableStatus dumps table status from local cache.
func (b *OFBridge) DumpTableStatus() []TableStatus {
	var r []TableStatus

	b.RLock()
	defer b.RUnlock()

	for _, t := range b.tableCache {
		r = append(r, t.Status())
	}
	return r
}

// PacketRcvd is a callback when a packetIn is received on ofctrl.OFSwitch.
func (b *OFBridge) PacketRcvd(sw *ofctrl.OFSwitch, packet *ofctrl.PacketIn) {
	klog.V(2).InfoS("Received packetIn", "packet", packet)
	if len(packet.UserData) == 0 {
		klog.Info("Received packetIn without packetIn category in userdata")
		return
	}
	category := packet.UserData[0]
	v, found := b.pktConsumers.Load(category)
	if found {
		pktInQueue, _ := v.(*PacketInQueue)
		pktInQueue.AddOrDrop(packet)
	}
}

// SwitchConnected is a callback when the remote OFSwitch is connected.
func (b *OFBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	klog.Infof("OFSwitch is connected: %v", sw.DPID())
	b.SetOFSwitch(sw)
	b.setPacketInFormatTo2()
	b.ofSwitch.EnableMonitor()
	// initialize tables.
	b.Initialize()
	b.queryTableFeatures()
	go func() {
		// b.connected is nil if it is an automatic reconnection but not triggered by OFSwitch.Connect.
		if b.connected != nil {
			b.connected <- true
		}
		b.connCh <- struct{}{}
	}()
}

func (b *OFBridge) SetOFSwitch(sw *ofctrl.OFSwitch) {
	b.ofSwitchMutex.Lock()
	defer b.ofSwitchMutex.Unlock()
	b.ofSwitch = sw
}

// MultipartReply is a callback when multipartReply message is received on ofctrl.OFSwitch is connected.
// Client uses this method to handle the reply message if it has customized MultipartRequest message.
func (b *OFBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow15.MultipartReply) {
	ch, ok := func() (chan *openflow15.MultipartReply, bool) {
		b.mpReplyChsMutex.RLock()
		defer b.mpReplyChsMutex.RUnlock()
		ch, ok := b.mpReplyChs[rep.Xid]
		return ch, ok
	}()
	if ok {
		ch <- rep
	}
}

func (b *OFBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	klog.Infof("OFSwitch is disconnected: %v", sw.DPID())
}

func (b *OFBridge) FlowGraphEnabledOnSwitch() bool {
	return false
}

func (b *OFBridge) TLVMapEnabledOnSwitch() bool {
	return false
}

// Initialize creates ofctrl.Table for each table in the tableCache.
func (b *OFBridge) Initialize() {
	b.Lock()
	defer b.Unlock()

	for id, table := range b.tableCache {
		table.Table = ofctrl.NewTable(id, b.ofSwitch)
		// reset flow counts, which is needed for reconnections
		table.ResetStatus()
	}

	metrics.OVSTotalFlowCount.Set(0)
}

// Connect initiates the connection to the OFSwitch, and initializes ofTables after connected.
func (b *OFBridge) Connect(maxRetrySec int, connectionCh chan struct{}) error {
	b.connCh = connectionCh
	b.maxRetrySec = maxRetrySec
	b.connected = make(chan bool)
	errCh := make(chan error)
	go func() {
		err := b.controller.Connect(b.mgmtAddr)
		if err != nil {
			errCh <- err
		}
	}()

	maxWait, _ := time.ParseDuration(fmt.Sprintf("%ds", maxRetrySec))
	select {
	case err := <-errCh:
		return err
	case <-time.After(maxWait):
		b.controller.Delete()
		return fmt.Errorf("failed to connect to OpenFlow switch after %d seconds", maxRetrySec)
	case <-b.connected:
		b.connected = nil
		return nil
	}
}

// Disconnect stops connection to the OFSwitch.
func (b *OFBridge) Disconnect() error {
	b.controller.Delete()
	return nil
}

// DumpFlows queries the Openflow entries from OFSwitch, the filter of the query is Openflow cookieID. The result is
// a map from flow cookieID to FlowStates.
func (b *OFBridge) DumpFlows(cookieID, cookieMask uint64) (map[uint64]*FlowStates, error) {
	ofStats, err := b.ofSwitch.DumpFlowStats(cookieID, &cookieMask, nil, nil)
	if err != nil {
		return nil, err
	}
	if ofStats == nil {
		return nil, nil
	}
	return parseFlowStats(ofStats), nil
}

// DeleteFlowsByCookie removes Openflow entries from OFSwitch. The removed Openflow entries use the specific CookieID.
func (b *OFBridge) DeleteFlowsByCookie(cookieID, cookieMask uint64) error {
	flowMod := openflow15.NewFlowMod()
	flowMod.Command = openflow15.FC_DELETE
	flowMod.Cookie = cookieID
	flowMod.CookieMask = cookieMask
	flowMod.OutPort = openflow15.P_ANY
	flowMod.OutGroup = openflow15.OFPG_ANY
	flowMod.TableId = openflow15.OFPTT_ALL
	return b.ofSwitch.Send(flowMod)
}

func (b *OFBridge) IsConnected() bool {
	sw := func() *ofctrl.OFSwitch {
		b.ofSwitchMutex.RLock()
		defer b.ofSwitchMutex.RUnlock()
		return b.ofSwitch
	}()
	if sw == nil {
		return false
	}
	return sw.IsReady()
}

func (b *OFBridge) AddFlowsInBundle(addflows, modFlows, delFlows []*openflow15.FlowMod) error {
	// If no Openflow entries are requested to be added or modified or deleted on the OVS bridge, return immediately.
	if len(addflows) == 0 && len(modFlows) == 0 && len(delFlows) == 0 {
		klog.V(2).Info("No Openflow entries need to be synced to the OVS bridge, returning")
		return nil
	}
	// Create a new transaction.
	tx := b.ofSwitch.NewTransaction(ofctrl.Atomic)
	// Open a bundle on the OFSwitch.
	if err := tx.Begin(); err != nil {
		return err
	}

	syncFlows := func(flows []*openflow15.FlowMod, operation int) error {
		for _, flowMod := range flows {
			flowMod.Command = uint8(operation)
			// "AddFlow" operation is async, the function only returns error which occur when constructing and sending
			// the BundleAdd message. An absence of error does not mean that all Openflow entries are added into the
			// bundle by the switch. The number of entries successfully added to the bundle by the switch will be
			// returned by function "Complete".
			if err := tx.AddFlow(flowMod); err != nil {
				// Close the bundle and cancel it if there is error when adding the FlowMod message.
				_, err := tx.Complete()
				if err == nil {
					tx.Abort()
				}
				return err
			}
		}
		return nil
	}

	// Install new Openflow entries with the opened bundle.
	if err := syncFlows(addflows, openflow15.FC_ADD); err != nil {
		return err
	}
	// Modify existing Openflow entries with the opened bundle.
	if err := syncFlows(modFlows, openflow15.FC_MODIFY_STRICT); err != nil {
		return err
	}
	// Delete Openflow entries with the opened bundle.
	if err := syncFlows(delFlows, openflow15.FC_DELETE_STRICT); err != nil {
		return err
	}

	// Close the bundle before committing it to the OFSwitch.
	count, err := tx.Complete()
	if err != nil {
		return err
	} else if count != len(addflows)+len(modFlows)+len(delFlows) {
		// This case should not be possible if all the calls to "tx.AddFlow" returned nil. This is just a sanity check.
		tx.Abort()
		return errors.New("failed to add all Openflow entries in one transaction, cancelling it")
	}

	// Commit the bundle to the OFSwitch. The "Commit" operation is sync, and the Openflow entries should be realized if
	// there is no error returned.
	if err := tx.Commit(); err != nil {
		return err
	}

	// Update TableStatus after the transaction is committed successfully.
	for _, message := range addflows {
		table := b.tableCache[message.TableId]
		table.UpdateStatus(1)
	}
	for _, message := range delFlows {
		table := b.tableCache[message.TableId]
		table.UpdateStatus(-1)
	}
	return nil
}

func (b *OFBridge) AddOFEntriesInBundle(addEntries []OFEntry, modEntries []OFEntry, delEntries []OFEntry) error {
	// If no Openflow entries are requested to be added or modified or deleted on the OVS bridge, return immediately.
	if len(addEntries) == 0 && len(modEntries) == 0 && len(delEntries) == 0 {
		klog.V(2).Info("No Openflow entries need to be synced to the OVS bridge, returning")
		return nil
	}
	type entryOperation struct {
		entry     OFEntry
		operation OFOperation
	}
	var flowSet, groupSet []entryOperation
	// Classify the entries according to the EntryType, and set a correct operation type.
	checkMessages := func(entries []OFEntry, operation OFOperation) {
		for _, entry := range entries {
			switch entry.Type() {
			case FlowEntry:
				flow := entry.(*ofFlow)
				flowSet = append(flowSet, entryOperation{
					entry:     flow,
					operation: operation,
				})
			case GroupEntry:
				group := entry.(*ofGroup)
				groupSet = append(groupSet, entryOperation{
					entry:     group,
					operation: operation,
				})
			}
		}
	}

	checkMessages(addEntries, AddMessage)
	checkMessages(modEntries, ModifyMessage)
	checkMessages(delEntries, DeleteMessage)

	// Create a new transaction. Use ofctrl.Ordered to ensure the messages are realized on OVS in the order of adding
	// messages. This type could ensure Group entry is realized on OVS in advance of Flow entry.
	tx := b.ofSwitch.NewTransaction(ofctrl.Ordered)
	// Open a bundle on the OFSwitch.
	if err := tx.Begin(); err != nil {
		return err
	}

	var sentMessages int
	addMessage := func(entrySet []entryOperation) error {
		if entrySet == nil {
			return nil
		}
		for _, e := range entrySet {
			messages, err := e.entry.GetBundleMessages(e.operation)
			if err != nil {
				return err
			}
			sentMessages += len(messages)
			// "AddMessage" operation is async, the function only returns error which occur when constructing and sending
			// the BundleAdd message. An absence of error does not mean that all OpenFlow entries are added into the
			// bundle by the switch. The number of entries successfully added to the bundle by the switch will be
			// returned by function "Complete".
			for _, message := range messages {
				if err := tx.AddMessage(message); err != nil {
					// Close the bundle and cancel it if there is error when adding the FlowMod message.
					_, err := tx.Complete()
					if err == nil {
						tx.Abort()
					}
					return err
				}
			}
		}
		return nil
	}

	// Add Group modification messages in advance of Flow modification messages, so it can ensure the dependent Group
	// exists when adding a new Flow entry. When OVS is deleting the Group, the corresponding Flow entry is removed
	// together. It doesn't return an error when OVS is deleting a non-existing Flow entry.
	for _, entries := range [][]entryOperation{
		groupSet, flowSet,
	} {
		if err := addMessage(entries); err != nil {
			return nil
		}
	}

	// Close the bundle before committing it to the OFSwitch.
	count, err := tx.Complete()
	if err != nil {
		return err
	} else if count != sentMessages {
		// This case should not be possible if all the calls to "tx.AddMessage" returned nil. This is just a sanity check.
		tx.Abort()
		return errors.New("failed to add all Openflow entries in one transaction, cancelling it")
	}

	// Commit the bundle to the OFSwitch. The "Commit" operation is sync, and the Openflow entries should be realized if
	// there is no error returned.
	if err := tx.Commit(); err != nil {
		return err
	}

	// Update TableStatus after the transaction is committed successfully.
	for _, e := range flowSet {
		ofFlow := e.entry.(*ofFlow)
		switch e.operation {
		case AddMessage:
			ofFlow.table.UpdateStatus(1)
		case DeleteMessage:
			ofFlow.table.UpdateStatus(-1)
		}
	}

	return nil
}

type PacketInQueue struct {
	rateLimiter *rate.Limiter
	packetsCh   chan *ofctrl.PacketIn
}

func NewPacketInQueue(size int, r rate.Limit) *PacketInQueue {
	return &PacketInQueue{rateLimiter: rate.NewLimiter(r, size), packetsCh: make(chan *ofctrl.PacketIn, size)}
}

func (q *PacketInQueue) AddOrDrop(packet *ofctrl.PacketIn) bool {
	select {
	case q.packetsCh <- packet:
		return true
	default:
		// Channel is full.
		return false
	}
}

func (q *PacketInQueue) GetRateLimited(stopCh <-chan struct{}) *ofctrl.PacketIn {
	when := q.rateLimiter.Reserve().Delay()
	t := time.NewTimer(when)
	defer t.Stop()

	select {
	case <-stopCh:
		return nil
	case <-t.C:
		break
	}
	select {
	case <-stopCh:
		return nil
	case packet := <-q.packetsCh:
		return packet
	}
}

func (b *OFBridge) SubscribePacketIn(category uint8, pktInQueue *PacketInQueue) error {
	_, exist := b.pktConsumers.Load(category)
	if exist {
		return fmt.Errorf("packetIn category %d already exists", category)
	}
	b.pktConsumers.Store(category, pktInQueue)
	return nil
}

func (b *OFBridge) SendPacketOut(packetOut *ofctrl.PacketOut) error {
	return b.ofSwitch.Send(packetOut.GetMessage())
}

func (b *OFBridge) ResumePacket(packetIn *ofctrl.PacketIn) error {
	return b.ofSwitch.ResumePacket(packetIn)
}

func (b *OFBridge) BuildPacketOut() PacketOutBuilder {
	return &ofPacketOutBuilder{
		pktOut: new(ofctrl.PacketOut),
	}
}

// MaxRetry is a callback from OFController. It sets the max retry count that OFController attempts to connect to OFSwitch.
func (b *OFBridge) MaxRetry() int {
	return b.maxRetrySec
}

// RetryInterval is a callback from OFController. It sets the interval in that the OFController will initiate next connection
// to OFSwitch if it fails this time.
func (b *OFBridge) RetryInterval() time.Duration {
	return b.retryInterval
}

func (b *OFBridge) setPacketInFormatTo2() {
	b.ofSwitch.SetPacketInFormat(openflow15.OFPUTIL_PACKET_IN_NXT2)
}

func (b *OFBridge) queryTableFeatures() {
	mpartRequest := &openflow15.MultipartRequest{
		Header: openflow15.NewOfp15Header(),
		Type:   openflow15.MultipartType_TableFeatures,
		Flags:  0,
	}
	mpartRequest.Header.Type = openflow15.Type_MultiPartRequest
	mpartRequest.Header.Length = mpartRequest.Len()
	// Use a buffer for the channel to avoid blocking the OpenFlow connection inbound channel, since it takes time when
	// sending the Multipart Request messages to modify the tables' names. The buffer size "20" is the observed number
	// of the Multipart Reply messages sent from OVS.
	tableFeatureCh := make(chan *openflow15.MultipartReply, 20)
	b.registerMpReplyCh(mpartRequest.Xid, tableFeatureCh)
	go func() {
		// Delete the channel which is used to receive the MultipartReply message after all tables' features are received.
		defer b.unregisterMpReplyCh(mpartRequest.Xid)
		b.processTableFeatures(tableFeatureCh)
	}()
	b.ofSwitch.Send(mpartRequest)
}

func (b *OFBridge) processTableFeatures(ch chan *openflow15.MultipartReply) {
	header := openflow15.NewOfp15Header()
	header.Type = openflow15.Type_MultiPartRequest
	// Since the initial MultipartRequest doesn't specify any table ID, OVS will reply all tables' (except the hidden one)
	// features in the reply. Here we complete the loop after we receive all the reply messages, while the reply message
	// is configured with Flags=0.
	for {
		select {
		case rpl := <-ch:
			request := &openflow15.MultipartRequest{
				Header: header,
				Type:   openflow15.MultipartType_TableFeatures,
				Flags:  rpl.Flags,
			}
			// A MultipartReply message may have one or many OFPTableFeatures messages, and MultipartReply.Body is a
			// slice of these messages.
			for _, body := range rpl.Body {
				tableFeature := body.(*openflow15.TableFeatures)
				// Modify table name if the table is in the pipeline, otherwise use the default table features.
				// OVS doesn't allow to skip any table except the hidden table (always the last table) in a table_features
				// request. So use the existing table features for the tables that Antrea doesn't define in the pipeline.
				if t, ok := b.tableCache[tableFeature.TableID]; ok {
					// Set table name with the configured value.
					copy(tableFeature.Name[0:], t.name)
				}
				request.Body = append(request.Body, tableFeature)
			}
			request.Length = request.Len()
			b.ofSwitch.Send(request)
			// OVS uses "Flags=0" in the last MultipartReply message to indicate all tables' features have been sent.
			// Here use this mark to identify all related messages are received and complete the loop.
			if rpl.Flags == 0 {
				break
			}
		}
	}
}

func (b *OFBridge) registerMpReplyCh(xid uint32, ch chan *openflow15.MultipartReply) {
	b.mpReplyChsMutex.Lock()
	defer b.mpReplyChsMutex.Unlock()
	b.mpReplyChs[xid] = ch

}

func (b *OFBridge) unregisterMpReplyCh(xid uint32) {
	b.mpReplyChsMutex.Lock()
	defer b.mpReplyChsMutex.Unlock()
	delete(b.mpReplyChs, xid)
}

func NewOFBridge(br string, mgmtAddr string) *OFBridge {
	s := &OFBridge{
		bridgeName:           br,
		mgmtAddr:             mgmtAddr,
		tableCache:           make(map[uint8]*ofTable),
		retryInterval:        1 * time.Second,
		pktConsumers:         sync.Map{},
		mpReplyChs:           make(map[uint32]chan *openflow15.MultipartReply),
		tunMetadataLengthMap: make(map[uint16]uint8),
	}
	s.controller = ofctrl.NewController(s)
	return s
}

var tableID uint8

func NextTableID() (id uint8) {
	id = tableID
	tableID += 1
	return
}

// ResetTableID is used to reset the initial tableID so that the table ID increases from 0.
// This function is only for test.
func ResetTableID() {
	tableID = 0
}

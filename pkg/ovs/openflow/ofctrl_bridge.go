package openflow

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/ofnet/ofctrl"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/metrics"
)

const (
	ofTableExistsError = "Table already exists"
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
	stage      StageID
	pipelineID uint8

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
	return t.stage
}

func (t *ofTable) GetPipelineID() uint8 {
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
	metrics.OVSFlowCount.WithLabelValues(strconv.Itoa(int(t.id))).Add(float64(flowCountDelta))

	t.updateTime = time.Now()
}

func (t *ofTable) ResetStatus() {
	t.Lock()
	defer t.Unlock()

	t.flowCount = 0

	metrics.OVSFlowCount.WithLabelValues(strconv.Itoa(int(t.id))).Set(0)

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
	flowStats := make(map[uint64]*FlowStates)
	for _, stat := range ofStats {
		cookie := stat.Cookie
		s := &FlowStates{
			TableID:         stat.TableId,
			PacketCount:     stat.PacketCount,
			DurationNSecond: stat.DurationNSec,
		}
		flowStats[cookie] = s
	}
	return flowStats, nil
}

func NewOFTable(id uint8, name string, stage StageID, pipelineID uint8) Table {
	return &ofTable{
		id:         id,
		name:       name,
		stage:      stage,
		pipelineID: pipelineID,
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
	// pktConsumers is a map from PacketIn reason to the channel that is used to publish the PacketIn message.
	pktConsumers      sync.Map
	multipartReplyChs map[uint32]chan *openflow13.MultipartReply
}

func (b *OFBridge) CreateGroup(id GroupIDType) Group {
	ofctrlGroup, err := b.ofSwitch.NewGroup(uint32(id), ofctrl.GroupSelect)
	if err != nil { // group already exists
		ofctrlGroup = b.ofSwitch.GetGroup(uint32(id))
	}
	g := &ofGroup{bridge: b, ofctrl: ofctrlGroup}
	return g
}

func (b *OFBridge) DeleteGroup(id GroupIDType) bool {
	g := b.ofSwitch.GetGroup(uint32(id))
	if g == nil {
		return true
	}
	if err := g.Delete(); err != nil {
		return false
	}
	return true
}

func (b *OFBridge) CreateMeter(id MeterIDType, flags ofctrl.MeterFlag) Meter {
	ofctrlMeter, err := b.ofSwitch.NewMeter(uint32(id), flags)

	if err != nil {
		ofctrlMeter = b.ofSwitch.GetMeter(uint32(id))
	}
	m := &ofMeter{bridge: b, ofctrl: ofctrlMeter}
	return m
}

func (b *OFBridge) DeleteMeter(id MeterIDType) bool {
	m := b.ofSwitch.GetMeter(uint32(id))
	if m == nil {
		return true
	}
	if err := m.Delete(); err != nil {
		return false
	}
	return true
}

func (b *OFBridge) DeleteMeterAll() error {
	// Clear all existing meter entries
	// TODO: this should be defined in libOpenflow
	const OFPM_ALL = 0xffffffff // Represents all meters
	meterMod := openflow13.NewMeterMod()
	meterMod.MeterId = OFPM_ALL
	meterMod.Command = openflow13.OFPMC_DELETE
	if err := b.ofSwitch.Send(meterMod); err != nil {
		return err
	}
	return nil
}

func (b *OFBridge) CreateTable(table Table, next uint8, missAction MissActionType) Table {
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

// DeleteTable removes the table from ofctrl.OFSwitch, and remove from local cache.
func (b *OFBridge) DeleteTable(id uint8) bool {
	err := b.ofSwitch.DeleteTable(id)
	if err != nil {
		return false
	}

	b.Lock()
	defer b.Unlock()

	delete(b.tableCache, id)
	return true
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
	klog.V(2).Infof("Received packet: %+v", packet)
	reason := packet.Reason
	v, found := b.pktConsumers.Load(reason)
	if found {
		pktInQueue, _ := v.(*PacketInQueue)
		pktInQueue.AddOrDrop(packet)
	}
}

// SwitchConnected is a callback when the remote OFSwitch is connected.
func (b *OFBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	klog.Infof("OFSwitch is connected: %v", sw.DPID())
	// initialize tables.
	b.ofSwitch = sw
	b.ofSwitch.EnableMonitor()
	b.initialize()
	go func() {
		// b.connected is nil if it is an automatic reconnection but not triggered by OFSwitch.Connect.
		if b.connected != nil {
			b.connected <- true
		}
		b.connCh <- struct{}{}
	}()
}

// MultipartReply is a callback when multipartReply message is received on ofctrl.OFSwitch is connected.
// Client uses this method to handle the reply message if it has customized MultipartRequest message.
func (b *OFBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
	if ch, ok := b.multipartReplyChs[rep.Xid]; ok {
		ch <- rep
	}
}

func (b *OFBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	klog.Infof("OFSwitch is disconnected: %v", sw.DPID())
}

// initialize creates ofctrl.Table for each table in the tableCache.
func (b *OFBridge) initialize() {
	b.Lock()
	defer b.Unlock()

	for id, table := range b.tableCache {
		if id == 0 {
			table.Table = b.ofSwitch.DefaultTable()
		} else {
			ofTable, err := b.ofSwitch.NewTable(id)
			if err != nil && err.Error() == ofTableExistsError {
				ofTable = b.ofSwitch.GetTable(id)
			}
			table.Table = ofTable
		}
		// reset flow counts, which is needed for reconnections
		table.ResetStatus()
	}

	b.queryTableFeatures()

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
	flowStats := make(map[uint64]*FlowStates)
	for _, stat := range ofStats {
		cookie := stat.Cookie
		s := &FlowStates{
			TableID:         stat.TableId,
			PacketCount:     stat.PacketCount,
			DurationNSecond: stat.DurationNSec,
		}
		flowStats[cookie] = s
	}
	return flowStats, nil
}

// DeleteFlowsByCookie removes Openflow entries from OFSwitch. The removed Openflow entries use the specific CookieID.
func (b *OFBridge) DeleteFlowsByCookie(cookieID, cookieMask uint64) error {
	flowMod := openflow13.NewFlowMod()
	flowMod.Command = openflow13.FC_DELETE
	flowMod.Cookie = cookieID
	flowMod.CookieMask = cookieMask
	flowMod.OutPort = openflow13.P_ANY
	flowMod.OutGroup = openflow13.OFPG_ANY
	flowMod.TableId = openflow13.OFPTT_ALL
	return b.ofSwitch.Send(flowMod)
}

func (b *OFBridge) IsConnected() bool {
	return b.ofSwitch.IsReady()
}

func (b *OFBridge) AddFlowsInBundle(addflows []Flow, modFlows []Flow, delFlows []Flow) error {
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

	syncFlows := func(flows []Flow, operation int) error {
		for _, flow := range flows {
			ofFlow := flow.(*ofFlow)
			// "AddFlow" operation is async, the function only returns error which occur when constructing and sending
			// the BundleAdd message. An absence of error does not mean that all Openflow entries are added into the
			// bundle by the switch. The number of entries successfully added to the bundle by the switch will be
			// returned by function "Complete".
			flowMod, err := ofFlow.Flow.GetBundleMessage(operation)
			if err != nil {
				return err
			}
			if err := tx.AddMessage(flowMod); err != nil {
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
	if err := syncFlows(addflows, openflow13.FC_ADD); err != nil {
		return err
	}
	// Modify existing Openflow entries with the opened bundle.
	if err := syncFlows(modFlows, openflow13.FC_MODIFY_STRICT); err != nil {
		return err
	}
	// Delete Openflow entries with the opened bundle.
	if err := syncFlows(delFlows, openflow13.FC_DELETE_STRICT); err != nil {
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
	for _, flow := range addflows {
		ofFlow := flow.(*ofFlow)
		ofFlow.table.UpdateStatus(1)
	}
	for _, flow := range delFlows {
		ofFlow := flow.(*ofFlow)
		ofFlow.table.UpdateStatus(-1)
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

	addMessage := func(entrySet []entryOperation) error {
		if entrySet == nil {
			return nil
		}
		for _, e := range entrySet {
			msg, err := e.entry.GetBundleMessage(e.operation)
			if err != nil {
				return err
			}
			// "AddMessage" operation is async, the function only returns error which occur when constructing and sending
			// the BundleAdd message. An absence of error does not mean that all OpenFlow entries are added into the
			// bundle by the switch. The number of entries successfully added to the bundle by the switch will be
			// returned by function "Complete".
			if err := tx.AddMessage(msg); err != nil {
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
	} else if count != len(addEntries)+len(modEntries)+len(delEntries) {
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
	return &PacketInQueue{rateLimiter: rate.NewLimiter(r, 1), packetsCh: make(chan *ofctrl.PacketIn, size)}
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

func (b *OFBridge) SubscribePacketIn(reason uint8, pktInQueue *PacketInQueue) error {
	_, exist := b.pktConsumers.Load(reason)
	if exist {
		return fmt.Errorf("packetIn reason %d already exists", reason)
	}
	b.pktConsumers.Store(reason, pktInQueue)
	return nil
}

func (b *OFBridge) AddTLVMap(optClass uint16, optType uint8, optLength uint8, tunMetadataIndex uint16) error {
	if err := b.ofSwitch.AddTunnelTLVMap(optClass, optType, optLength, tunMetadataIndex); err != nil {
		return err
	}
	return nil
}

func (b *OFBridge) SendPacketOut(packetOut *ofctrl.PacketOut) error {
	return b.ofSwitch.Send(packetOut.GetMessage())
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

func (b *OFBridge) queryTableFeatures() {
	mpartRequest := &openflow13.MultipartRequest{
		Header: openflow13.NewOfp13Header(),
		Type:   openflow13.MultipartType_TableFeatures,
		Flags:  0,
	}
	mpartRequest.Header.Type = openflow13.Type_MultiPartRequest
	mpartRequest.Header.Length = mpartRequest.Len()
	// Use a buffer for the channel to avoid blocking the OpenFlow connection inbound channel, since it takes time when
	// sending the Multipart Request messages to modify the tables' names. The buffer size "20" is the observed number
	// of the Multipart Reply messages sent from OVS.
	tableFeatureCh := make(chan *openflow13.MultipartReply, 20)
	b.multipartReplyChs[mpartRequest.Xid] = tableFeatureCh
	go func() {
		// Delete the channel which is used to receive the MultipartReply message after all tables' features are received.
		defer func() {
			delete(b.multipartReplyChs, mpartRequest.Xid)
		}()
		b.processTableFeatures(tableFeatureCh)
	}()
	b.ofSwitch.Send(mpartRequest)
}

func (b *OFBridge) processTableFeatures(ch chan *openflow13.MultipartReply) {
	header := openflow13.NewOfp13Header()
	header.Type = openflow13.Type_MultiPartRequest
	// Since the initial MultipartRequest doesn't specify any table ID, OVS will reply all tables' (except the hidden one)
	// features in the reply. Here we complete the loop after we receive all the reply messages, while the reply message
	// is configured with Flags=0.
	for {
		select {
		case rpl := <-ch:
			request := &openflow13.MultipartRequest{
				Header: header,
				Type:   openflow13.MultipartType_TableFeatures,
				Flags:  rpl.Flags,
			}
			// A MultipartReply message may have one or many OFPTableFeatures messages, and MultipartReply.Body is a
			// slice of these messages.
			for _, body := range rpl.Body {
				tableFeature := body.(*openflow13.OFPTableFeatures)
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

func NewOFBridge(br string, mgmtAddr string) Bridge {
	s := &OFBridge{
		bridgeName:        br,
		mgmtAddr:          mgmtAddr,
		tableCache:        make(map[uint8]*ofTable),
		retryInterval:     1 * time.Second,
		pktConsumers:      sync.Map{},
		multipartReplyChs: make(map[uint32]chan *openflow13.MultipartReply),
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

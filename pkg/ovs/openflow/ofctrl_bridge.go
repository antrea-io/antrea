package openflow

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"golang.org/x/time/rate"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
)

const (
	ofTableExistsError = "Table already exists"
)

// ofTable implements openflow.Table.
type ofTable struct {
	// sync.RWMutex protects ofTable status from concurrent modification and reading.
	sync.RWMutex
	id         TableIDType
	next       TableIDType
	missAction MissActionType
	flowCount  uint
	updateTime time.Time

	*ofctrl.Table
}

func (t *ofTable) GetID() TableIDType {
	return t.id
}

func (t *ofTable) Status() TableStatus {
	t.RLock()
	defer t.RUnlock()

	return TableStatus{
		ID:         uint(t.id),
		FlowCount:  t.flowCount,
		UpdateTime: t.updateTime,
	}
}

func (t *ofTable) GetMissAction() MissActionType {
	return t.missAction
}

func (t *ofTable) GetNext() TableIDType {
	return t.next
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

func newOFTable(id, next TableIDType, missAction MissActionType) *ofTable {
	return &ofTable{
		id:         id,
		next:       next,
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
	tableCache map[TableIDType]*ofTable

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
	pktConsumers sync.Map
}

func (b *OFBridge) CreateGroup(id GroupIDType) Group {
	ofctrlGroup, err := b.ofSwitch.NewGroup(uint32(id), ofctrl.GroupSelect)
	if err != nil {
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

func (b *OFBridge) CreateTable(id, next TableIDType, missAction MissActionType) Table {
	t := newOFTable(id, next, missAction)

	b.Lock()
	defer b.Unlock()

	b.tableCache[id] = t
	return t
}

// DeleteTable removes the table from ofctrl.OFSwitch, and remove from local cache.
func (b *OFBridge) DeleteTable(id TableIDType) bool {
	err := b.ofSwitch.DeleteTable(uint8(id))
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
			ofTable, err := b.ofSwitch.NewTable(uint8(id))
			if err != nil && err.Error() == ofTableExistsError {
				ofTable = b.ofSwitch.GetTable(uint8(id))
			}
			table.Table = ofTable
		}
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

func NewOFBridge(br string, mgmtAddr string) Bridge {
	s := &OFBridge{
		bridgeName:    br,
		mgmtAddr:      mgmtAddr,
		tableCache:    make(map[TableIDType]*ofTable),
		retryInterval: 1 * time.Second,
		pktConsumers:  sync.Map{},
	}
	s.controller = ofctrl.NewController(s)
	return s
}

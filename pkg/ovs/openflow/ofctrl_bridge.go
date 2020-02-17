package openflow

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/klog"
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
	t.updateTime = time.Now()
}

func (t *ofTable) ResetStatus() {
	t.Lock()
	defer t.Unlock()

	t.flowCount = 0
	t.updateTime = time.Now()
}

// BuildFlow returns FlowBuilder object to help construct Openflow entry.
func (t *ofTable) BuildFlow(priority uint16) FlowBuilder {
	fb := new(ofFlowBuilder)
	fb.table = t
	// Set ofctl.Table to Flow, otherwise the flow can't find OFSwitch to install.
	fb.Flow = ofctrl.Flow{Table: t.Table, Match: ofctrl.FlowMatch{Priority: priority}}
	return fb
}

// DumpFlows dumps all existing Openflow entries from OFSwitch using cookie ID and table ID as filters.
func (t *ofTable) DumpFlows(cookieID, cookieMask uint64) map[uint64]*FlowStates {
	ofStats := t.Table.Switch.DumpFlowStats(cookieID, cookieMask, nil, &t.TableId)
	if ofStats == nil {
		return nil
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
	return flowStats
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
	klog.Infof("Received packet: %+v", packet)
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

// Initialize creates ofctrl.Table for each table in the tableCache.
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
func (b *OFBridge) DumpFlows(cookieID, cookieMask uint64) map[uint64]*FlowStates {
	ofStats := b.ofSwitch.DumpFlowStats(cookieID, cookieMask, nil, nil)
	if ofStats == nil {
		return nil
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
	return flowStats
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
	b.ofSwitch.Send(flowMod)
	return nil
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
			ofFlow.Flow.NextElem = ofFlow.lastAction
			// "AddFlow" operation is async, the function only returns error which occur when constructing and sending
			// the BundleAdd message. An absence of error does not mean that all Openflow entries are added into the
			// bundle by the switch. The number of entries successfully added to the bundle by the switch will be
			// returned by function "Complete".
			flowMod, err := ofFlow.Flow.GenerateFlowModMessage(operation)
			if err != nil {
				return err
			}
			if err := tx.AddFlow(flowMod); err != nil {
				// Close the bundle and abort it if there is error when adding the FlowMod message.
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
		return errors.New("failed to add all Openflow entries in one transaction, abort it")
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
		ofFlow.UpdateInstallStatus(true)
	}
	for _, flow := range modFlows {
		ofFlow := flow.(*ofFlow)
		ofFlow.UpdateInstallStatus(true)
	}
	for _, flow := range delFlows {
		ofFlow := flow.(*ofFlow)
		ofFlow.table.UpdateStatus(-1)
	}
	return nil
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
	}
	s.controller = ofctrl.NewController(s)
	return s
}

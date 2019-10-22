package openflow

import (
	"fmt"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/klog"
)

const (
	OVSRunDir          = "/var/run/openvswitch"
	ofTableExistsError = "Table already exists"
)

// ofTable implements openflow.Table.
type ofTable struct {
	sync.Mutex
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

// BuildFlow returns FlowBuilder object to help construct Openflow entry.
func (t *ofTable) BuildFlow() FlowBuilder {
	fb := new(ofFlowBuilder)
	fb.table = t
	// Set ofctl.Table to Flow, otherwise the flow can't find OFSwitch to install.
	fb.Flow = ofctrl.Flow{Table: t.Table}
	return fb
}

// DumpFlows dumps all existent Openflow entries from OFSwitch using cookie ID and table ID as filters
func (t *ofTable) DumpFlows(cookieID, cookieMask uint64) map[uint64]*FlowStats {
	ofStats := t.Table.Switch.DumpFlowStats(cookieID, cookieMask, nil, &t.TableId)
	if ofStats == nil {
		return nil
	}
	flowStats := make(map[uint64]*FlowStats)
	for _, stat := range ofStats {
		cookie := stat.Cookie
		s := &FlowStats{
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
	sync.Mutex
	bridgeName string
	// tableCache is used to cache ofTables
	tableCache map[TableIDType]*ofTable

	// ofSwitch is the target OFSwitch
	ofSwitch *ofctrl.OFSwitch
	// controller helps maintain connections to remote OFSwitch.
	controller *ofctrl.Controller
	// retryInterval is the interval for retry connection.
	retryInterval time.Duration
	// maxRetrySec is the seconds waiting for connection to the OFSwitch.
	maxRetrySec int

	// channel to notify agent OFSwitch is connected
	connCh chan struct{}
	// connected is an internal channel to notify if connected to the OFSwitch or not. It is used only in Connect method
	connected chan bool
}

func (b *OFBridge) CreateTable(id, next TableIDType, missAction MissActionType) Table {
	t := newOFTable(id, next, missAction)
	b.Lock()
	defer b.Unlock()

	b.tableCache[id] = t
	return t
}

func (b *OFBridge) GetName() string {
	return b.bridgeName
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

// Initialize creates ofctrl.Table for each table in the tableCache
func (b *OFBridge) initialize() {
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
	}
}

// Connect initiates the connection to the OFSwitch, and initializes ofTables after connected.
func (b *OFBridge) Connect(maxRetrySec int, connectionCh chan struct{}) error {
	b.connCh = connectionCh
	b.maxRetrySec = maxRetrySec
	b.connected = make(chan bool)
	errCh := make(chan error)
	sockPath := fmt.Sprintf("%s/%s.mgmt", OVSRunDir, b.bridgeName)
	go func() {
		err := b.controller.Connect(sockPath)
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
func (b *OFBridge) DumpFlows(cookieID, cookieMask uint64) map[uint64]*FlowStats {
	ofStats := b.ofSwitch.DumpFlowStats(cookieID, cookieMask, nil, nil)
	if ofStats == nil {
		return nil
	}
	flowStats := make(map[uint64]*FlowStats)
	for _, stat := range ofStats {
		cookie := stat.Cookie
		s := &FlowStats{
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

// MaxRetry is a callback from OFController. It sets the max retry count that OFController attempts to connect to OFSwitch.
func (b *OFBridge) MaxRetry() int {
	return b.maxRetrySec
}

// RetryInterval is a callback from OFController. It sets the interval in that the OFController will initiate next connection
// to OFSwitch if it fails this time.
func (b *OFBridge) RetryInterval() time.Duration {
	return b.retryInterval
}

func NewOFBridge(br string) *OFBridge {
	s := &OFBridge{
		bridgeName:    br,
		tableCache:    make(map[TableIDType]*ofTable),
		retryInterval: 1 * time.Second,
	}
	s.controller = ofctrl.NewController(s)
	return s
}

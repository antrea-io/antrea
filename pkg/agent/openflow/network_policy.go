package openflow

import (
	"fmt"
	"k8s.io/klog"
	"net"
	"sync"

	"k8s.io/api/networking/v1"

	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

type AddressCategory uint8

const (
	IPAddr AddressCategory = iota
	IPNetAddr
	OFPortAddr
)

type AddressType int

const (
	SrcAddress AddressType = iota
	DstAddress
)

// ConjunctionNotFound is an error response when the specified conjunction is not found from the local cache.
type ConjunctionNotFound uint32

func (e *ConjunctionNotFound) Error() string {
	return fmt.Sprintf("conjunction with ID %d not found", uint32(*e))
}

func newConjunctionNotFound(conjunctionID uint32) *ConjunctionNotFound {
	err := ConjunctionNotFound(conjunctionID)
	return &err
}

type Address interface {
	GetMatchValue() string
	GetMatchKey(addrType AddressType) string
}

// IP address calculated from Pod's address.
type IPAddress net.IP

func (a *IPAddress) GetMatchKey(addrType AddressType) string {
	switch addrType {
	case SrcAddress:
		return "nw_src"
	case DstAddress:
		return "nw_dst"
	default:
		klog.Errorf("unknown AddressType %d in IPAddress", addrType)
		return ""
	}
}

func (a *IPAddress) GetMatchValue() string {
	addr := net.IP(*a)
	return addr.String()
}

func NewIPAddress(addr net.IP) *IPAddress {
	ia := IPAddress(addr)
	return &ia
}

// IP block calculated from Pod's address.
type IPNetAddress net.IPNet

func (a *IPNetAddress) GetMatchKey(addrType AddressType) string {
	switch addrType {
	case SrcAddress:
		return "nw_src"
	case DstAddress:
		return "nw_dst"
	default:
		klog.Errorf("unknown AddressType %d in IPNetAddress", addrType)
		return ""
	}
}

func (a *IPNetAddress) GetMatchValue() string {
	addr := net.IPNet(*a)
	return addr.String()
}

func NewIPNetAddress(addr net.IPNet) *IPNetAddress {
	ia := IPNetAddress(addr)
	return &ia
}

// OFPortAddress is the Openflow port of an interface.
type OFPortAddress int32

func (a *OFPortAddress) GetMatchKey(addrType AddressType) string {
	switch addrType {
	case SrcAddress:
		return "in_port"
	case DstAddress:
		return fmt.Sprintf("%s[%d..%d]", portCacheReg.reg(), ofportRegRange[0], ofportRegRange[1])
	default:
		klog.Errorf("unknown AddressType %d in OFPortAddress", addrType)
		return ""
	}
}

func (a *OFPortAddress) GetMatchValue() string {
	return fmt.Sprintf("%d", int32(*a))
}

func NewOFPortAddress(addr int32) *OFPortAddress {
	a := OFPortAddress(addr)
	return &a
}

// PolicyRule groups configurations to set up conjunctive match for egress/ingress policy rules.
type PolicyRule struct {
	ID         uint32
	Direction  v1.PolicyType
	From       []Address
	ExceptFrom []Address
	To         []Address
	ExceptTo   []Address
	Service    []*v1.NetworkPolicyPort
}

// TODO: change matchKey/matchValue to efficient types after switching to OF Gobinding.
// conjunctiveMatch generates match conditions for conjunctive match flow entry, including source or destination
// IP address, ofport number of OVS interface, or Service port. When conjunctiveMatch is used to match IP
// address or ofport number, matchProtocol is "ip". When conjunctiveMatch is used to match Service
// port, matchProtocol is Service protocol. If Service protocol is not set, "tcp" is used by default.
type conjunctiveMatch struct {
	matchKey      string
	matchValue    string
	matchProtocol string
}

// conjunctiveAction generates the conjunction action in Openflow entry.
type conjunctiveAction struct {
	conjID   uint32
	clauseID uint8
	nClause  uint8
}

// conjunctiveMatchFlowBuilder generates conjunctive match flow entries for conjunctions share the
// same match conditions.
type conjunctiveMatchFlowBuilder struct {
	*conjunctiveMatch
	// actions is a mapping from conjunction ID to conjunctiveAction.
	actions   map[uint32]*conjunctiveAction
	client    *client
	lock      sync.RWMutex         // Lock for action modifications among multiple conjunctions.
	dropTable *binding.TableIDType // Install flow entry using this match condition on dropTable if it is not nil.
	installed bool                 // Add flow entry if installed is false, and modify flow entry if true.
}

// conjunction includes all Openflow entries for a NetworkPolicy rule, including conjunction action flows, and
// conjunctive match flows. Conjunction action flows use this conjunction ID as match condition.
// Conjunctive match flows are grouped by clauses, and their match condition includes from address,
// to address, or service port configured in NetworkPolicy rule.
type conjunction struct {
	id            uint32
	fromClause    *clause
	toClause      *clause
	serviceClause *clause
	actionFlows   []binding.Flow
}

// clause groups conjunctive match flows. All matches in the same clause represent source addresses, or
// destination addresses or service ports in a NetworkPolicy rule.
type clause struct {
	action *conjunctiveAction
	// matches is a mapping for conjunctive match conditions in the same clause. The key is a unique string generated
	// from the conjunctive match condition.
	matches map[string]*conjunctiveMatch
	// read/write lock for accessing matches
	lock sync.RWMutex
	// ruleTable is where to install conjunctive match flows.
	ruleTable binding.Table
	// dropTable is where to install Openflow entries to drop the packet sent to or from the BindingGroup but does not
	// satisfy any conjunctive match conditions. It should be nil, if the clause is used for matching service port.
	dropTable binding.Table
}

// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for
// ruleTable and the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the
// dropTable.
func (c *client) InstallPolicyRuleFlows(rule *PolicyRule) error {
	// TODO: 1. create conjunction object, and add it into c.policyCache.
	//       2. Install action flow.
	//       3. Install conjunctive match flows if exists in rule.Form/To/Service
	return nil
}

// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
func (c *client) UninstallPolicyRuleFlows(ruleID uint32) error {
	// TODO: 1. Check if conjunction exists in c.policyCache, if false, return not found error.
	//       2. Uninstall action flow.
	//       3. Remove conjunction from actions of conjunctive matches.
	//       4. Remove conjunction from c.policyCache

	return nil
}

// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is srcAddress, the
// addresses are added to PolicyRule.From, else to PolicyRule.To.
func (c *client) AddPolicyRuleAddress(ruleID uint32, addrType AddressType, addresses []Address) error {
	// TODO: 1. Check if conjunction exists in c.policyCache, if not exist, return not found error.
	//  	 2. Add conjunction to actions of conjunctive match using specific address.
	//  	 3. Check if need to install default drop flow for specific address

	return nil
}

// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is srcAddress, the addresses
// are removed from PolicyRule.From, else from PolicyRule.To.
func (c *client) DeletePolicyRuleAddress(ruleID uint32, addrType AddressType, addresses []Address) error {
	// TODO: 1. Check if conjunction exists in c.policyCache, if false, return not found error.
	//  	 2. Remove conjunction to actions of conjunctive match using specific address.
	//  	 3. Check if there is no actions left for target flow match. If true, remove conjunctive match
	//          and check if need to uninstall drop flow for specific address

	return nil
}

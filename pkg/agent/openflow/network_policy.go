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

package openflow

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	thirdpartynp "antrea.io/antrea/third_party/networkpolicy"
)

var (
	MatchDstIP         = types.NewMatchKey(binding.ProtocolIP, types.IPAddr, "nw_dst")
	MatchSrcIP         = types.NewMatchKey(binding.ProtocolIP, types.IPAddr, "nw_src")
	MatchDstIPNet      = types.NewMatchKey(binding.ProtocolIP, types.IPNetAddr, "nw_dst")
	MatchSrcIPNet      = types.NewMatchKey(binding.ProtocolIP, types.IPNetAddr, "nw_src")
	MatchDstIPv6       = types.NewMatchKey(binding.ProtocolIPv6, types.IPAddr, "ipv6_dst")
	MatchSrcIPv6       = types.NewMatchKey(binding.ProtocolIPv6, types.IPAddr, "ipv6_src")
	MatchDstIPNetv6    = types.NewMatchKey(binding.ProtocolIPv6, types.IPNetAddr, "ipv6_dst")
	MatchSrcIPNetv6    = types.NewMatchKey(binding.ProtocolIPv6, types.IPNetAddr, "ipv6_src")
	MatchDstOFPort     = types.NewMatchKey(binding.ProtocolIP, types.OFPortAddr, "reg1[0..31]")
	MatchSrcOFPort     = types.NewMatchKey(binding.ProtocolIP, types.OFPortAddr, "in_port")
	MatchTCPDstPort    = types.NewMatchKey(binding.ProtocolTCP, types.L4PortAddr, "tp_dst")
	MatchTCPv6DstPort  = types.NewMatchKey(binding.ProtocolTCPv6, types.L4PortAddr, "tp_dst")
	MatchUDPDstPort    = types.NewMatchKey(binding.ProtocolUDP, types.L4PortAddr, "tp_dst")
	MatchUDPv6DstPort  = types.NewMatchKey(binding.ProtocolUDPv6, types.L4PortAddr, "tp_dst")
	MatchSCTPDstPort   = types.NewMatchKey(binding.ProtocolSCTP, types.L4PortAddr, "tp_dst")
	MatchSCTPv6DstPort = types.NewMatchKey(binding.ProtocolSCTPv6, types.L4PortAddr, "tp_dst")
	MatchTCPSrcPort    = types.NewMatchKey(binding.ProtocolTCP, types.L4PortAddr, "tp_src")
	MatchTCPv6SrcPort  = types.NewMatchKey(binding.ProtocolTCPv6, types.L4PortAddr, "tp_src")
	MatchUDPSrcPort    = types.NewMatchKey(binding.ProtocolUDP, types.L4PortAddr, "tp_src")
	MatchUDPv6SrcPort  = types.NewMatchKey(binding.ProtocolUDPv6, types.L4PortAddr, "tp_src")
	Unsupported        = types.NewMatchKey(binding.ProtocolIP, types.UnSupported, "unknown")

	// metricFlowIdentifier is used to identify metric flows in metric table.
	// There could be other flows like default flow and Traceflow flows in the table. Only metric flows are supposed to
	// have normal priority.
	metricFlowIdentifier = fmt.Sprintf("priority=%d,", priorityNormal)

	protocolUDP = v1beta2.ProtocolUDP
	dnsPort     = intstr.FromInt(53)
)

// IP address calculated from Pod's address.
type IPAddress net.IP

func (a *IPAddress) GetMatchKey(addrType types.AddressType) *types.MatchKey {
	ipArr := net.IP(*a)
	switch addrType {
	case types.SrcAddress:
		if ipArr.To4() != nil {
			return MatchSrcIP
		}
		return MatchSrcIPv6
	case types.DstAddress:
		if ipArr.To4() != nil {
			return MatchDstIP
		}
		return MatchDstIPv6
	default:
		klog.Errorf("Unknown AddressType %d in IPAddress", addrType)
		return Unsupported
	}
}

func (a *IPAddress) GetMatchValue() string {
	addr := net.IP(*a)
	return addr.String()
}

func (a *IPAddress) GetValue() interface{} {
	return net.IP(*a)
}

func NewIPAddress(addr net.IP) *IPAddress {
	ia := IPAddress(addr)
	return &ia
}

// IP block calculated from Pod's address.
type IPNetAddress net.IPNet

func (a *IPNetAddress) GetMatchKey(addrType types.AddressType) *types.MatchKey {
	ipAddr := net.IPNet(*a)
	switch addrType {
	case types.SrcAddress:
		if ipAddr.IP.To4() != nil {
			return MatchSrcIPNet
		}
		return MatchSrcIPNetv6
	case types.DstAddress:
		if ipAddr.IP.To4() != nil {
			return MatchDstIPNet
		}
		return MatchDstIPNetv6
	default:
		klog.Errorf("Unknown AddressType %d in IPNetAddress", addrType)
		return Unsupported
	}
}

func (a *IPNetAddress) GetMatchValue() string {
	addr := net.IPNet(*a)
	return addr.String()
}

func (a *IPNetAddress) GetValue() interface{} {
	return net.IPNet(*a)
}

func NewIPNetAddress(addr net.IPNet) *IPNetAddress {
	ia := IPNetAddress(addr)
	return &ia
}

// OFPortAddress is the Openflow port of an interface.
type OFPortAddress int32

func (a *OFPortAddress) GetMatchKey(addrType types.AddressType) *types.MatchKey {
	switch addrType {
	case types.SrcAddress:
		// in_port is used in egress rule to match packets sent from local Pod. Service traffic is not covered by this
		// match, and source IP will be matched instead.
		return MatchSrcOFPort
	case types.DstAddress:
		return MatchDstOFPort
	default:
		klog.Errorf("Unknown AddressType %d in OFPortAddress", addrType)
		return Unsupported
	}
}

func (a *OFPortAddress) GetMatchValue() string {
	return fmt.Sprintf("%d", int32(*a))
}

func (a *OFPortAddress) GetValue() interface{} {
	return int32(*a)
}

func NewOFPortAddress(addr int32) *OFPortAddress {
	a := OFPortAddress(addr)
	return &a
}

// ConjunctionNotFound is an error response when the specified policyRuleConjunction is not found from the local cache.
type ConjunctionNotFound uint32

func (e *ConjunctionNotFound) Error() string {
	return fmt.Sprintf("policyRuleConjunction with ID %d not found", uint32(*e))
}

func newConjunctionNotFound(conjunctionID uint32) *ConjunctionNotFound {
	err := ConjunctionNotFound(conjunctionID)
	return &err
}

// conjunctiveMatch generates match conditions for conjunctive match flow entry, including source or destination
// IP address, ofport number of OVS interface, or Service port. When conjunctiveMatch is used to match IP
// address or ofport number, matchProtocol is "ip". When conjunctiveMatch is used to match Service
// port, matchProtocol is Service protocol. If Service protocol is not set, "tcp" is used by default.
type conjunctiveMatch struct {
	tableID    uint8
	priority   *uint16
	matchKey   *types.MatchKey
	matchValue interface{}
}

func (m *conjunctiveMatch) generateGlobalMapKey() string {
	var valueStr, priorityStr string
	matchType := m.matchKey
	switch v := m.matchValue.(type) {
	case net.IP:
		// Use the unique format "x.x.x.x/xx" for IP address and IP net, to avoid generating two different global map
		// keys for IP and IP/mask. Use MatchDstIPNet/MatchSrcIPNet as match type to generate global cache key for both IP
		// and IPNet. This is because OVS treats IP and IP/$maskLen as the same condition (maskLen=32 for an IPv4 address,
		// and maskLen=128 for an IPv6 address). If Antrea has two different conjunctive match flow contexts, only one
		// flow entry is installed on OVS, and the conjunctive actions in the first context wil be overwritten by those
		// in the second one.
		var maskLen int
		if v.To4() != nil {
			maskLen = net.IPv4len * 8
		} else {
			maskLen = net.IPv6len * 8
		}
		valueStr = fmt.Sprintf("%s/%d", v.String(), maskLen)
		switch m.matchKey {
		case MatchDstIP:
			matchType = MatchDstIPNet
		case MatchDstIPv6:
			matchType = MatchDstIPNetv6
		case MatchSrcIP:
			matchType = MatchSrcIPNet
		case MatchSrcIPv6:
			matchType = MatchSrcIPNetv6
		}
	case net.IPNet:
		valueStr = v.String()
	case types.BitRange:
		bitRange := m.matchValue.(types.BitRange)
		if bitRange.Mask != nil {
			valueStr = fmt.Sprintf("%d/%d", bitRange.Value, *bitRange.Mask)
		} else {
			// To normalize the key, set full mask while a single port is provided.
			valueStr = fmt.Sprintf("%d/65535", bitRange.Value)
		}
	default:
		// The default cases include the matchValue is an ofport Number.
		valueStr = fmt.Sprintf("%s", m.matchValue)
	}
	if m.priority == nil {
		priorityStr = strconv.Itoa(int(priorityNormal))
	} else {
		priorityStr = strconv.Itoa(int(*m.priority))
	}
	return fmt.Sprintf("table:%d,priority:%s,type:%v,value:%s", m.tableID, priorityStr, matchType, valueStr)
}

// changeType is generally used to describe the change type of a conjMatchFlowContext. It is also used in "flowChange"
// to describe the expected OpenFlow operation which needs to be applied on the OVS bridge, and used in "actionChange"
// to describe the policyRuleConjunction is expected to be added to or removed from conjMatchFlowContext's actions.
// The value of changeType could be creation, modification, and deletion.
type changeType int

const (
	insertion changeType = iota
	modification
	deletion
)

// flowChange stores the expected OpenFlow entry and flow operation type which need to be applied on the OVS bridge.
// The "flow" in flowChange should be nil if there is no change on the OpenFlow entry. A possible case is that a
// DENY-ALL rule is required by a policyRuleConjunction, the flowChange will update the in-memory cache, but will not
// change on OVS.
type flowChange struct {
	flow       binding.Flow
	changeType changeType
}

// actionChange stores the changed action of the conjunctive match flow, and the change type.
// The "action" in actionChange is not nil.
type actionChange struct {
	action     *conjunctiveAction
	changeType changeType
}

// conjunctiveAction generates the policyRuleConjunction action in Openflow entry. The flow action is like
// policyRuleConjunction(conjID,clauseID/nClause) when it has been realized on the switch.
type conjunctiveAction struct {
	conjID   uint32
	clauseID uint8
	nClause  uint8
}

// conjMatchFlowContext generates conjunctive match flow entries for conjunctions share the same match conditions.
// One conjMatchFlowContext is responsible for one specific conjunctive match flow entry. As the match condition
// of the flow entry can be shared by different conjunctions, the realized Openflow entry might have multiple
// conjunctive actions. If the dropTable is not nil, conjMatchFlowContext also installs a drop flow in the dropTable.
type conjMatchFlowContext struct {
	// conjunctiveMatch describes the match condition of conjunctive match flow entry.
	*conjunctiveMatch
	// actions is a map from policyRuleConjunction ID to conjunctiveAction. It records all the conjunctive actions in
	// the conjunctive match flow. When the number of actions is reduced to 0, the conjMatchFlowContext.flow is
	// uninstalled from the switch.
	actions map[uint32]*conjunctiveAction
	// denyAllRules is a set to cache the "DENY-ALL" rules that is applied to the matching address in this context.
	denyAllRules map[uint32]bool
	client       *client
	// flow is the conjunctive match flow built from this context. flow needs to be updated if actions are changed.
	flow binding.Flow
	// dropflow is the default drop flow built from this context to drop packets in the AppliedToGroup but not pass the
	// NetworkPolicy rule. dropFlow is installed on the switch as long as either actions or denyAllRules is not
	// empty, and uninstalled when both two are empty. When the dropFlow is uninstalled from the switch, the
	// conjMatchFlowContext is removed from the cache.
	dropFlow binding.Flow
}

// createOrUpdateConjunctiveMatchFlow creates or updates the conjunctive match flow with the latest actions. It returns
// the flowChange including the changed OpenFlow entry and the expected operation which need to be applied on the OVS bridge.
func (ctx *conjMatchFlowContext) createOrUpdateConjunctiveMatchFlow(actions []*conjunctiveAction) *flowChange {
	// Check if flow is already installed. If not, create a new flow.
	if ctx.flow == nil {
		// Check the number of valid conjunctiveActions, and return nil immediately if it is 0. It happens when the match
		// condition is used only for matching AppliedToGroup, but no From or To is defined in the NetworkPolicy rule.
		if len(actions) == 0 {
			return nil
		}

		// Create the conjunctive match flow entry. The actions here should not be empty for either add or update case.
		// The expected operation for a new Openflow entry should be "insertion".
		flow := ctx.client.conjunctiveMatchFlow(ctx.tableID, ctx.matchKey, ctx.matchValue, ctx.priority, actions)
		return &flowChange{
			flow:       flow,
			changeType: insertion,
		}
	}

	// Modify the existing Openflow entry and reset the actions.
	flowBuilder := ctx.flow.CopyToBuilder(0, false)
	for _, act := range actions {
		flowBuilder.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	// The expected operation for an existing Openflow entry should be "modification".
	return &flowChange{
		flow:       flowBuilder.Done(),
		changeType: modification,
	}
}

// deleteAction deletes the specified policyRuleConjunction from conjunctiveMatchFlow's actions, and then returns the
// flowChange.
func (ctx *conjMatchFlowContext) deleteAction(conjID uint32) *flowChange {
	// If the specified conjunctive action is the last one, delete the conjunctive match flow entry from the OVS bridge.
	// No need to check if the conjunction ID of the only conjunctive action is the specified ID or not, as it
	// has been checked in the caller.
	if len(ctx.actions) == 1 && ctx.flow != nil {
		return &flowChange{
			flow:       ctx.flow,
			changeType: deletion,
		}
	}
	// Modify the Openflow entry and reset the other conjunctive actions.
	var actions []*conjunctiveAction
	for _, act := range ctx.actions {
		if act.conjID != conjID {
			actions = append(actions, act)
		}
	}
	return ctx.createOrUpdateConjunctiveMatchFlow(actions)
}

// addAction adds the specified policyRuleConjunction into conjunctiveMatchFlow's actions, and then returns the flowChange.
func (ctx *conjMatchFlowContext) addAction(action *conjunctiveAction) *flowChange {
	// Check if the conjunction exists in conjMatchFlowContext actions or not. If yes, return nil immediately.
	_, found := ctx.actions[action.conjID]
	if found {
		return nil
	}

	// Append current conjunctive action to the existing actions, and then calculate the conjunctive match flow changes.
	actions := []*conjunctiveAction{action}
	for _, act := range ctx.actions {
		actions = append(actions, act)
	}
	return ctx.createOrUpdateConjunctiveMatchFlow(actions)
}

func (ctx *conjMatchFlowContext) addDenyAllRule(ruleID uint32) {
	if ctx.denyAllRules == nil {
		ctx.denyAllRules = make(map[uint32]bool)
	}
	ctx.denyAllRules[ruleID] = true
}

func (ctx *conjMatchFlowContext) delDenyAllRule(ruleID uint32) {
	// Delete the DENY-ALL rule if it is in context denyAllRules.
	_, found := ctx.denyAllRules[ruleID]
	if found {
		delete(ctx.denyAllRules, ruleID)
	}
}

// conjMatchFlowContextChange describes the changes of a conjMatchFlowContext. It is generated when a policyRuleConjunction
// is added, deleted, or the addresses in an existing policyRuleConjunction are changed. The changes are calculated first,
// and then applied on the OVS bridge using a single Bundle, and lastly the local cache is updated. The local cahce
// is updated only if conjMatchFlowContextChange is applied on the OVS bridge successfully.
type conjMatchFlowContextChange struct {
	// context is the changed conjMatchFlowContext, which needs to be updated after the OpenFlow entries are applied to
	// the OVS bridge. context is not nil.
	context *conjMatchFlowContext
	// ctxChangeType is the changed type of the conjMatchFlowContext. The possible values are "creation", "modification"
	// and "deletion". Add the context into the globalConjMatchFlowCache if the ctxChangeType is "insertion", and remove
	// from the globalConjMatchFlowCache if it is "deletion".
	ctxChangeType changeType
	// matchFlow is the changed conjunctive match flow which needs to be realized on the OVS bridge. It is used to update
	// conjMatchFlowContext.flow. matchFlow is set if the conjunctive match flow needs to be updated on the OVS bridge, or
	// a DENY-ALL rule change is required by the policyRuleConjunction. matchFlow is nil if the policyRuleConjunction
	// is already added/removed in the conjMatchFlowContext's actions or denyAllRules.
	matchFlow *flowChange
	// dropFlow is the changed drop flow which needs to be realized on the OVS bridge. It is used to update
	// conjMatchFlowContext.dropFlow. dropFlow is set when the default drop flow needs to be added or removed on the OVS
	// bridge, and it is nil in other cases.
	dropFlow *flowChange
	// clause is the policyRuleConjunction's clause having current conjMatchFlowContextChange. It is used to update the
	// mapping relations between the policyRuleConjunction and the conjMatchFlowContext. Update the clause.matches after
	// the conjMatchFlowContextChange is realized on the OVS bridge. clause is not nil.
	clause *clause
	// actChange is the changed conjunctive action. It is used to update the conjMatchFlowContext's actions. actChange
	// is not nil.
	actChange *actionChange
}

// updateContextStatus changes conjMatchFlowContext's status, including,
// 1) reset flow and dropFlow after the flow changes have been applied to the OVS bridge,
// 2) modify the actions with the changed action,
// 3) update the mapping of denyAllRules and corresponding policyRuleConjunction,
// 4) add the new conjMatchFlowContext into the globalConjMatchFlowCache, or remove the deleted conjMatchFlowContext
//    from the globalConjMatchFlowCache.
func (c *conjMatchFlowContextChange) updateContextStatus() {
	matcherKey := c.context.generateGlobalMapKey()
	// Update clause.matches with the conjMatchFlowContext, and update conjMatchFlowContext.actions with the changed
	// conjunctive action.
	changedAction := c.actChange.action
	switch c.actChange.changeType {
	case insertion:
		c.clause.matches[matcherKey] = c.context
		if changedAction != nil {
			c.context.actions[changedAction.conjID] = changedAction
		}
	case deletion:
		delete(c.clause.matches, matcherKey)
		if changedAction != nil {
			delete(c.context.actions, changedAction.conjID)
		}
	}
	// Update the match flow in the conjMatchFlowContext. There are two kinds of possible changes on the match flow:
	// 1) A conjunctive match flow change required by the policyRuleConjunction.
	// 2) A DENY-ALL rule required by the policyRuleConjunction.
	// For 1), conjMatchFlowContext.Flow should be updated with the conjMatchFlowContextChange.matchFlow.flow.
	// For 2), append or delete the conjunction ID from the conjMatchFlowContext's denyAllRules.
	if c.matchFlow != nil {
		switch c.matchFlow.changeType {
		case insertion:
			fallthrough
		case modification:
			if c.matchFlow.flow != nil {
				c.context.flow = c.matchFlow.flow
			} else {
				switch c.actChange.changeType {
				case insertion:
					c.context.addDenyAllRule(c.clause.action.conjID)
				case deletion:
					c.context.delDenyAllRule(c.clause.action.conjID)
				}
			}
		case deletion:
			if c.matchFlow.flow != nil {
				c.context.flow = nil
			} else {
				c.context.delDenyAllRule(c.clause.action.conjID)
			}
		}
	}
	// Update conjMatchFlowContext.dropFlow.
	if c.dropFlow != nil {
		switch c.dropFlow.changeType {
		case insertion:
			c.context.dropFlow = c.dropFlow.flow
		case deletion:
			c.context.dropFlow = nil
		}
	}

	// Update globalConjMatchFlowCache. Add the conjMatchFlowContext into the globalConjMatchFlowCache if the ctxChangeType
	// is "insertion", or delete from the globalConjMatchFlowCache if the ctxChangeType is "deletion".
	switch c.ctxChangeType {
	case insertion:
		c.context.client.globalConjMatchFlowCache[matcherKey] = c.context
	case deletion:
		delete(c.context.client.globalConjMatchFlowCache, matcherKey)
	}
}

// policyRuleConjunction is responsible to build Openflow entries for Pods that are in a NetworkPolicy rule's AppliedToGroup.
// The Openflow entries include conjunction action flows, conjunctive match flows, and default drop flows in the dropTable.
// NetworkPolicyController will make sure only one goroutine operates on a policyRuleConjunction.
// 1) Conjunction action flows use policyRuleConjunction ID as match condition. policyRuleConjunction ID is the single
// 	  match condition for conjunction action flows to allow packets. If the NetworkPolicy rule has also configured excepts
// 	  in From or To, Openflow entries are installed only for diff IPBlocks between From/To and Excepts. These are added as
//	  conjunctive match flows as described below.
// 2) Conjunctive match flows adds conjunctive actions in Openflow entry, and they are grouped by clauses. The match
// 	  condition in one clause is one of these three types: from address(for fromClause), or to address(for toClause), or
// 	  service ports(for serviceClause) configured in the NetworkPolicy rule. Each conjunctive match flow entry is
// 	  maintained by one specific conjMatchFlowContext which is stored in globalConjMatchFlowCache, and shared by clauses
// 	  if they have the same match conditions. clause adds or deletes conjunctive action to conjMatchFlowContext actions.
// 	  A clause is hit if the packet matches any conjunctive match flow that are grouped by this clause. Conjunction
// 	  action flow is hit only if all clauses in the policyRuleConjunction are hit.
// 3) Default drop flows are also maintained by conjMatchFlowContext. It is used to drop packets sent from or to the
// 	  AppliedToGroup but not pass the Network Policy rule.
type policyRuleConjunction struct {
	id            uint32
	fromClause    *clause
	toClause      *clause
	serviceClause *clause
	actionFlows   []binding.Flow
	metricFlows   []binding.Flow
	// NetworkPolicy reference information for debugging usage.
	npRef       *v1beta2.NetworkPolicyReference
	ruleTableID uint8
}

// clause groups conjunctive match flows. Matches in a clause represent source addresses(for fromClause), or destination
// addresses(for toClause) or service ports(for serviceClause) in a NetworkPolicy rule. When the new address or service
// port is added into the clause, it adds a new conjMatchFlowContext into globalConjMatchFlowCache (or finds the
// existing one from globalConjMatchFlowCache), and then update the key of the conjunctiveMatch into its own matches.
// When address is deleted from the clause, it deletes the conjunctive action from the conjMatchFlowContext,
// and then deletes the key of conjunctiveMatch from its own matches.
type clause struct {
	action *conjunctiveAction
	// matches is a map from the unique string generated from the conjunctiveMatch to conjMatchFlowContext. It is used
	// to cache conjunctive match conditions in the same clause.
	matches map[string]*conjMatchFlowContext
	// ruleTable is where to install conjunctive match flows.
	ruleTable binding.Table
	// dropTable is where to install Openflow entries to drop the packet sent to or from the AppliedToGroup but does not
	// satisfy any conjunctive match conditions. It should be nil, if the clause is used for matching service port.
	dropTable binding.Table
}

func (c *client) NewDNSpacketInConjunction(id uint32) error {
	existingConj := c.getPolicyRuleConjunction(id)
	if existingConj != nil {
		klog.InfoS("DNS Conjunction has already been added to cache", "id", id)
		return nil
	}
	conj := &policyRuleConjunction{
		id:          id,
		ruleTableID: AntreaPolicyIngressRuleTable.GetID(),
		actionFlows: []binding.Flow{c.dnsPacketInFlow(id), c.dnsResponseBypassPacketInFlow(), c.dnsResponseBypassConntrackFlow()},
	}
	if err := c.ofEntryOperations.AddAll(conj.actionFlows); err != nil {
		return fmt.Errorf("error when adding action flows for the DNS conjunction: %w", err)
	}
	udpService := v1beta2.Service{
		Protocol: &protocolUDP,
		Port:     &dnsPort,
	}
	dnsPriority := priorityDNSIntercept
	conj.serviceClause = conj.newClause(1, 2, getTableByID(conj.ruleTableID), nil)
	conj.toClause = conj.newClause(2, 2, getTableByID(conj.ruleTableID), nil)

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	ctxChanges := conj.serviceClause.addServiceFlows(c, []v1beta2.Service{udpService}, &dnsPriority, true)
	if err := c.applyConjunctiveMatchFlows(ctxChanges); err != nil {
		return err
	}
	// Add the policyRuleConjunction into policyCache
	c.policyCache.Add(conj)
	return nil
}

func (c *client) AddAddressToDNSConjunction(id uint32, addrs []types.Address) error {
	dnsPriority := priorityDNSIntercept
	return c.AddPolicyRuleAddress(id, types.DstAddress, addrs, &dnsPriority)
}

func (c *client) DeleteAddressFromDNSConjunction(id uint32, addrs []types.Address) error {
	dnsPriority := priorityDNSIntercept
	return c.DeletePolicyRuleAddress(id, types.DstAddress, addrs, &dnsPriority)
}

func (c *clause) addConjunctiveMatchFlow(client *client, match *conjunctiveMatch) *conjMatchFlowContextChange {
	matcherKey := match.generateGlobalMapKey()
	_, found := c.matches[matcherKey]
	if found {
		klog.V(2).Infof("Conjunctive match flow with matcher %s is already added in rule: %d", matcherKey, c.action.conjID)
		return nil
	}

	var context *conjMatchFlowContext
	ctxType := modification
	var dropFlow *flowChange
	// Get conjMatchFlowContext from globalConjMatchFlowCache. If it doesn't exist, create a new one and add into the cache.
	context, found = client.globalConjMatchFlowCache[matcherKey]
	if !found {
		context = &conjMatchFlowContext{
			conjunctiveMatch: match,
			actions:          make(map[uint32]*conjunctiveAction),
			client:           client,
		}
		ctxType = insertion

		// Generate the default drop flow if dropTable is not nil and the default drop flow is not set yet.
		if c.dropTable != nil && context.dropFlow == nil {
			dropFlow = &flowChange{
				flow:       context.client.defaultDropFlow(c.dropTable, match.matchKey, match.matchValue),
				changeType: insertion,
			}
		}
	}

	// Calculate the change on the conjMatchFlowContext.
	ctxChanges := &conjMatchFlowContextChange{
		context:       context,
		ctxChangeType: ctxType,
		clause:        c,
		actChange: &actionChange{
			changeType: insertion,
		},
		dropFlow: dropFlow,
	}
	if c.action.nClause > 1 {
		// Append the conjunction to conjunctiveFlowContext's actions, and add the changed flow into the conjMatchFlowContextChange.
		flowChange := context.addAction(c.action)
		if flowChange != nil {
			ctxChanges.matchFlow = flowChange
			ctxChanges.actChange.action = c.action
		}
	} else {
		// Set the flowChange type as "insertion" but do not set flowChange.Flow. In this case, the policyRuleConjunction should
		// be added into conjunctiveFlowContext's denyAllRules.
		ctxChanges.matchFlow = &flowChange{
			changeType: insertion,
		}
	}

	return ctxChanges
}

func generateAddressConjMatch(ruleTableID uint8, addr types.Address, addrType types.AddressType, priority *uint16) *conjunctiveMatch {
	matchKey := addr.GetMatchKey(addrType)
	matchValue := addr.GetValue()
	match := &conjunctiveMatch{
		tableID:    ruleTableID,
		matchKey:   matchKey,
		matchValue: matchValue,
		priority:   priority,
	}
	return match
}

func getServiceMatchType(protocol *v1beta2.Protocol, ipv4Enabled, ipv6Enabled, matchSrc bool) []*types.MatchKey {
	var matchKeys []*types.MatchKey
	switch *protocol {
	case v1beta2.ProtocolTCP:
		if !matchSrc {
			if ipv4Enabled {
				matchKeys = append(matchKeys, MatchTCPDstPort)
			}
			if ipv6Enabled {
				matchKeys = append(matchKeys, MatchTCPv6DstPort)
			}
		} else {
			if ipv4Enabled {
				matchKeys = append(matchKeys, MatchTCPSrcPort)
			}
			if ipv6Enabled {
				matchKeys = append(matchKeys, MatchTCPv6SrcPort)
			}
		}
	case v1beta2.ProtocolUDP:
		if !matchSrc {
			if ipv4Enabled {
				matchKeys = append(matchKeys, MatchUDPDstPort)
			}
			if ipv6Enabled {
				matchKeys = append(matchKeys, MatchUDPv6DstPort)
			}
		} else {
			if ipv4Enabled {
				matchKeys = append(matchKeys, MatchUDPSrcPort)
			}
			if ipv6Enabled {
				matchKeys = append(matchKeys, MatchUDPv6SrcPort)
			}
		}
	case v1beta2.ProtocolSCTP:
		if ipv4Enabled {
			matchKeys = append(matchKeys, MatchSCTPDstPort)
		}
		if ipv6Enabled {
			matchKeys = append(matchKeys, MatchSCTPv6DstPort)
		}
	default:
		matchKeys = []*types.MatchKey{MatchTCPDstPort}
	}
	return matchKeys
}

func generateServicePortConjMatches(ruleTableID uint8, service v1beta2.Service, priority *uint16, ipv4Enabled, ipv6Enabled, matchSrc bool) []*conjunctiveMatch {
	matchKeys := getServiceMatchType(service.Protocol, ipv4Enabled, ipv6Enabled, matchSrc)
	ovsBitRanges := serviceToBitRanges(service)
	var matches []*conjunctiveMatch
	for _, matchKey := range matchKeys {
		for _, ovsBitRange := range ovsBitRanges {
			matches = append(matches,
				&conjunctiveMatch{
					tableID:    ruleTableID,
					matchKey:   matchKey,
					matchValue: ovsBitRange,
					priority:   priority,
				})
		}
	}
	return matches
}

// serviceToBitRanges converts a Service to a list of BitRange.
func serviceToBitRanges(service v1beta2.Service) []types.BitRange {
	var ovsBitRanges []types.BitRange
	// If `EndPort` is equal to `Port`, then treat it as single port case.
	if service.EndPort != nil && *service.EndPort > service.Port.IntVal {
		// Add several antrea range services based on a port range.
		portRange := thirdpartynp.PortRange{Start: uint16(service.Port.IntVal), End: uint16(*service.EndPort)}
		bitRanges, err := portRange.BitwiseMatch()
		if err != nil {
			klog.Errorf("Error when getting BitRanges from %v: %v", portRange, err)
			return ovsBitRanges
		}
		for _, bitRange := range bitRanges {
			curBitRange := bitRange
			ovsBitRanges = append(ovsBitRanges, types.BitRange{
				Value: curBitRange.Value,
				Mask:  &curBitRange.Mask,
			})
		}
	} else if service.Port != nil {
		// Add single antrea service based on a single port.
		ovsBitRanges = append(ovsBitRanges, types.BitRange{
			Value: uint16(service.Port.IntVal),
		})
	} else {
		// Match all ports with the given protocol type if `Port` and `EndPort` are not
		// specified (value is 0).
		ovsBitRanges = append(ovsBitRanges, types.BitRange{
			Value: uint16(0),
		})
	}
	return ovsBitRanges
}

// addAddrFlows translates the specified addresses to conjunctiveMatchFlows, and returns the corresponding changes on the
// conjunctiveMatchFlows.
func (c *clause) addAddrFlows(client *client, addrType types.AddressType, addresses []types.Address, priority *uint16) []*conjMatchFlowContextChange {
	var conjMatchFlowContextChanges []*conjMatchFlowContextChange
	// Calculate Openflow changes for the added addresses.
	for _, addr := range addresses {
		match := generateAddressConjMatch(c.ruleTable.GetID(), addr, addrType, priority)
		ctxChange := c.addConjunctiveMatchFlow(client, match)
		if ctxChange != nil {
			conjMatchFlowContextChanges = append(conjMatchFlowContextChanges, ctxChange)
		}
	}
	return conjMatchFlowContextChanges
}

// addServiceFlows translates the specified NetworkPolicyPorts to conjunctiveMatchFlow, and returns corresponding
// conjMatchFlowContextChange.
func (c *clause) addServiceFlows(client *client, ports []v1beta2.Service, priority *uint16, matchSrc bool) []*conjMatchFlowContextChange {
	var conjMatchFlowContextChanges []*conjMatchFlowContextChange
	for _, port := range ports {
		matches := generateServicePortConjMatches(c.ruleTable.GetID(), port, priority, client.IsIPv4Enabled(), client.IsIPv6Enabled(), matchSrc)
		for _, match := range matches {
			ctxChange := c.addConjunctiveMatchFlow(client, match)
			conjMatchFlowContextChanges = append(conjMatchFlowContextChanges, ctxChange)
		}
	}
	return conjMatchFlowContextChanges
}

// deleteConjunctiveMatchFlow deletes the specific conjunctiveAction from existing flow.
func (c *clause) deleteConjunctiveMatchFlow(flowContextKey string) *conjMatchFlowContextChange {
	context, found := c.matches[flowContextKey]
	// Match is not located in clause cache. It happens if the conjMatchFlowContext is already deleted from clause local cache.
	if !found {
		return nil
	}

	ctxChange := &conjMatchFlowContextChange{
		context:       context,
		clause:        c,
		ctxChangeType: modification,
		actChange: &actionChange{
			changeType: deletion,
		},
	}
	conjID := c.action.conjID
	expectedConjunctiveActions := len(context.actions)
	expectedDenyAllRules := len(context.denyAllRules)
	if c.action.nClause > 1 {
		// Delete the conjunctive action if it is in context actions.
		action, found := context.actions[conjID]
		if found {
			ctxChange.matchFlow = context.deleteAction(conjID)
			ctxChange.actChange.action = action
			expectedConjunctiveActions--
		}
	} else {
		// Delete the DENY-ALL rule if it is in context denyAllRules.
		ctxChange.matchFlow = &flowChange{
			changeType: deletion,
		}
		expectedDenyAllRules--
	}

	// Uninstall default drop flow if the deleted conjunctiveAction is the last action or the rule is the last one in
	// the denyAllRules.
	if expectedConjunctiveActions == 0 && expectedDenyAllRules == 0 {
		if context.dropFlow != nil {
			ctxChange.dropFlow = &flowChange{
				flow:       context.dropFlow,
				changeType: deletion,
			}
		}
		// Remove the context from global cache if the match condition is not used by either DENEY-ALL or the conjunctive
		// match flow.
		ctxChange.ctxChangeType = deletion
	}

	return ctxChange
}

// deleteAddrFlows deletes conjunctiveMatchFlow relevant to the specified addresses from local cache,
// and uninstalls Openflow entry.
func (c *clause) deleteAddrFlows(addrType types.AddressType, addresses []types.Address, priority *uint16) []*conjMatchFlowContextChange {
	var ctxChanges []*conjMatchFlowContextChange
	for _, addr := range addresses {
		match := generateAddressConjMatch(c.ruleTable.GetID(), addr, addrType, priority)
		contextKey := match.generateGlobalMapKey()
		ctxChange := c.deleteConjunctiveMatchFlow(contextKey)
		if ctxChange != nil {
			ctxChanges = append(ctxChanges, ctxChange)
		}
	}
	return ctxChanges
}

// deleteAllMatches deletes all conjunctiveMatchFlow in the clause, and removes Openflow entry. deleteAllMatches
// is always invoked when NetworkPolicy rule is deleted.
func (c *clause) deleteAllMatches() []*conjMatchFlowContextChange {
	var ctxChanges []*conjMatchFlowContextChange
	for key := range c.matches {
		ctxChange := c.deleteConjunctiveMatchFlow(key)
		if ctxChange != nil {
			ctxChanges = append(ctxChanges, ctxChange)
		}
	}
	return ctxChanges
}

func (c *policyRuleConjunction) getAddressClause(addrType types.AddressType) *clause {
	switch addrType {
	case types.SrcAddress:
		return c.fromClause
	case types.DstAddress:
		return c.toClause
	default:
		klog.Errorf("no address clause use AddressType %d", addrType)
		return nil
	}
}

// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for ruleTable and
// the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the dropTable.
// NetworkPolicyController will make sure only one goroutine operates on a PolicyRule and addresses in the rule.
// For a normal NetworkPolicy rule, these Openflow entries are installed: 1) 1 conjunction action flow; 2) multiple
// conjunctive match flows, the flow number depends on addresses in rule.From and rule.To, or if
// rule.FromExcepts/rule.ToExcepts are present, flow number is equal to diff of addresses between rule.From and
// rule.FromExcepts, and diff addresses between rule.To and rule.ToExcepts, and in addition number includes service ports
// in rule.Service; and 3) multiple default drop flows, the number is dependent on the addresses in rule.From for
// an egress rule, and addresses in rule.To for an ingress rule.
// For ALLOW-ALL rule, the Openflow entries installed on the switch are similar to a normal rule. The differences include,
// 1) rule.Service is nil; and 2) rule.To has only one address "0.0.0.0/0" for egress rule, and rule.From is "0.0.0.0/0"
// for ingress rule.
// For DENY-ALL rule, only the default drop flow is installed for the addresses in rule.From for egress rule, or
// addresses in rule.To for ingress rule. No conjunctive match flow or conjunction action except flows are installed.
// A DENY-ALL rule is configured with rule.ID, rule.Direction, and either rule.From(egress rule) or rule.To(ingress rule).
// Other fields in the rule should be nil.
// If there is an error in any clause's addAddrFlows or addServiceFlows, the conjunction action flow will never be hit.
// If the default drop flow is already installed before this error, all packets will be dropped by the default drop flow,
// Otherwise all packets will be allowed.
func (c *client) InstallPolicyRuleFlows(rule *types.PolicyRule) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	conj := c.calculateActionFlowChangesForRule(rule)

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	ctxChanges := c.calculateMatchFlowChangesForRule(conj, rule)

	if err := c.ofEntryOperations.AddAll(conj.metricFlows); err != nil {
		return err
	}
	if err := c.ofEntryOperations.AddAll(conj.actionFlows); err != nil {
		return err
	}
	if err := c.applyConjunctiveMatchFlows(ctxChanges); err != nil {
		return err
	}
	// Add the policyRuleConjunction into policyCache
	c.policyCache.Add(conj)
	return nil
}

// calculateActionFlowChangesForRule calculates and updates the actionFlows for the conjunction corresponded to the ofPolicyRule.
func (c *client) calculateActionFlowChangesForRule(rule *types.PolicyRule) *policyRuleConjunction {
	ruleOfID := rule.FlowID
	// Check if the policyRuleConjunction is added into cache or not. If yes, return nil.
	conj := c.getPolicyRuleConjunction(ruleOfID)
	if conj != nil {
		klog.V(2).Infof("PolicyRuleConjunction %d is already added in cache", ruleOfID)
		return nil
	}
	conj = &policyRuleConjunction{
		id:    ruleOfID,
		npRef: rule.PolicyRef,
	}
	nClause, ruleTable, dropTable := conj.calculateClauses(rule, c)
	conj.ruleTableID = rule.TableID
	_, isEgress := egressTables[rule.TableID]
	isIngress := !isEgress

	// Conjunction action flows are installed only if the number of clauses in the conjunction is > 1. It should be a rule
	// to drop all packets.  If the number is 1, no conjunctive match flows or conjunction action flows are installed,
	// but the default drop flow is installed.
	if nClause > 1 {
		// Install action flows.
		var actionFlows []binding.Flow
		var metricFlows []binding.Flow
		if rule.IsAntreaNetworkPolicyRule() && *rule.Action == crdv1alpha1.RuleActionDrop {
			metricFlows = append(metricFlows, c.denyRuleMetricFlow(ruleOfID, isIngress))
			actionFlows = append(actionFlows, c.conjunctionActionDenyFlow(ruleOfID, ruleTable, rule.Priority, DispositionDrop, rule.EnableLogging))
		} else if rule.IsAntreaNetworkPolicyRule() && *rule.Action == crdv1alpha1.RuleActionReject {
			metricFlows = append(metricFlows, c.denyRuleMetricFlow(ruleOfID, isIngress))
			actionFlows = append(actionFlows, c.conjunctionActionDenyFlow(ruleOfID, ruleTable, rule.Priority, DispositionRej, rule.EnableLogging))
		} else {
			metricFlows = append(metricFlows, c.allowRulesMetricFlows(ruleOfID, isIngress)...)
			actionFlows = append(actionFlows, c.conjunctionActionFlow(ruleOfID, ruleTable, dropTable.GetNext(), rule.Priority, rule.EnableLogging)...)
		}
		conj.actionFlows = actionFlows
		conj.metricFlows = metricFlows
	}
	return conj
}

// calculateMatchFlowChangesForRule calculates the contextChanges for the policyRule, and updates the context status in case of batch install.
func (c *client) calculateMatchFlowChangesForRule(conj *policyRuleConjunction, rule *types.PolicyRule) []*conjMatchFlowContextChange {
	// Calculate the conjMatchFlowContext changes. The changed Openflow entries are included in the conjMatchFlowContext change.
	ctxChanges := conj.calculateChangesForRuleCreation(c, rule)
	return ctxChanges
}

// addRuleToConjunctiveMatch adds a rule's clauses to corresponding conjunctive match contexts.
// Unlike calculateMatchFlowChangesForRule, it updates the context status directly and doesn't calculate flow changes.
// It's used in initial batch install where we first add all rules then calculates flows change based on final state.
func (c *client) addRuleToConjunctiveMatch(conj *policyRuleConjunction, rule *types.PolicyRule) {
	if conj.fromClause != nil {
		for _, addr := range rule.From {
			match := generateAddressConjMatch(conj.fromClause.ruleTable.GetID(), addr, types.SrcAddress, rule.Priority)
			c.addActionToConjunctiveMatch(conj.fromClause, match)
		}
	}
	if conj.toClause != nil {
		for _, addr := range rule.To {
			match := generateAddressConjMatch(conj.toClause.ruleTable.GetID(), addr, types.DstAddress, rule.Priority)
			c.addActionToConjunctiveMatch(conj.toClause, match)
		}
	}
	if conj.serviceClause != nil {
		for _, port := range rule.Service {
			matches := generateServicePortConjMatches(conj.serviceClause.ruleTable.GetID(), port, rule.Priority, c.IsIPv4Enabled(), c.IsIPv6Enabled(), false)
			for _, match := range matches {
				c.addActionToConjunctiveMatch(conj.serviceClause, match)
			}
		}
	}
}

// addActionToConjunctiveMatch adds a clause to corresponding conjunctive match context.
// It updates the context status directly and doesn't calculate the match flow, which is supposed to be calculated after
// all actions are added. It's used in initial batch install only.
func (c *client) addActionToConjunctiveMatch(clause *clause, match *conjunctiveMatch) {
	matcherKey := match.generateGlobalMapKey()
	_, found := clause.matches[matcherKey]
	if found {
		klog.V(2).InfoS("Conjunctive match flow is already added for rule", "matcherKey", matcherKey, "ruleID", clause.action.conjID)
		return
	}

	var context *conjMatchFlowContext
	// Get conjMatchFlowContext from globalConjMatchFlowCache. If it doesn't exist, create a new one and add into the cache.
	context, found = c.globalConjMatchFlowCache[matcherKey]
	if !found {
		context = &conjMatchFlowContext{
			conjunctiveMatch: match,
			actions:          make(map[uint32]*conjunctiveAction),
			client:           c,
		}
		// Generate the default drop flow if dropTable is not nil.
		if clause.dropTable != nil {
			context.dropFlow = context.client.defaultDropFlow(clause.dropTable, match.matchKey, match.matchValue)
		}
		c.globalConjMatchFlowCache[matcherKey] = context
	}
	clause.matches[matcherKey] = context

	if clause.action.nClause > 1 {
		// Add the conjunction to the conjunctiveFlowContext's actions.
		context.actions[clause.action.conjID] = clause.action
	} else {
		// Add the conjunction ID to the conjunctiveFlowContext's denyAllRules.
		context.addDenyAllRule(clause.action.conjID)
	}
}

// BatchInstallPolicyRuleFlows installs flows for NetworkPolicy rules in case of agent restart. It calculates and
// accumulates all Openflow entry updates required and installs all of them on OVS bridge in one bundle.
// It resets the global conjunctive match flow cache upon failure, and should NOT be used after any rule is installed
// via the InstallPolicyRuleFlows method. Otherwise the cache would be out of sync.
func (c *client) BatchInstallPolicyRuleFlows(ofPolicyRules []*types.PolicyRule) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	var allFlows []binding.Flow
	var conjunctions []*policyRuleConjunction

	for _, rule := range ofPolicyRules {
		conj := c.calculateActionFlowChangesForRule(rule)
		c.addRuleToConjunctiveMatch(conj, rule)
		allFlows = append(allFlows, conj.actionFlows...)
		allFlows = append(allFlows, conj.metricFlows...)
		conjunctions = append(conjunctions, conj)
	}

	for _, ctx := range c.globalConjMatchFlowCache {
		// In theory there must be at least one action but InstallPolicyRuleFlows currently handles the 1 clause case
		// and we do the same in addRuleToConjunctiveMatch. The check is added only for consistency. Later we should
		// return error if clients install a rule with only 1 clause, and should remove the extra code for processing it.
		if len(ctx.actions) > 0 {
			actions := make([]*conjunctiveAction, 0, len(ctx.actions))
			for _, action := range ctx.actions {
				actions = append(actions, action)
			}
			ctx.flow = c.conjunctiveMatchFlow(ctx.tableID, ctx.matchKey, ctx.matchValue, ctx.priority, actions)
			allFlows = append(allFlows, ctx.flow)
		}
		if ctx.dropFlow != nil {
			allFlows = append(allFlows, ctx.dropFlow)
		}
	}

	// Send the changed Openflow entries to the OVS bridge.
	if err := c.ofEntryOperations.AddAll(allFlows); err != nil {
		// Reset the global conjunctive match flow cache since the OpenFlow bundle, which contains
		// all the match flows to be installed, was not applied successfully.
		c.globalConjMatchFlowCache = map[string]*conjMatchFlowContext{}
		return err
	}
	// Update conjMatchFlowContexts as the expected status.
	for _, conj := range conjunctions {
		// Add the policyRuleConjunction into policyCache
		c.policyCache.Add(conj)
	}
	return nil
}

// applyConjunctiveMatchFlows installs OpenFlow entries on the OVS bridge, and then updates the conjMatchFlowContext.
func (c *client) applyConjunctiveMatchFlows(flowChanges []*conjMatchFlowContextChange) error {
	// Send the OpenFlow entries to the OVS bridge.
	if err := c.sendConjunctiveFlows(flowChanges, []binding.Flow{}); err != nil {
		return err
	}
	// Update conjunctiveMatchContext.
	for _, ctxChange := range flowChanges {
		ctxChange.updateContextStatus()
	}
	return nil
}

// sendConjunctiveFlows sends all the changed OpenFlow entries to the OVS bridge in a single Bundle.
func (c *client) sendConjunctiveFlows(changes []*conjMatchFlowContextChange, flows []binding.Flow) error {
	var addFlows, modifyFlows, deleteFlows []binding.Flow
	var flowChanges []*flowChange
	addFlows = flows
	for _, flowChange := range changes {
		if flowChange.matchFlow != nil {
			flowChanges = append(flowChanges, flowChange.matchFlow)
		}
		if flowChange.dropFlow != nil {
			flowChanges = append(flowChanges, flowChange.dropFlow)
		}
	}
	// Retrieve the OpenFlow entries from the flowChanges.
	for _, fc := range flowChanges {
		switch fc.changeType {
		case insertion:
			addFlows = append(addFlows, fc.flow)
		case modification:
			modifyFlows = append(modifyFlows, fc.flow)
		case deletion:
			deleteFlows = append(deleteFlows, fc.flow)
		}
	}
	return c.bridge.AddFlowsInBundle(addFlows, modifyFlows, deleteFlows)
}

// ActionFlowPriorities returns the OF priorities of the actionFlows in the policyRuleConjunction
func (c *policyRuleConjunction) ActionFlowPriorities() []string {
	priorities := make([]string, 0, len(c.actionFlows))
	for _, flow := range c.actionFlows {
		priorityStr := strconv.Itoa(int(flow.FlowPriority()))
		priorities = append(priorities, priorityStr)
	}
	return priorities
}

func (c *policyRuleConjunction) newClause(clauseID uint8, nClause uint8, ruleTable, dropTable binding.Table) *clause {
	return &clause{
		ruleTable: ruleTable,
		dropTable: dropTable,
		matches:   make(map[string]*conjMatchFlowContext, 0),
		action: &conjunctiveAction{
			conjID:   c.id,
			clauseID: clauseID,
			nClause:  nClause,
		},
	}
}

// calculateClauses configures the policyRuleConjunction's clauses according to the PolicyRule. The Openflow entries are
// not installed on the OVS bridge when calculating the clauses.
func (c *policyRuleConjunction) calculateClauses(rule *types.PolicyRule, clnt *client) (uint8, binding.Table, binding.Table) {
	var dropTable binding.Table
	var isEgressRule = false
	switch rule.Direction {
	case v1beta2.DirectionOut:
		dropTable = EgressDefaultTable
		isEgressRule = true
	default:
		dropTable = IngressDefaultTable
	}
	ruleTable := getTableByID(rule.TableID)

	var fromID, toID, serviceID, nClause uint8
	// Calculate clause IDs and the total number of clauses.
	if rule.From != nil {
		nClause++
		fromID = nClause
	}
	if rule.To != nil {
		nClause++
		toID = nClause
	}
	if rule.Service != nil {
		nClause++
		serviceID = nClause
	}

	var defaultTable binding.Table
	if rule.From != nil {
		// deny rule does not need to be created for ClusterNetworkPolicies
		if !isEgressRule || rule.IsAntreaNetworkPolicyRule() {
			defaultTable = nil
		} else {
			defaultTable = dropTable
		}
		c.fromClause = c.newClause(fromID, nClause, ruleTable, defaultTable)
	}
	if rule.To != nil {
		if isEgressRule || rule.IsAntreaNetworkPolicyRule() {
			defaultTable = nil
		} else {
			defaultTable = dropTable
		}
		c.toClause = c.newClause(toID, nClause, ruleTable, defaultTable)
	}
	if rule.Service != nil {
		c.serviceClause = c.newClause(serviceID, nClause, ruleTable, nil)
	}
	return nClause, ruleTable, dropTable
}

// calculateChangesForRuleCreation returns the conjMatchFlowContextChanges of the new policyRuleConjunction. It
// will calculate the expected conjMatchFlowContext status, and the changed Openflow entries.
func (c *policyRuleConjunction) calculateChangesForRuleCreation(clnt *client, rule *types.PolicyRule) []*conjMatchFlowContextChange {
	var ctxChanges []*conjMatchFlowContextChange
	if c.fromClause != nil {
		ctxChanges = append(ctxChanges, c.fromClause.addAddrFlows(clnt, types.SrcAddress, rule.From, rule.Priority)...)
	}
	if c.toClause != nil {
		ctxChanges = append(ctxChanges, c.toClause.addAddrFlows(clnt, types.DstAddress, rule.To, rule.Priority)...)
	}
	if c.serviceClause != nil {
		ctxChanges = append(ctxChanges, c.serviceClause.addServiceFlows(clnt, rule.Service, rule.Priority, false)...)
	}
	return ctxChanges
}

// calculateChangesForRuleDeletion returns the conjMatchFlowContextChanges of the deleted policyRuleConjunction. It
// will calculate the expected conjMatchFlowContext status, and the changed Openflow entries.
func (c *policyRuleConjunction) calculateChangesForRuleDeletion() []*conjMatchFlowContextChange {
	var ctxChanges []*conjMatchFlowContextChange
	if c.fromClause != nil {
		ctxChanges = append(ctxChanges, c.fromClause.deleteAllMatches()...)
	}
	if c.toClause != nil {
		ctxChanges = append(ctxChanges, c.toClause.deleteAllMatches()...)
	}
	if c.serviceClause != nil {
		ctxChanges = append(ctxChanges, c.serviceClause.deleteAllMatches()...)
	}
	return ctxChanges
}

// getAllFlowKeys returns the matching strings of actions flows of
// policyRuleConjunction, as well as matching flows of all its clauses.
func (c *policyRuleConjunction) getAllFlowKeys() []string {
	flowKeys := []string{}
	dropFlowKeys := []string{}
	for _, flow := range c.actionFlows {
		flowKeys = append(flowKeys, flow.MatchString())
	}

	addClauseFlowKeys := func(clause *clause) {
		if clause == nil {
			return
		}
		for _, ctx := range clause.matches {
			if ctx.flow != nil {
				flowKeys = append(flowKeys, ctx.flow.MatchString())
			}
			if ctx.dropFlow != nil {
				dropFlowKeys = append(dropFlowKeys, ctx.dropFlow.MatchString())
			}
		}
	}
	addClauseFlowKeys(c.fromClause)
	addClauseFlowKeys(c.toClause)
	addClauseFlowKeys(c.serviceClause)

	// Add flows in the order of action flows, conjunctive match flows, drop flows.
	return append(flowKeys, dropFlowKeys...)
}

func (c *client) getPolicyRuleConjunction(ruleID uint32) *policyRuleConjunction {
	conj, found, _ := c.policyCache.GetByKey(fmt.Sprint(ruleID))
	if !found {
		return nil
	}
	return conj.(*policyRuleConjunction)
}

func (c *client) GetPolicyInfoFromConjunction(ruleID uint32) (string, string) {
	conjunction := c.getPolicyRuleConjunction(ruleID)
	if conjunction == nil {
		return "", ""
	}
	priorities := conjunction.ActionFlowPriorities()
	if len(priorities) == 0 {
		return "", ""
	}
	return conjunction.npRef.ToString(), priorities[0]
}

// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
// It also returns a slice of stale ofPriorities used by ClusterNetworkPolicies.
// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
func (c *client) UninstallPolicyRuleFlows(ruleID uint32) ([]string, error) {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	conj := c.getPolicyRuleConjunction(ruleID)
	if conj == nil {
		klog.V(2).Infof("policyRuleConjunction with ID %d not found", ruleID)
		return nil, nil
	}
	staleOFPriorities := c.getStalePriorities(conj)
	// Delete action flows from the OVS bridge.
	if err := c.ofEntryOperations.DeleteAll(conj.actionFlows); err != nil {
		return nil, err
	}
	if err := c.ofEntryOperations.DeleteAll(conj.metricFlows); err != nil {
		return nil, err
	}

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	// Get the conjMatchFlowContext changes.
	ctxChanges := conj.calculateChangesForRuleDeletion()
	// Send the changed OpenFlow entries to the OVS bridge and update the conjMatchFlowContext.
	if err := c.applyConjunctiveMatchFlows(ctxChanges); err != nil {
		return nil, err
	}

	c.policyCache.Delete(conj)
	return staleOFPriorities, nil
}

// getStalePriorities returns the ofPriorities that will be stale on the rule table where the
// policyRuleConjunction is installed, after the deletion of that policyRuleConjunction.
func (c *client) getStalePriorities(conj *policyRuleConjunction) (staleOFPriorities []string) {
	var ofPrioritiesPotentiallyStale []string
	if conj.ruleTableID != IngressRuleTable.GetID() && conj.ruleTableID != EgressRuleTable.GetID() {
		ofPrioritiesPotentiallyStale = conj.ActionFlowPriorities()
	}
	klog.V(4).Infof("Potential stale ofpriority %v found", ofPrioritiesPotentiallyStale)
	for _, p := range ofPrioritiesPotentiallyStale {
		// Filter out all the policyRuleConjuctions created at the ofPriority across all CNP tables.
		conjs, _ := c.policyCache.ByIndex(priorityIndex, p)
		priorityStale := true
		for i := 0; i < len(conjs); i++ {
			conjFiltered := conjs[i].(*policyRuleConjunction)
			if conj.id != conjFiltered.id && conj.ruleTableID == conjFiltered.ruleTableID {
				// There are other policyRuleConjuctions in the same table created with this
				// ofPriority. The ofPriority is thus not stale and cannot be released.
				priorityStale = false
				break
			}
		}
		if priorityStale {
			klog.V(2).Infof("ofPriority %v is now stale", p)
			staleOFPriorities = append(staleOFPriorities, p)
		}
	}
	return staleOFPriorities
}

func (c *client) replayPolicyFlows() {
	var flows []binding.Flow
	addActionFlows := func(conj *policyRuleConjunction) {
		for _, flow := range conj.actionFlows {
			flow.Reset()
			flows = append(flows, flow)
		}
	}
	addMetricFlows := func(conj *policyRuleConjunction) {
		for _, flow := range conj.metricFlows {
			flow.Reset()
			flows = append(flows, flow)
		}
	}

	for _, conj := range c.policyCache.List() {
		addActionFlows(conj.(*policyRuleConjunction))
		addMetricFlows(conj.(*policyRuleConjunction))
	}

	addMatchFlows := func(ctx *conjMatchFlowContext) {
		if ctx.dropFlow != nil {
			ctx.dropFlow.Reset()
			flows = append(flows, ctx.dropFlow)
		}
		if ctx.flow != nil {
			ctx.flow.Reset()
			flows = append(flows, ctx.flow)
		}
	}

	for _, ctx := range c.globalConjMatchFlowCache {
		addMatchFlows(ctx)
	}
	if err := c.ofEntryOperations.AddAll(flows); err != nil {
		klog.Errorf("Error when replaying flows: %v", err)
	}
}

// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is srcAddress, the
// addresses are added to PolicyRule.From, else to PolicyRule.To.
func (c *client) AddPolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address, priority *uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	conj := c.getPolicyRuleConjunction(ruleID)
	// If policyRuleConjunction doesn't exist in client's policyCache return not found error. It should not happen, since
	// NetworkPolicyController will guarantee the policyRuleConjunction is created before this method is called. The check
	// here is for safety.
	if conj == nil {
		return newConjunctionNotFound(ruleID)
	}
	var clause = conj.getAddressClause(addrType)
	// Check if the clause is nil or not. The clause is nil if the addrType is an unsupported type.
	if clause == nil {
		return fmt.Errorf("no clause is using addrType %d", addrType)
	}

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	flowChanges := clause.addAddrFlows(c, addrType, addresses, priority)
	return c.applyConjunctiveMatchFlows(flowChanges)
}

// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is srcAddress, the addresses
// are removed from PolicyRule.From, else from PolicyRule.To.
func (c *client) DeletePolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address, priority *uint16) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	conj := c.getPolicyRuleConjunction(ruleID)
	// If policyRuleConjunction doesn't exist in client's policyCache return not found error. It should not happen, since
	// NetworkPolicyController will guarantee the policyRuleConjunction is created before this method is called. The check
	//	here is for safety.
	if conj == nil {
		return newConjunctionNotFound(ruleID)
	}

	var clause = conj.getAddressClause(addrType)
	// Check if the clause is nil or not. The clause is nil if the addrType is an unsupported type.
	if clause == nil {
		return fmt.Errorf("no clause is using addrType %d", addrType)
	}

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	// Remove policyRuleConjunction to actions of conjunctive match using specific address.
	changes := clause.deleteAddrFlows(addrType, addresses, priority)
	// Update the Openflow entries on the OVS bridge, and update local cache.
	return c.applyConjunctiveMatchFlows(changes)
}

func (c *client) GetNetworkPolicyFlowKeys(npName, npNamespace string) []string {
	flowKeys := []string{}
	// Hold replayMutex write lock to protect flows from being modified by
	// NetworkPolicy updates and replayPolicyFlows. This is more for logic
	// cleanliness, as: for now flow updates do not impact the matching string
	// generation; NetworkPolicy updates do not change policyRuleConjunction.actionFlows;
	// and last for protection of clause flows, conjMatchFlowLock is good enough.
	c.replayMutex.Lock()
	defer c.replayMutex.Unlock()

	for _, conjObj := range c.policyCache.List() {
		conj := conjObj.(*policyRuleConjunction)
		if conj.npRef.Name == npName && conj.npRef.Namespace == npNamespace {
			// There can be duplicated flows added due to conjunctive matches
			// shared by multiple policy rules (clauses).
			flowKeys = append(flowKeys, conj.getAllFlowKeys()...)
		}
	}
	return flowKeys
}

// flowUpdates stores updates to the actionFlows and matchFlows in a policyRuleConjunction.
type flowUpdates struct {
	newActionFlows []binding.Flow
	newPriority    uint16
}

// getMatchFlowUpdates calculates the update for conjuctiveMatchFlows in a policyRuleConjunction to be
// installed on a new priority.
func getMatchFlowUpdates(conj *policyRuleConjunction, newPriority uint16) (add, del []binding.Flow) {
	allClause := []*clause{conj.fromClause, conj.toClause, conj.serviceClause}
	for _, c := range allClause {
		if c == nil {
			continue
		}
		for _, ctx := range c.matches {
			f := ctx.flow
			updatedFlow := f.CopyToBuilder(newPriority, true).Done()
			add = append(add, updatedFlow)
			del = append(del, f)
		}
	}
	return add, del
}

// processFlowUpdates identifies the update cases in flow adds and deletes.
// For conjunctiveMatchFlow updates, the following scenario is possible:
//  A flow {priority=100,ip,reg1=0x1f action=conjunction(1,1/3)} need to be re-assigned priority=99.
//  In this case, an addFlow of <priority=99,ip,reg1=0x1f> and delFlow <priority=100,ip,reg1=0x1f> will be issued.
//  At the same time, another flow {priority=99,ip,reg1=0x1f action=conjunction(2,1/3)} exists and now needs to
//  be re-assigned priority 98. This operation will issue a delFlow <priority=99,ip,reg1=0x1f>, which
//  would essentially void the add flow for conj=1.
// In this case, we remove the conflicting delFlow and set addFlow as a modifyFlow.
func (c *client) processFlowUpdates(addFlows, delFlows []binding.Flow) (add, update, del []binding.Flow) {
	for _, a := range addFlows {
		matched := false
		for i := 0; i < len(delFlows); i++ {
			if a.FlowPriority() == delFlows[i].FlowPriority() && a.MatchString() == delFlows[i].MatchString() {
				matched = true
				// treat the addFlow as update
				update = append(update, a)
				// remove the delFlow from the list
				delFlows = append(delFlows[:i], delFlows[i+1:]...)
				// reset list index as delFlows[i] is removed
				i--
			}
		}
		if !matched {
			add = append(add, a)
		}
	}
	del = delFlows
	return add, update, del
}

// updateConjunctionActionFlows constructs a new policyRuleConjunction with actionFlows updated to be
// stored in the policyCache.
func (c *client) updateConjunctionActionFlows(conj *policyRuleConjunction, updates flowUpdates) *policyRuleConjunction {
	newActionFlows := make([]binding.Flow, len(conj.actionFlows))
	copy(newActionFlows, updates.newActionFlows)
	newConj := &policyRuleConjunction{
		id:            conj.id,
		fromClause:    conj.fromClause,
		toClause:      conj.toClause,
		serviceClause: conj.serviceClause,
		actionFlows:   newActionFlows,
		npRef:         conj.npRef,
		ruleTableID:   conj.ruleTableID,
	}
	return newConj
}

// updateConjunctionMatchFlows updates the conjuctiveMatchFlows in a policyRuleConjunction.
func (c *client) updateConjunctionMatchFlows(conj *policyRuleConjunction, newPriority uint16) {
	allClause := []*clause{conj.fromClause, conj.toClause, conj.serviceClause}
	for _, cl := range allClause {
		if cl == nil {
			continue
		}
		for i, ctx := range cl.matches {
			delete(c.globalConjMatchFlowCache, ctx.generateGlobalMapKey())
			f := ctx.flow
			updatedFlow := f.CopyToBuilder(newPriority, true).Done()
			cl.matches[i].flow = updatedFlow
			cl.matches[i].priority = &newPriority
		}
		// update the globalConjMatchFlowCache so that the keys are updated
		for _, ctx := range cl.matches {
			c.globalConjMatchFlowCache[ctx.generateGlobalMapKey()] = ctx
		}
	}
}

// calculateFlowUpdates calculates the flow updates required for the priority re-assignments specified in the input map.
func (c *client) calculateFlowUpdates(updates map[uint16]uint16, table uint8) (addFlows, delFlows []binding.Flow,
	conjFlowUpdates map[uint32]flowUpdates) {
	conjFlowUpdates = map[uint32]flowUpdates{}
	for original, newPriority := range updates {
		originalPriorityStr := strconv.Itoa(int(original))
		conjs, _ := c.policyCache.ByIndex(priorityIndex, originalPriorityStr)
		for _, conjObj := range conjs {
			conj := conjObj.(*policyRuleConjunction)
			// Only re-assign flow priorities for flows in the table specified.
			if conj.ruleTableID != table {
				klog.V(4).Infof("Conjunction %v with the same actionFlow priority is from a different table %v", conj.id, conj.ruleTableID)
				continue
			}
			for _, actionFlow := range conj.actionFlows {
				flowPriority := actionFlow.FlowPriority()
				if flowPriority == original {
					// The OF flow was created at the priority which need to be re-installed
					// at the NewPriority now
					updatedFlow := actionFlow.CopyToBuilder(newPriority, true).Done()
					addFlows = append(addFlows, updatedFlow)
					delFlows = append(delFlows, actionFlow)
					// Store the actionFlow update to the policyRuleConjunction and update all
					// policyRuleConjunctions if flow installation is successful.
					conjFlowUpdates[conj.id] = flowUpdates{
						append(conjFlowUpdates[conj.id].newActionFlows, updatedFlow),
						newPriority,
					}
				}
			}
			matchFlowAdd, matchFlowDel := getMatchFlowUpdates(conj, newPriority)
			addFlows = append(addFlows, matchFlowAdd...)
			delFlows = append(delFlows, matchFlowDel...)
		}
	}
	return addFlows, delFlows, conjFlowUpdates
}

// ReassignFlowPriorities takes a list of priority updates, and update the actionFlows to replace
// the old priority with the desired one, for each priority update.
func (c *client) ReassignFlowPriorities(updates map[uint16]uint16, table uint8) error {
	addFlows, delFlows, conjFlowUpdates := c.calculateFlowUpdates(updates, table)
	add, update, del := c.processFlowUpdates(addFlows, delFlows)
	// Commit the flows updates calculated.
	err := c.bridge.AddFlowsInBundle(add, update, del)
	if err != nil {
		return err
	}
	for conjID, actionUpdates := range conjFlowUpdates {
		originalConj, _, _ := c.policyCache.GetByKey(fmt.Sprint(conjID))
		conj := originalConj.(*policyRuleConjunction)
		updatedConj := c.updateConjunctionActionFlows(conj, actionUpdates)
		c.updateConjunctionMatchFlows(updatedConj, actionUpdates.newPriority)
		c.policyCache.Update(updatedConj)
	}
	return nil
}

func parseDropFlow(flowMap map[string]string) (uint32, types.RuleMetric) {
	m := types.RuleMetric{}
	pkts, _ := strconv.ParseUint(flowMap["n_packets"], 10, 64)
	m.Packets = pkts
	m.Sessions = pkts
	bytes, _ := strconv.ParseUint(flowMap["n_bytes"], 10, 64)
	m.Bytes = bytes
	reg3 := flowMap["reg3"]
	id, _ := strconv.ParseUint(reg3[:strings.Index(reg3, " ")], 0, 32)
	return uint32(id), m
}

func parseAllowFlow(flowMap map[string]string) (uint32, types.RuleMetric) {
	m := types.RuleMetric{}
	pkts, _ := strconv.ParseUint(flowMap["n_packets"], 10, 64)
	m.Packets = pkts
	if strings.Contains(flowMap["ct_state"], "+") { // ct_state=+new
		m.Sessions = pkts
	}
	bytes, _ := strconv.ParseUint(flowMap["n_bytes"], 10, 64)
	m.Bytes = bytes
	ct_label := flowMap["ct_label"]
	idRaw := ct_label[strings.Index(ct_label, "0x")+2 : strings.Index(ct_label, "/")]
	if len(idRaw) > 8 { // only 32 bits are valid.
		idRaw = idRaw[:len(idRaw)-8]
	}
	id, _ := strconv.ParseUint(idRaw, 16, 32)
	return uint32(id), m
}

func parseFlowToMap(flow string) map[string]string {
	split := strings.Split(flow, ",")
	flowMap := make(map[string]string)
	for _, seg := range split {
		equalIndex := strings.Index(seg, "=")
		// Some substrings spilt by "," may have no "=", for instance, if "resubmit(,70)" is present.
		if equalIndex == -1 {
			continue
		}
		flowMap[strings.TrimSpace(seg[:equalIndex])] = strings.TrimSpace(seg[equalIndex+1:])
	}
	return flowMap
}

func parseMetricFlow(flow string) (uint32, types.RuleMetric) {
	dropIdentifier := "reg0"
	flowMap := parseFlowToMap(flow)
	// example allow flow format:
	// table=101, n_packets=0, n_bytes=0, priority=200,ct_state=-new,ct_label=0x1/0xffffffff,ip actions=goto_table:105
	// example drop flow format:
	// table=101, n_packets=9, n_bytes=666, priority=200,reg0=0x100000/0x100000,reg3=0x5 actions=drop
	if _, ok := flowMap[dropIdentifier]; ok {
		return parseDropFlow(flowMap)
	}
	return parseAllowFlow(flowMap)
}

func (c *client) NetworkPolicyMetrics() map[uint32]*types.RuleMetric {
	result := map[uint32]*types.RuleMetric{}
	egressFlows, _ := c.ovsctlClient.DumpTableFlows(EgressMetricTable.GetID())
	ingressFlows, _ := c.ovsctlClient.DumpTableFlows(IngressMetricTable.GetID())

	collectMetricsFromFlows := func(flows []string) {
		for _, flow := range flows {
			if !strings.Contains(flow, metricFlowIdentifier) {
				continue
			}
			ruleID, metric := parseMetricFlow(flow)

			if accMetric, ok := result[ruleID]; ok {
				accMetric.Merge(&metric)
			} else {
				result[ruleID] = &metric
			}
		}
	}
	// We have two flows for each allow rule. One matches 'ct_state=+new'
	// and counts the number of first packets, which is also the number
	// of sessions (this is the reason why we have 2 flows). The other
	// matches 'ct_state=-new' and is used to count all subsequent
	// packets in the session. We need to merge metrics from these 2
	// flows to get the correct number of total packets.
	collectMetricsFromFlows(egressFlows)
	collectMetricsFromFlows(ingressFlows)
	return result
}

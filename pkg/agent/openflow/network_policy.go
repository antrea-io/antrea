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

	coreV1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const (
	MatchDstIP int = iota
	MatchSrcIP
	MatchDstIPNet
	MatchSrcIPNet
	MatchDstOFPort
	MatchSrcOFPort
	MatchTCPDstPort
	MatchUDPDstPort
	MatchSCTPDstPort
	Unsupported
)

// IP address calculated from Pod's address.
type IPAddress net.IP

func (a *IPAddress) GetMatchKey(addrType types.AddressType) int {
	switch addrType {
	case types.SrcAddress:
		return MatchSrcIP
	case types.DstAddress:
		return MatchDstIP
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

func (a *IPNetAddress) GetMatchKey(addrType types.AddressType) int {
	switch addrType {
	case types.SrcAddress:
		return MatchSrcIPNet
	case types.DstAddress:
		return MatchDstIPNet
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

func (a *OFPortAddress) GetMatchKey(addrType types.AddressType) int {
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
	tableID    binding.TableIDType
	matchKey   int
	matchValue interface{}
}

func (m *conjunctiveMatch) generateGlobalMapKey() string {
	return fmt.Sprintf("table:%d,type:%d,value:%s", m.tableID, m.matchKey, m.matchValue)
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

// installOrUpdateFlow installs or updates conjunctive match entries of the rule table.
func (ctx *conjMatchFlowContext) installOrUpdateFlow(actions []*conjunctiveAction) error {
	// Check if flow is already installed. If not, add new flow on the switch.
	if ctx.flow == nil {
		// Check then number of valid conjunctiveAction, no need to install openflow if it is 0. It happens when the match
		// condition is used only for matching AppliedToGroup, but no From or To is defined in the NetworkPolicy rule.
		if len(actions) == 0 {
			return nil
		}

		// Build the Openflow entry. actions here should not be empty for either add or update case.
		flow := ctx.client.conjunctiveMatchFlow(ctx.tableID, ctx.matchKey, ctx.matchValue, actions...)

		if err := flow.Add(); err != nil {
			return err
		}
		ctx.flow = flow

		return nil
	}

	// Modify existing Openflow entry with latest actions.
	flowBuilder := ctx.flow.CopyToBuilder()
	for _, act := range actions {
		flowBuilder.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	newFlow := flowBuilder.Done()
	if err := newFlow.Modify(); err != nil {
		return err
	}
	ctx.flow = newFlow
	return nil
}

// deleteAction deletes the specified policyRuleConjunction from conjunctiveMatchFlow's actions, and then updates the
// conjunctive match flow entry on the switch.
func (ctx *conjMatchFlowContext) deleteAction(conjID uint32) error {
	// If the specified conjunctive action is the last one in actions, delete the conjunctive match flow entry from the
	// switch. No need to check if the conjunction ID of the only conjunctive action is the specified ID or not, as it
	// has been checked in the caller.
	if len(ctx.actions) == 1 && ctx.flow != nil {
		if err := ctx.flow.Delete(); err != nil {
			return err
		}
		ctx.flow = nil
	} else {
		// Update Openflow entry with the left conjunctive actions.
		var actions []*conjunctiveAction
		for _, act := range ctx.actions {
			if act.conjID != conjID {
				actions = append(actions, act)
			}
		}
		err := ctx.installOrUpdateFlow(actions)
		if err != nil {
			return err
		}
	}
	delete(ctx.actions, conjID)
	return nil
}

// addAction adds the specified conjunction into conjunctiveMatchFlow's actions, and then updates the conjunctive
// match flow on the switch. It also installs default drop flow if dropTable is not nil, and the dropFlow is not
// installed before.
func (ctx *conjMatchFlowContext) addAction(action *conjunctiveAction) error {
	// Check if the conjunction exists in conjMatchFlowContext actions or not. If yes, return nil directly.
	// Otherwise, add the new action, and update the Openflow entry.
	_, found := ctx.actions[action.conjID]
	if found {
		return nil
	}

	// Install or update Openflow entry for the new conjunctiveAction.
	actions := make([]*conjunctiveAction, 0, len(ctx.actions)+1)
	for _, act := range ctx.actions {
		actions = append(actions, act)
	}
	actions = append(actions, action)
	err := ctx.installOrUpdateFlow(actions)
	if err != nil {
		return err
	}
	ctx.actions[action.conjID] = action

	return nil
}

func (ctx *conjMatchFlowContext) addDenyAllRule(ruleID uint32) error {
	if ctx.denyAllRules == nil {
		ctx.denyAllRules = make(map[uint32]bool)
	}
	ctx.denyAllRules[ruleID] = true
	return nil
}

// policyRuleConjunction is responsible to build Openflow entries for Pods that are in a NetworkPolicy rule's AppliedToGroup.
// The Openflow entries include conjunction action flows, conjunctive match flows, and default drop flows in the dropTable.
// NetworkPolicyController will make sure only one goroutine operates on a policyRuleConjunction.
// 1) Conjunction action flows use policyRuleConjunction ID as match condition. policyRuleConjunction ID is the single
// 	  match condition for conjunction action flows to allow packets. If the NetworkPolicy rule has also configured excepts
// 	  in From or To, extra Openflow entries are installed to drop packets using the addresses in the excepts and
// 	  policyRuleConjunction ID as the match conditions, and these flows have a higher priority than the one only matching
// 	  policyRuleConjunction ID.
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

func (c *clause) addConjunctiveMatchFlow(client *client, match *conjunctiveMatch) error {
	matcherKey := match.generateGlobalMapKey()
	_, found := c.matches[matcherKey]
	if found {
		klog.V(2).Infof("Conjunctive match flow with matcher %s is already added in rule: %d", matcherKey, c.action.conjID)
		return nil
	}

	client.conjMatchFlowLock.Lock()
	defer client.conjMatchFlowLock.Unlock()

	// Get conjMatchFlowContext from globalConjMatchFlowCache. If it doesn't exist, create a new one and add into the cache.
	context, found := client.globalConjMatchFlowCache[matcherKey]
	if !found {
		context = &conjMatchFlowContext{
			conjunctiveMatch: match,
			actions:          make(map[uint32]*conjunctiveAction),
			client:           client,
		}

		// Install the default drop flow entry if dropTable is not nil.
		if c.dropTable != nil && context.dropFlow == nil {
			dropFlow := context.client.defaultDropFlow(c.dropTable.GetID(), match.matchKey, match.matchValue)
			if err := dropFlow.Add(); err != nil {
				return err
			}
			context.dropFlow = dropFlow
		}
		client.globalConjMatchFlowCache[matcherKey] = context
	}
	if c.action.nClause > 1 {
		// Add the conjunction into conjunctiveFlowContext's actions, and update the flow entry on the switch.
		err := context.addAction(c.action)
		if err != nil {
			return err
		}
	} else {
		// Add the DENY-ALL rule into conjunctiveFlowContext's denyAllRules.
		err := context.addDenyAllRule(c.action.conjID)
		if err != nil {
			return err
		}
	}

	c.matches[matcherKey] = context

	return nil
}

func (c *clause) generateAddressConjMatch(addr types.Address, addrType types.AddressType) *conjunctiveMatch {
	matchKey := addr.GetMatchKey(addrType)
	matchValue := addr.GetValue()
	match := &conjunctiveMatch{
		tableID:    c.ruleTable.GetID(),
		matchKey:   matchKey,
		matchValue: matchValue,
	}
	return match
}

func getServiceMatchType(protocol *coreV1.Protocol) int {
	switch *protocol {
	case coreV1.ProtocolTCP:
		return MatchTCPDstPort
	case coreV1.ProtocolUDP:
		return MatchUDPDstPort
	case coreV1.ProtocolSCTP:
		return MatchSCTPDstPort
	default:
		return MatchTCPDstPort
	}
}

func (c *clause) generateServicePortConjMatch(port *v1.NetworkPolicyPort) *conjunctiveMatch {
	matchKey := getServiceMatchType(port.Protocol)
	matchValue := uint16(port.Port.IntVal)
	match := &conjunctiveMatch{
		tableID:    c.ruleTable.GetID(),
		matchKey:   matchKey,
		matchValue: matchValue,
	}
	return match
}

// addAddrFlows translates the specified addresses to conjunctiveMatchFlow, and installs corresponding Openflow entry.
func (c *clause) addAddrFlows(client *client, addrType types.AddressType, addresses []types.Address) error {
	for _, addr := range addresses {
		match := c.generateAddressConjMatch(addr, addrType)
		err := c.addConjunctiveMatchFlow(client, match)
		if err != nil {
			return err
		}
	}
	return nil
}

// addServiceFlows translates the specified NetworkPolicyPorts to conjunctiveMatchFlow, and installs corresponding Openflow entry.
func (c *clause) addServiceFlows(client *client, ports []*v1.NetworkPolicyPort) error {
	for _, port := range ports {
		match := c.generateServicePortConjMatch(port)
		err := c.addConjunctiveMatchFlow(client, match)
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteConjunctiveMatchFlow deletes the specific conjunctiveAction from existing flow.
func (c *clause) deleteConjunctiveMatchFlow(flowContextKey string) error {
	context, found := c.matches[flowContextKey]
	// Match is not located in clause cache. It happens if the conjMatchFlowContext is already deleted from clause local cache.
	if !found {
		return nil
	}

	conjID := c.action.conjID
	context.client.conjMatchFlowLock.Lock()
	defer context.client.conjMatchFlowLock.Unlock()
	if c.action.nClause > 1 {
		// Delete the conjunctive action if it is in context actions.
		_, found = context.actions[conjID]
		if found {
			err := context.deleteAction(conjID)
			if err != nil {
				return err
			}
		}
	} else {
		// Delete the DENY-ALL rule if it is in context denyAllRules.
		_, found := context.denyAllRules[conjID]
		if found {
			delete(context.denyAllRules, conjID)
		}
	}

	// Uninstall default drop flow if both actions and denyAllRules are empty.
	if len(context.actions) == 0 && len(context.denyAllRules) == 0 {
		if context.dropFlow != nil {
			if err := context.dropFlow.Delete(); err != nil {
				return err
			}
			context.dropFlow = nil
		}
		// Remove the context from global cache after both the conjunctive match flow and the default drop
		// flow are uninstalled from the switch.
		delete(context.client.globalConjMatchFlowCache, context.generateGlobalMapKey())
	}

	// Delete the key of conjMatchFlowContext from clause matches.
	delete(c.matches, flowContextKey)
	return nil
}

// deleteAddrFlows deletes conjunctiveMatchFlow relevant to the specified addresses from local cache,
// and uninstalls Openflow entry.
func (c *clause) deleteAddrFlows(addrType types.AddressType, addresses []types.Address) error {
	for _, addr := range addresses {
		match := c.generateAddressConjMatch(addr, addrType)
		contextKey := match.generateGlobalMapKey()
		err := c.deleteConjunctiveMatchFlow(contextKey)
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteAllMatches deletes all conjunctiveMatchFlow in the clause, and removes Openflow entry. deleteAllMatches
// is always invoked when NetworkPolicy rule is deleted.
func (c *clause) deleteAllMatches() error {
	for key := range c.matches {
		err := c.deleteConjunctiveMatchFlow(key)
		if err != nil {
			return err
		}
	}
	return nil
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
// For a normal NetworkPolicy rule, these Openflow entries are installed: 1) 1 conjunction action flow, and 0 or multiple
// conjunction except flows, the number of conjunction excepts flows is decided by the addresses in rule.ExceptFrom and
// rule.ExceptTo is configured; 2) multiple conjunctive match flows, the flow number depends on addresses in rule.From
// and rule.To, and service ports in rule.Service; and 3) multiple default drop flows, the number is dependent on
// on the addresses in rule.From for an egress rule, and addresses in rule.To for an ingress rule.
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

	// Check if the policyRuleConjunction is added into cache or not. If yes, return nil.
	conj := c.getPolicyRuleConjunction(rule.ID)
	if conj != nil {
		klog.V(2).Infof("PolicyRuleConjunction %d is already added in cache", rule.ID)
		return nil
	}

	var ruleTable, dropTable binding.Table
	var isEgressRule = false
	switch rule.Direction {
	case v1.PolicyTypeEgress:
		ruleTable = c.pipeline[egressRuleTable]
		dropTable = c.pipeline[egressDefaultTable]
		isEgressRule = true
	default:
		ruleTable = c.pipeline[ingressRuleTable]
		dropTable = c.pipeline[ingressDefaultTable]
	}
	conj = &policyRuleConjunction{
		id: rule.ID,
	}

	var fromID, toID, serviceID, nClause uint8
	// Calculate clause ID
	if rule.From != nil {
		nClause += 1
		fromID = nClause
	}
	if rule.To != nil {
		nClause += 1
		toID = nClause
	}
	if rule.Service != nil {
		nClause += 1
		serviceID = nClause
	}

	// Conjunction action flows are installed only if the number of clauses in the conjunction is > 1. It should be a rule
	// to drop all packets.  If the number is 1, no conjunctive match flows or conjunction action flows are installed,
	// but the default drop flow is installed.
	if nClause > 1 {
		// Install action flows.
		var actionFlows = []binding.Flow{
			c.conjunctionActionFlow(rule.ID, ruleTable.GetID(), dropTable.GetNext()),
		}
		if rule.ExceptFrom != nil {
			for _, addr := range rule.ExceptFrom {
				flow := c.conjunctionExceptionFlow(rule.ID, ruleTable.GetID(), dropTable.GetID(), addr.GetMatchKey(types.SrcAddress), addr.GetValue())
				actionFlows = append(actionFlows, flow)
			}
		}
		if rule.ExceptTo != nil {
			for _, addr := range rule.ExceptTo {
				flow := c.conjunctionExceptionFlow(rule.ID, ruleTable.GetID(), dropTable.GetID(), addr.GetMatchKey(types.DstAddress), addr.GetValue())
				actionFlows = append(actionFlows, flow)
			}
		}
		for _, flow := range actionFlows {
			err := flow.Add()
			if err != nil {
				return err
			}
		}
		conj.actionFlows = actionFlows
	}

	// Install conjunctive match flows if exists in rule.Form/To/Service
	var defaultTable binding.Table
	if rule.From != nil {
		if isEgressRule {
			defaultTable = dropTable
		} else {
			defaultTable = nil
		}
		conj.fromClause = conj.newClause(fromID, nClause, ruleTable, defaultTable)
		if err := conj.fromClause.addAddrFlows(c, types.SrcAddress, rule.From); err != nil {
			return err
		}
	}
	if rule.To != nil {
		if !isEgressRule {
			defaultTable = dropTable
		} else {
			defaultTable = nil
		}
		conj.toClause = conj.newClause(toID, nClause, ruleTable, defaultTable)
		if err := conj.toClause.addAddrFlows(c, types.DstAddress, rule.To); err != nil {
			return err
		}
	}
	if rule.Service != nil {
		conj.serviceClause = conj.newClause(serviceID, nClause, ruleTable, nil)
		if err := conj.serviceClause.addServiceFlows(c, rule.Service); err != nil {
			return err
		}
	}
	c.policyCache.Store(rule.ID, conj)
	return nil
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

func (c *client) getPolicyRuleConjunction(ruleID uint32) *policyRuleConjunction {
	conj, found := c.policyCache.Load(ruleID)
	if !found {
		return nil
	}
	return conj.(*policyRuleConjunction)
}

// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
func (c *client) UninstallPolicyRuleFlows(ruleID uint32) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	conj := c.getPolicyRuleConjunction(ruleID)
	if conj == nil {
		klog.V(2).Infof("policyRuleConjunction with ID %d not found", ruleID)
		return nil
	}

	// Delete action flows
	for _, flow := range conj.actionFlows {
		err := flow.Delete()
		if err != nil {
			return err
		}
	}

	// Remove conjunctive match flows grouped by this PolicyRuleConjunction's clauses.
	if conj.fromClause != nil {
		err := conj.fromClause.deleteAllMatches()
		if err != nil {
			return err
		}
	}
	if conj.toClause != nil {
		err := conj.toClause.deleteAllMatches()
		if err != nil {
			return err
		}
	}
	if conj.serviceClause != nil {
		err := conj.serviceClause.deleteAllMatches()
		if err != nil {
			return err
		}
	}

	// Remove policyRuleConjunction from client's policyCache.
	c.policyCache.Delete(ruleID)
	return nil
}

func (c *client) replayPolicyFlows() {
	addActionFlows := func(conj *policyRuleConjunction) {
		for _, flow := range conj.actionFlows {
			if err := flow.Add(); err != nil {
				klog.Errorf("Error when replaying flow: %v", err)
			}
		}
	}

	c.policyCache.Range(func(key, value interface{}) bool {
		addActionFlows(value.(*policyRuleConjunction))
		return true
	})

	for _, ctx := range c.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			if err := ctx.dropFlow.Add(); err != nil {
				klog.Errorf("Error when replaying flow: %v", err)
			}
		}
		if ctx.flow != nil {
			if err := ctx.flow.Add(); err != nil {
				klog.Errorf("Error when replaying flow: %v", err)
			}
		}
	}
}

// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is srcAddress, the
// addresses are added to PolicyRule.From, else to PolicyRule.To.
func (c *client) AddPolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error {
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
	return clause.addAddrFlows(c, addrType, addresses)
}

// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is srcAddress, the addresses
// are removed from PolicyRule.From, else from PolicyRule.To.
func (c *client) DeletePolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error {
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
	// Remove policyRuleConjunction to actions of conjunctive match using specific address.
	return clause.deleteAddrFlows(addrType, addresses)
}

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

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
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
	var valueStr string
	matchType := m.matchKey
	switch v := m.matchValue.(type) {
	case net.IP:
		// Use the unique format "x.x.x.x/xx" for IP address and IP net, to avoid generating two different global map
		// keys for IP and IP/32. Use MatchDstIPNet/MatchSrcIPNet as match type to generate global cache key for both IP
		// and IPNet. This is because OVS treats IP and IP/32 as the same condition, if Antrea has two different
		// conjunctive match flow contexts, only one flow entry is installed on OVS, and the conjunctive actions in the
		// first context wil be overwritten by those in the second one.
		valueStr = fmt.Sprintf("%s/32", v.String())
		switch m.matchKey {
		case MatchDstIP:
			matchType = MatchDstIPNet
		case MatchSrcIP:
			matchType = MatchSrcIPNet
		}
	case net.IPNet:
		valueStr = v.String()
	default:
		// The default cases include the matchValue is a Service port or an ofport Number.
		valueStr = fmt.Sprintf("%s", m.matchValue)
	}
	return fmt.Sprintf("table:%d,type:%d,value:%s", m.tableID, matchType, valueStr)
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
		flow := ctx.client.conjunctiveMatchFlow(ctx.tableID, ctx.matchKey, ctx.matchValue, actions...)
		return &flowChange{
			flow:       flow,
			changeType: insertion,
		}
	}

	// Modify the existing Openflow entry and reset the actions.
	flowBuilder := ctx.flow.CopyToBuilder()
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
	} else {
		// Modify the Openflow entry and reset the other conjunctive actions.
		var actions []*conjunctiveAction
		for _, act := range ctx.actions {
			if act.conjID != conjID {
				actions = append(actions, act)
			}
		}
		return ctx.createOrUpdateConjunctiveMatchFlow(actions)
	}
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
	// NetworkPolicy name and Namespace information for debugging usage.
	npName      string
	npNamespace string
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
				flow:       context.client.defaultDropFlow(c.dropTable.GetID(), match.matchKey, match.matchValue),
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

func getServiceMatchType(protocol *v1beta1.Protocol) int {
	switch *protocol {
	case v1beta1.ProtocolTCP:
		return MatchTCPDstPort
	case v1beta1.ProtocolUDP:
		return MatchUDPDstPort
	case v1beta1.ProtocolSCTP:
		return MatchSCTPDstPort
	default:
		return MatchTCPDstPort
	}
}

func (c *clause) generateServicePortConjMatch(port v1beta1.Service) *conjunctiveMatch {
	matchKey := getServiceMatchType(port.Protocol)
	matchValue := uint16(port.Port.IntVal)
	match := &conjunctiveMatch{
		tableID:    c.ruleTable.GetID(),
		matchKey:   matchKey,
		matchValue: matchValue,
	}
	return match
}

// addAddrFlows translates the specified addresses to conjunctiveMatchFlows, and returns the corresponding changes on the
// conjunctiveMatchFlows.
func (c *clause) addAddrFlows(client *client, addrType types.AddressType, addresses []types.Address) []*conjMatchFlowContextChange {
	var conjMatchFlowContextChanges []*conjMatchFlowContextChange
	// Calculate Openflow changes for the added addresses.
	for _, addr := range addresses {
		match := c.generateAddressConjMatch(addr, addrType)
		ctxChange := c.addConjunctiveMatchFlow(client, match)
		if ctxChange != nil {
			conjMatchFlowContextChanges = append(conjMatchFlowContextChanges, ctxChange)
		}
	}
	return conjMatchFlowContextChanges
}

// addServiceFlows translates the specified NetworkPolicyPorts to conjunctiveMatchFlow, and returns corresponding
// conjMatchFlowContextChange.
func (c *clause) addServiceFlows(client *client, ports []v1beta1.Service) []*conjMatchFlowContextChange {
	var conjMatchFlowContextChanges []*conjMatchFlowContextChange
	for _, port := range ports {
		match := c.generateServicePortConjMatch(port)
		ctxChange := c.addConjunctiveMatchFlow(client, match)
		conjMatchFlowContextChanges = append(conjMatchFlowContextChanges, ctxChange)
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
func (c *clause) deleteAddrFlows(addrType types.AddressType, addresses []types.Address) []*conjMatchFlowContextChange {
	var ctxChanges []*conjMatchFlowContextChange
	for _, addr := range addresses {
		match := c.generateAddressConjMatch(addr, addrType)
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
func (c *client) InstallPolicyRuleFlows(ruleID uint32, rule *types.PolicyRule, npName, npNamespace string) error {
	c.replayMutex.RLock()
	defer c.replayMutex.RUnlock()

	// Check if the policyRuleConjunction is added into cache or not. If yes, return nil.
	conj := c.getPolicyRuleConjunction(ruleID)
	if conj != nil {
		klog.V(2).Infof("PolicyRuleConjunction %d is already added in cache", ruleID)
		return nil
	}

	conj = &policyRuleConjunction{
		id:          ruleID,
		npName:      npName,
		npNamespace: npNamespace}
	nClause, ruleTable, dropTable := conj.calculateClauses(rule, c)

	// Conjunction action flows are installed only if the number of clauses in the conjunction is > 1. It should be a rule
	// to drop all packets.  If the number is 1, no conjunctive match flows or conjunction action flows are installed,
	// but the default drop flow is installed.
	if nClause > 1 {
		// Install action flows.
		var actionFlows = []binding.Flow{
			c.conjunctionActionFlow(ruleID, ruleTable.GetID(), dropTable.GetNext()),
		}
		if err := c.ofEntryOperations.AddAll(actionFlows); err != nil {
			return nil
		}
		// Add the action flows after the Openflow entries are installed on the OVS bridge successfully.
		conj.actionFlows = actionFlows
	}
	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()

	// Calculate the conjMatchFlowContext changes. The changed Openflow entries are included in the conjMatchFlowContext change.
	ctxChanges := conj.calculateChangesForRuleCreation(c, rule)

	// Send the changed Openflow entries to the OVS bridge, and then update the conjMatchFlowContext as the expected status.
	if err := c.applyConjunctiveMatchFlows(ctxChanges); err != nil {
		return err
	}
	// Add the policyRuleConjunction into policyCache.
	c.policyCache.Store(ruleID, conj)
	return nil
}

// applyConjunctiveMatchFlows installs OpenFlow entries on the OVS bridge, and then updates the conjMatchFlowContext.
func (c *client) applyConjunctiveMatchFlows(flowChanges []*conjMatchFlowContextChange) error {
	// Send the OpenFlow entries to the OVS bridge.
	if err := c.sendConjunctiveMatchFlows(flowChanges); err != nil {
		return err
	}
	// Update conjunctiveMatchContext.
	for _, ctxChange := range flowChanges {
		ctxChange.updateContextStatus()
	}
	return nil
}

// sendConjunctiveMatchFlows sends all the changed OpenFlow entries to the OVS bridge in a single Bundle.
func (c *client) sendConjunctiveMatchFlows(changes []*conjMatchFlowContextChange) error {
	var addFlows, modifyFlows, deleteFlows []binding.Flow
	var flowChanges []*flowChange
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
	var ruleTable, dropTable binding.Table
	var isEgressRule = false
	switch rule.Direction {
	case v1beta1.DirectionOut:
		ruleTable = clnt.pipeline[egressRuleTable]
		dropTable = clnt.pipeline[egressDefaultTable]
		isEgressRule = true
	default:
		ruleTable = clnt.pipeline[ingressRuleTable]
		dropTable = clnt.pipeline[ingressDefaultTable]
	}

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
		if isEgressRule {
			defaultTable = dropTable
		} else {
			defaultTable = nil
		}
		c.fromClause = c.newClause(fromID, nClause, ruleTable, defaultTable)
	}
	if rule.To != nil {
		if !isEgressRule {
			defaultTable = dropTable
		} else {
			defaultTable = nil
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
		ctxChanges = append(ctxChanges, c.fromClause.addAddrFlows(clnt, types.SrcAddress, rule.From)...)
	}
	if c.toClause != nil {
		ctxChanges = append(ctxChanges, c.toClause.addAddrFlows(clnt, types.DstAddress, rule.To)...)
	}
	if c.serviceClause != nil {
		ctxChanges = append(ctxChanges, c.serviceClause.addServiceFlows(clnt, rule.Service)...)
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

	// Delete action flows from the OVS bridge.
	if err := c.ofEntryOperations.DeleteAll(conj.actionFlows); err != nil {
		return err
	}

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	// Get the conjMatchFlowContext changes.
	ctxChanges := conj.calculateChangesForRuleDeletion()
	// Send the changed OpenFlow entries to the OVS bridge and update the conjMatchFlowContext.
	if err := c.applyConjunctiveMatchFlows(ctxChanges); err != nil {
		return err
	}

	// Remove policyRuleConjunction from client's policyCache.
	c.policyCache.Delete(ruleID)
	return nil
}

func (c *client) replayPolicyFlows() {
	var flows []binding.Flow
	addActionFlows := func(conj *policyRuleConjunction) {
		for _, flow := range conj.actionFlows {
			flow.Reset()
			flows = append(flows, flow)
		}
	}

	c.policyCache.Range(func(key, value interface{}) bool {
		addActionFlows(value.(*policyRuleConjunction))
		return true
	})

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

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	flowChanges := clause.addAddrFlows(c, addrType, addresses)
	return c.applyConjunctiveMatchFlows(flowChanges)
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

	c.conjMatchFlowLock.Lock()
	defer c.conjMatchFlowLock.Unlock()
	// Remove policyRuleConjunction to actions of conjunctive match using specific address.
	changes := clause.deleteAddrFlows(addrType, addresses)
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

	c.policyCache.Range(func(key, value interface{}) bool {
		conj := value.(*policyRuleConjunction)
		if conj.npName == npName && conj.npNamespace == npNamespace {
			// There can be duplicated flows added due to conjunctive matches
			// shared by multiple policy rules (clauses).
			flowKeys = append(flowKeys, conj.getAllFlowKeys()...)
		}
		return true
	})
	return flowKeys
}

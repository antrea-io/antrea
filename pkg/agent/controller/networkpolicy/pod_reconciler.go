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

package networkpolicy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	baselineTierPriority int32 = 253
	banpTierPriority     int32 = 254
)

type ruleType int

const (
	unicast   ruleType = 0
	igmp      ruleType = 1
	multicast ruleType = 2

	igmpServicesKey = "igmp-services-key"
)

// Reconciler is an interface that knows how to reconcile the desired state of
// CompletedRule with the actual state of Openflow entries.
type Reconciler interface {
	// Reconcile reconciles the desired state of the provided CompletedRule
	// with the actual state of Openflow entries.
	Reconcile(rule *CompletedRule) error

	// BatchReconcile reconciles the desired state of the provided CompletedRules
	// with the actual state of Openflow entries in batch. It should only be invoked
	// if all rules are newly added without last realized status.
	BatchReconcile(rules []*CompletedRule) error

	// Forget cleanups the actual state of Openflow entries of the specified ruleID.
	Forget(ruleID string) error

	// GetRuleByFlowID returns the rule from the async rule cache in idAllocator cache.
	GetRuleByFlowID(ruleID uint32) (*types.PolicyRule, bool, error)

	// RunIDAllocatorWorker runs the worker that deletes the rules from the cache
	// in idAllocator.
	RunIDAllocatorWorker(stopCh <-chan struct{})
}

// servicesKey is used to identify Services based on their numbered ports.
type servicesKey string

// normalizeServices calculates the servicesKey of the provided services based
// on their numbered ports.
// It constructs the string with strings.Builder instead of using the spew
// library for efficiency consideration as this function is called quite often.
// It ignores the difference of protocol and non resolved ports because the
// servicesKey is only used to distinguish the results obtained by resolving
// named ports for the same services.
func normalizeServices(services []v1beta2.Service) servicesKey {
	var b strings.Builder
	for _, svc := range services {
		if svc.Port != nil {
			if svc.Port.Type == intstr.String {
				binary.Write(&b, binary.BigEndian, int32(0))
			} else {
				binary.Write(&b, binary.BigEndian, svc.Port.IntVal)
			}
		}
	}
	return servicesKey(b.String())
}

// podPolicyLastRealized is the struct cached by podReconciler. It's used to track the
// actual state of rules we have enforced, so that we can know how to reconcile
// a rule when it's updated/removed.
// It includes the last version of CompletedRule the podReconciler has realized
// and the related runtime information including the ofIDs, the Openflow ports
// or the IP addresses of the target Pods got from the InterfaceStore.
//
// Note that a policy rule can be split into multiple Openflow rules based on
// the named port resolving result. Pods that have same port numbers for the
// port names defined in the rule will share an Openflow rule. For example,
// if an ingress rule applies to 3 Pods like below:
//
// NetworkPolicy rule:
//
//	spec:
//	 ingress:
//	 - from:
//	   - namespaceSelector: {}
//	   ports:
//	   - port: http
//	     protocol: TCP
//
// Pod A and Pod B:
//
//	spec:
//	  containers:
//	  - ports:
//	    - containerPort: 80
//	      name: http
//	      protocol: TCP
//
// Pod C:
//
//	spec:
//	  containers:
//	  - ports:
//	    - containerPort: 8080
//	      name: http
//	      protocol: TCP
//
// Then Pod A and B will share an Openflow rule as both of them resolve "http" to 80,
// while Pod C will have another Openflow rule as it resolves "http" to 8080.
// In the implementation, we group Pods by their resolved services value so Pod A and B
// can be mapped to same group.
type podPolicyLastRealized struct {
	// ofIDs identifies Openflow rules in Openflow implementation.
	// It's a map of servicesKey to Openflow rule ID.
	ofIDs map[servicesKey]uint32
	// The desired state of a policy rule.
	*CompletedRule
	// The OFPort set we have realized for target Pods. We need to record them
	// because this info will be removed from InterfaceStore after CNI DEL, we
	// can't know which OFPort to delete when deleting a Pod from the rule. So
	// we compare the last realized OFPorts and the new desired one to identify
	// difference, which could also cover the stale OFPorts produced by the case
	// that Kubelet calls CNI ADD for a Pod more than once due to non CNI issues.
	// It's only used for ingress rule as its "to" addresses.
	// It's grouped by servicesKey, mapping to multiple Openflow rules.
	podOFPorts map[servicesKey]sets.Set[int32]
	// The IP set we have realized for target Pods. Same as podOFPorts.
	// It's only used for egress rule as its "from" addresses.
	// It's same in all Openflow rules, because named port is only for
	// destination Pods.
	podIPs sets.Set[string]
	// fqdnIPaddresses tracks the last realized set of IP addresses resolved for
	// the fqdn selector of this policy rule. It must be empty for policy rule
	// that is not egress and does not have toFQDN field.
	fqdnIPAddresses sets.Set[string]
	// serviceGroupIDs tracks the last realized set of groupIDs resolved for the
	// toServices of this policy rule or services of TargetMember of this policy rule.
	// It must be empty for policy rule that is neither an egress rule with toServices
	// field nor an ingress rule that is applied to Services.
	serviceGroupIDs sets.Set[int64]
	// groupAddresses track the latest realized set of multicast groups for the multicast traffic
	groupAddresses sets.Set[string]
}

func newPodPolicyLastRealized(rule *CompletedRule) *podPolicyLastRealized {
	return &podPolicyLastRealized{
		ofIDs:           map[servicesKey]uint32{},
		CompletedRule:   rule,
		podOFPorts:      map[servicesKey]sets.Set[int32]{},
		podIPs:          nil,
		fqdnIPAddresses: nil,
		serviceGroupIDs: nil,
		groupAddresses:  nil,
	}
}

// tablePriorityAssigner groups the priorityAssigner and mutex for a single OVS table
// that is reserved for installing Antrea policy rules.
type tablePriorityAssigner struct {
	assigner *priorityAssigner
	mutex    sync.RWMutex
}

// podReconciler implements Reconciler.
// Note that although its Reconcile and Forget methods are thread-safe, it's
// assumed each rule can only be processed by a single client at any given
// time. Different rules can be processed in parallel.
type podReconciler struct {
	// ofClient is the Openflow interface.
	ofClient openflow.Client

	// ifaceStore provides container interface OFPort and IP information.
	ifaceStore interfacestore.InterfaceStore

	// lastRealizeds caches the last realized rules.
	// It's a mapping from ruleID to *podPolicyLastRealized.
	lastRealizeds sync.Map

	// idAllocator provides interfaces to allocateForRule and release uint32 id.
	idAllocator *idAllocator

	// priorityAssigners provides interfaces to manage OF priorities for each OVS table.
	priorityAssigners map[uint8]*tablePriorityAssigner
	// ipv4Enabled tells if IPv4 is supported on this Node or not.
	ipv4Enabled bool
	// ipv6Enabled tells is IPv6 is supported on this Node or not.
	ipv6Enabled bool

	// fqdnController manages dns cache of FQDN rules. It provides interfaces for the
	// podReconciler to register FQDN policy rules and query the IP addresses corresponded
	// to a FQDN.
	fqdnController *fqdnController

	// groupCounters is a list of GroupCounter for v4 and v6 env. podReconciler uses these
	// GroupCounters to get the groupIDs of a specific Service.
	groupCounters []proxytypes.GroupCounter

	// multicastEnabled indicates whether multicast is enabled
	multicastEnabled bool
}

// newPodReconciler returns a new *podReconciler.
func newPodReconciler(ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	idAllocator *idAllocator,
	fqdnController *fqdnController,
	groupCounters []proxytypes.GroupCounter,
	v4Enabled bool,
	v6Enabled bool,
	antreaPolicyEnabled bool,
	multicastEnabled bool,
) *podReconciler {
	priorityAssigners := map[uint8]*tablePriorityAssigner{}
	if antreaPolicyEnabled {
		for _, table := range openflow.GetAntreaPolicyBaselineTierTables() {
			priorityAssigners[table.GetID()] = &tablePriorityAssigner{
				assigner: newPriorityAssigner(true),
			}
		}
		for _, table := range openflow.GetAntreaPolicyMultiTierTables() {
			priorityAssigners[table.GetID()] = &tablePriorityAssigner{
				assigner: newPriorityAssigner(false),
			}
		}
		if multicastEnabled {
			for _, table := range openflow.GetAntreaMulticastEgressTables() {
				priorityAssigners[table.GetID()] = &tablePriorityAssigner{
					assigner: newPriorityAssigner(false),
				}
			}
			for _, table := range openflow.GetAntreaIGMPIngressTables() {
				priorityAssigners[table.GetID()] = &tablePriorityAssigner{
					assigner: newPriorityAssigner(false),
				}
			}
		}
	}
	reconciler := &podReconciler{
		ofClient:          ofClient,
		ifaceStore:        ifaceStore,
		lastRealizeds:     sync.Map{},
		idAllocator:       idAllocator,
		priorityAssigners: priorityAssigners,
		fqdnController:    fqdnController,
		groupCounters:     groupCounters,
		multicastEnabled:  multicastEnabled,
	}
	// Check if ofClient is nil or not to be compatible with unit tests.
	if ofClient != nil {
		reconciler.ipv4Enabled = v4Enabled
		reconciler.ipv6Enabled = v6Enabled
	}
	return reconciler
}

// RunIDAllocatorWorker runs the worker that deletes the rules from the cache in
// idAllocator.
func (r *podReconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {
	r.idAllocator.runWorker(stopCh)
}

// Reconcile checks whether the provided rule has been enforced or not, and
// invoke the add or update method accordingly.
func (r *podReconciler) Reconcile(rule *CompletedRule) error {
	klog.InfoS("Reconciling Pod NetworkPolicy rule", "rule", rule.ID, "policy", rule.SourceRef.ToString())
	var err error
	var ofPriority *uint16

	value, exists := r.lastRealizeds.Load(rule.ID)
	ruleTable := r.getOFRuleTable(rule)
	priorityAssigner, _ := r.priorityAssigners[ruleTable]
	// IGMP Egress policy is enforced in userspace via packet-in message, there won't be OpenFlow
	// rules created for such rules. Therefore, assigning priority is not required.
	if rule.isAntreaNetworkPolicyRule() && !rule.isIGMPEgressPolicyRule() {
		// For CNP, only release priorityMutex after rule is installed on OVS. Otherwise,
		// priority re-assignments for flows that have already been assigned priorities but
		// not yet installed on OVS will be missed.
		priorityAssigner.mutex.Lock()
		defer priorityAssigner.mutex.Unlock()
	}
	ofPriority, registeredBefore, err := r.getOFPriority(rule, ruleTable, priorityAssigner)
	if err != nil {
		return err
	}
	var ofRuleInstallErr error
	if !exists {
		ofRuleInstallErr = r.add(rule, ofPriority, ruleTable)
	} else {
		ofRuleInstallErr = r.update(value.(*podPolicyLastRealized), rule, ofPriority, ruleTable)
	}
	if ofRuleInstallErr != nil && ofPriority != nil && !registeredBefore {
		priorityAssigner.assigner.release(*ofPriority)
	}
	return ofRuleInstallErr
}

func (r *podReconciler) getRuleType(rule *CompletedRule) ruleType {
	if !r.multicastEnabled {
		return unicast
	}
	for _, service := range rule.Services {
		if service.Protocol != nil && *service.Protocol == v1beta2.ProtocolIGMP {
			return igmp
		}
	}

	for _, ipBlock := range rule.To.IPBlocks {
		ipAddr := ip.IPNetToNetIPNet(&ipBlock.CIDR)
		if ipAddr.IP.IsMulticast() {
			return multicast
		}
	}
	return unicast
}

// getOFRuleTable retrieves the OpenFlow table to install the CompletedRule.
// The decision is made based on whether the rule is created for an ACNP/ANNP, and
// the Tier of that NetworkPolicy.
func (r *podReconciler) getOFRuleTable(rule *CompletedRule) uint8 {
	rType := r.getRuleType(rule)
	var ruleTables []*openflow.Table
	var tableID uint8
	switch rType {
	case unicast:
		if !rule.isAntreaNetworkPolicyRule() {
			if rule.Direction == v1beta2.DirectionIn {
				return openflow.IngressRuleTable.GetID()
			}
			return openflow.EgressRuleTable.GetID()
		}
		if rule.Direction == v1beta2.DirectionIn {
			ruleTables = openflow.GetAntreaPolicyIngressTables()
		} else {
			ruleTables = openflow.GetAntreaPolicyEgressTables()
		}
		if *rule.TierPriority != baselineTierPriority && *rule.TierPriority != banpTierPriority {
			return ruleTables[0].GetID()
		}
		tableID = ruleTables[1].GetID()
	case igmp:
		if rule.Direction == v1beta2.DirectionIn {
			ruleTables = openflow.GetAntreaIGMPIngressTables()
			tableID = ruleTables[0].GetID()
		}
	case multicast:
		// Multicast NetworkPolicy only supports egress so far, we leave tableID as 0
		// for ingress rules for multicast, later we will return empty flows for it.
		if rule.Direction == v1beta2.DirectionOut {
			ruleTables = openflow.GetAntreaMulticastEgressTables()
			tableID = ruleTables[0].GetID()
		}
	}
	return tableID
}

// getOFPriority retrieves the OFPriority for the input CompletedRule to be installed,
// and re-arranges installed priorities on OVS if necessary.
func (r *podReconciler) getOFPriority(rule *CompletedRule, tableID uint8, pa *tablePriorityAssigner) (*uint16, bool, error) {
	// IGMP Egress policy is enforced in userspace via packet-in message, there won't be OpenFlow
	// rules created for such rules. Therefore, assigning priority is not required.
	if !rule.isAntreaNetworkPolicyRule() || rule.isIGMPEgressPolicyRule() {
		klog.V(2).InfoS("Assigning default priority for K8s NetworkPolicy")
		return nil, true, nil
	}
	p := types.Priority{
		TierPriority:   *rule.TierPriority,
		PolicyPriority: *rule.PolicyPriority,
		RulePriority:   rule.Priority,
	}
	ofPriority, registered := pa.assigner.getOFPriority(p)
	if !registered {
		allPrioritiesInPolicy := make([]types.Priority, rule.MaxPriority+1)
		for i := int32(0); i <= rule.MaxPriority; i++ {
			allPrioritiesInPolicy[i] = types.Priority{
				TierPriority:   *rule.TierPriority,
				PolicyPriority: *rule.PolicyPriority,
				RulePriority:   i,
			}
		}
		priorityUpdates, revertFunc, err := pa.assigner.registerPriorities(allPrioritiesInPolicy)
		if err != nil {
			return nil, registered, err
		}
		// Re-assign installed priorities on OVS
		if len(priorityUpdates) > 0 {
			err := r.ofClient.ReassignFlowPriorities(priorityUpdates, tableID)
			if err != nil {
				revertFunc()
				return nil, registered, err
			}
		}
		ofPriority, _ = pa.assigner.getOFPriority(p)
	}
	klog.V(2).InfoS("Assigning OFPriority to rule", "rule", rule.ID, "priority", ofPriority)
	return &ofPriority, registered, nil
}

// BatchReconcile reconciles the desired state of the provided CompletedRules
// with the actual state of Openflow entries in batch. It should only be invoked
// if all rules are newly added without last realized status.
func (r *podReconciler) BatchReconcile(rules []*CompletedRule) error {
	var rulesToInstall []*CompletedRule
	var priorities []*uint16
	prioritiesByTable := map[uint8][]*uint16{}
	for _, rule := range rules {
		if _, exists := r.lastRealizeds.Load(rule.ID); exists {
			klog.ErrorS(nil, "Rule should not have been realized yet: initialization phase", "rule", rule.ID)
		} else {
			rulesToInstall = append(rulesToInstall, rule)
		}
	}
	if err := r.registerOFPriorities(rulesToInstall); err != nil {
		return err
	}
	for _, rule := range rulesToInstall {
		ruleTable := r.getOFRuleTable(rule)
		priorityAssigner := r.priorityAssigners[ruleTable]
		klog.V(2).InfoS("Adding NetworkPolicy rule to be reconciled in batch", "rule", rule.ID, "policy", rule.SourceRef.ToString())
		ofPriority, _, _ := r.getOFPriority(rule, ruleTable, priorityAssigner)
		priorities = append(priorities, ofPriority)
		if ofPriority != nil {
			prioritiesByTable[ruleTable] = append(prioritiesByTable[ruleTable], ofPriority)
		}
	}
	ofRuleInstallErr := r.batchAdd(rulesToInstall, priorities)
	if ofRuleInstallErr != nil {
		// If batch reconcile fails, all priorities should be released and the
		// priorityAssigners should return to the initial state.
		for tableID, ofPriorities := range prioritiesByTable {
			pa := r.priorityAssigners[tableID]
			for _, ofPriority := range ofPriorities {
				pa.assigner.release(*ofPriority)
			}
		}
	}
	return ofRuleInstallErr
}

// registerOFPriorities constructs a Priority type for each CompletedRule in the input list,
// and registers those Priorities with appropriate tablePriorityAssigner based on Tier.
func (r *podReconciler) registerOFPriorities(rules []*CompletedRule) error {
	prioritiesToRegister := map[uint8][]types.Priority{}
	for _, rule := range rules {
		// IGMP Egress policy is enforced in userspace via packet-in message, there won't be OpenFlow
		// rules created for such rules. Therefore, assigning priority is not required.
		if rule.isAntreaNetworkPolicyRule() && !rule.isIGMPEgressPolicyRule() {
			ruleTable := r.getOFRuleTable(rule)
			p := types.Priority{
				TierPriority:   *rule.TierPriority,
				PolicyPriority: *rule.PolicyPriority,
				RulePriority:   rule.Priority,
			}
			prioritiesToRegister[ruleTable] = append(prioritiesToRegister[ruleTable], p)
		}
	}
	for tableID, priorities := range prioritiesToRegister {
		if _, _, err := r.priorityAssigners[tableID].assigner.registerPriorities(priorities); err != nil {
			return err
		}
	}
	return nil
}

// add converts CompletedRule to PolicyRule(s) and invokes installOFRule to install them.
func (r *podReconciler) add(rule *CompletedRule, ofPriority *uint16, table uint8) error {
	klog.V(2).InfoS("Adding new rule", "rule", rule)
	ofRuleByServicesMap, lastRealized := r.computeOFRulesForAdd(rule, ofPriority, table)
	for svcKey, ofRule := range ofRuleByServicesMap {
		// Each pod group gets an Openflow ID.
		err := r.idAllocator.allocateForRule(ofRule)
		if err != nil {
			return fmt.Errorf("error allocating Openflow ID")
		}
		if err = r.installOFRule(ofRule); err != nil {
			if r.fqdnController != nil {
				lastRealized.fqdnIPAddresses = nil
			}
			lastRealized.serviceGroupIDs = nil
			return err
		}
		// Record ofID only if its Openflow is installed successfully.
		lastRealized.ofIDs[svcKey] = ofRule.FlowID
	}
	return nil
}

func (r *podReconciler) computeOFRulesForAdd(rule *CompletedRule, ofPriority *uint16, table uint8) (
	map[servicesKey]*types.PolicyRule, *podPolicyLastRealized) {
	lastRealized := newPodPolicyLastRealized(rule)
	// TODO: Handle the case that the following processing fails or partially succeeds.
	r.lastRealizeds.Store(rule.ID, lastRealized)

	ofRuleByServicesMap := map[servicesKey]*types.PolicyRule{}
	isIGMP := r.isIGMPRule(rule)
	if isIGMP && rule.Direction == v1beta2.DirectionIn {
		// IGMP query
		ofPorts := r.getOFPorts(rule.TargetMembers)
		lastRealized.podOFPorts[igmpServicesKey] = ofPorts
		ofRuleByServicesMap[igmpServicesKey] = &types.PolicyRule{
			Direction:     v1beta2.DirectionIn,
			To:            ofPortsToOFAddresses(ofPorts),
			Service:       rule.Services,
			Action:        rule.Action,
			Name:          rule.Name,
			Priority:      ofPriority,
			TableID:       table,
			PolicyRef:     rule.SourceRef,
			EnableLogging: rule.EnableLogging,
			LogLabel:      rule.LogLabel,
		}
		return ofRuleByServicesMap, lastRealized
	} else if isIGMP {
		// IGMP report
		return ofRuleByServicesMap, lastRealized
	}
	if rule.Direction == v1beta2.DirectionIn {
		isRuleAppliedToService := isRuleAppliedToService(rule.TargetMembers)
		// Addresses got from source GroupMembers' IPs.
		from1 := groupMembersToOFAddresses(rule.FromAddresses)
		// Get addresses that in From IPBlock but not in Except IPBlocks.
		from2 := ipBlocksToOFAddresses(rule.From.IPBlocks, r.ipv4Enabled, r.ipv6Enabled, isRuleAppliedToService)
		from3 := labelIDToOFAddresses(rule.From.LabelIdentities)
		from := append(from1, append(from2, from3...)...)
		membersByServicesMap, servicesMap := groupMembersByServices(rule.Services, rule.TargetMembers)
		for svcKey, members := range membersByServicesMap {
			var toAddresses []types.Address
			if isRuleAppliedToService {
				svcGroupIDs := r.getSvcGroupIDs(members)
				toAddresses = svcGroupIDsToOFAddresses(svcGroupIDs)
				// If rule is applied to Services, there will be only one svcKey, which is "", in
				// membersByServicesMap. So podPolicyLastRealized.serviceGroupIDs won't be overwritten in
				// this for-loop.
				lastRealized.serviceGroupIDs = svcGroupIDs
			} else {
				ofPorts := r.getOFPorts(members)
				toAddresses = ofPortsToOFAddresses(ofPorts)
				lastRealized.podOFPorts[svcKey] = ofPorts
			}
			ofRuleByServicesMap[svcKey] = &types.PolicyRule{
				Direction:     v1beta2.DirectionIn,
				From:          from,
				To:            toAddresses,
				Service:       filterUnresolvablePort(servicesMap[svcKey]),
				L7Protocols:   rule.L7Protocols,
				L7RuleVlanID:  rule.L7RuleVlanID,
				Action:        rule.Action,
				Name:          rule.Name,
				Priority:      ofPriority,
				TableID:       table,
				PolicyRef:     rule.SourceRef,
				EnableLogging: rule.EnableLogging,
				LogLabel:      rule.LogLabel,
			}
		}
	} else {
		if r.fqdnController != nil && len(rule.To.FQDNs) > 0 {
			// TODO: addFQDNRule installs new conjunctive flows, so maybe it doesn't
			// belong in computeOFRulesForAdd. The error handling needs to be corrected
			// as well: if the flows failed to install, there should be a retry
			// mechanism.
			if err := r.fqdnController.addFQDNRule(rule.ID, rule.To.FQDNs, r.getOFPorts(rule.TargetMembers)); err != nil {
				klog.ErrorS(err, "Error when adding FQDN rule", "ruleID", rule.ID)
			}
		}
		ips := r.getIPs(rule.TargetMembers)
		lastRealized.podIPs = ips
		from := ipsToOFAddresses(ips)
		memberByServicesMap, servicesMap := groupMembersByServices(rule.Services, rule.ToAddresses)
		for svcKey, members := range memberByServicesMap {
			ofRuleByServicesMap[svcKey] = &types.PolicyRule{
				Direction:     v1beta2.DirectionOut,
				From:          from,
				To:            groupMembersToOFAddresses(members),
				Service:       filterUnresolvablePort(servicesMap[svcKey]),
				L7Protocols:   rule.L7Protocols,
				L7RuleVlanID:  rule.L7RuleVlanID,
				Action:        rule.Action,
				Priority:      ofPriority,
				Name:          rule.Name,
				TableID:       table,
				PolicyRef:     rule.SourceRef,
				EnableLogging: rule.EnableLogging,
				LogLabel:      rule.LogLabel,
			}
		}

		// If there are no "ToAddresses", the above process doesn't create any PolicyRule.
		// We must ensure there is at least one PolicyRule, otherwise the Pods won't be
		// isolated, so we create a PolicyRule with the original services if it doesn't exist.
		// If there are IPBlocks or Pods that cannot resolve any named port, they will share
		// this PolicyRule. Antrea policies do not need this default isolation.
		if !rule.isAntreaNetworkPolicyRule() || len(rule.To.IPBlocks) > 0 || len(rule.To.FQDNs) > 0 || len(rule.To.ToServices) > 0 {
			svcKey := normalizeServices(rule.Services)
			ofRule, exists := ofRuleByServicesMap[svcKey]
			// Create a new Openflow rule if the group doesn't exist.
			if !exists {
				ofRule = &types.PolicyRule{
					Direction:     v1beta2.DirectionOut,
					From:          from,
					To:            []types.Address{},
					Service:       filterUnresolvablePort(rule.Services),
					Action:        rule.Action,
					Name:          rule.Name,
					Priority:      nil,
					TableID:       table,
					PolicyRef:     rule.SourceRef,
					EnableLogging: rule.EnableLogging,
					LogLabel:      rule.LogLabel,
				}
				ofRuleByServicesMap[svcKey] = ofRule
			}
			if len(rule.To.IPBlocks) > 0 {
				// Diff Addresses between To and Except of IPBlocks
				to := ipBlocksToOFAddresses(rule.To.IPBlocks, r.ipv4Enabled, r.ipv6Enabled, false)
				ofRule.To = append(ofRule.To, to...)
			}
			if r.fqdnController != nil && len(rule.To.FQDNs) > 0 {
				var addresses []types.Address
				addressSet := sets.New[string]()
				matchedIPs := r.fqdnController.getIPsForFQDNSelectors(rule.To.FQDNs)
				for _, ipAddr := range matchedIPs {
					addresses = append(addresses, openflow.NewIPAddress(ipAddr))
					addressSet.Insert(ipAddr.String())
				}
				ofRule.To = append(ofRule.To, addresses...)
				// If the rule installation fails, this will be reset
				lastRealized.fqdnIPAddresses = addressSet
			}
			if len(rule.To.ToServices) > 0 {
				svcGroupIDs := r.svcRefsToGroupIDs(rule.To.ToServices)
				addresses := svcGroupIDsToOFAddresses(svcGroupIDs)
				ofRule.To = append(ofRule.To, addresses...)
				// If the rule installation fails, this will be reset.
				lastRealized.serviceGroupIDs = svcGroupIDs
			}
		}
	}
	return ofRuleByServicesMap, lastRealized
}

// batchAdd converts CompletedRules to PolicyRules and invokes BatchInstallPolicyRuleFlows to install them.
func (r *podReconciler) batchAdd(rules []*CompletedRule, ofPriorities []*uint16) error {
	lastRealizeds := make([]*podPolicyLastRealized, len(rules))
	ofIDUpdateMaps := make([]map[servicesKey]uint32, len(rules))

	var allOFRules []*types.PolicyRule

	for idx, rule := range rules {
		ruleTable := r.getOFRuleTable(rule)
		ofRuleByServicesMap, lastRealized := r.computeOFRulesForAdd(rule, ofPriorities[idx], ruleTable)
		lastRealizeds[idx] = lastRealized
		for svcKey, ofRule := range ofRuleByServicesMap {
			err := r.idAllocator.allocateForRule(ofRule)
			if err != nil {
				return fmt.Errorf("error allocating Openflow ID")
			}
			allOFRules = append(allOFRules, ofRule)
			if ofIDUpdateMaps[idx] == nil {
				ofIDUpdateMaps[idx] = make(map[servicesKey]uint32)
			}
			ofIDUpdateMaps[idx][svcKey] = ofRule.FlowID
		}
	}
	if err := r.ofClient.BatchInstallPolicyRuleFlows(allOFRules); err != nil {
		for _, rule := range allOFRules {
			r.idAllocator.forgetRule(rule.FlowID)
		}
		return err
	}
	for i, lastRealized := range lastRealizeds {
		ofIDUpdatesByRule := ofIDUpdateMaps[i]
		for svcKey, ofID := range ofIDUpdatesByRule {
			lastRealized.ofIDs[svcKey] = ofID
		}
	}
	return nil
}

// update calculates the difference of Addresses between oldRule and newRule,
// and invokes Openflow client's methods to reconcile them.
func (r *podReconciler) update(lastRealized *podPolicyLastRealized, newRule *CompletedRule, ofPriority *uint16, table uint8) error {
	klog.V(2).InfoS("Updating existing rule", "rule", newRule)
	// staleOFIDs tracks servicesKey that are no long needed.
	// Firstly fill it with the last realized ofIDs.
	staleOFIDs := make(map[servicesKey]uint32, len(lastRealized.ofIDs))
	for svcKey, ofID := range lastRealized.ofIDs {
		staleOFIDs[svcKey] = ofID
	}
	isIGMP := r.isIGMPRule(newRule)
	if isIGMP && newRule.Direction == v1beta2.DirectionIn {
		// IGMP query
		newOFPorts := r.getOFPorts(newRule.TargetMembers)
		ofID, exists := lastRealized.ofIDs[igmpServicesKey]
		// Install a new Openflow rule if this group doesn't exist, otherwise do incremental update.
		if !exists {
			ofRule := &types.PolicyRule{
				Direction:     v1beta2.DirectionIn,
				To:            ofPortsToOFAddresses(newOFPorts),
				Service:       newRule.Services,
				L7Protocols:   newRule.L7Protocols,
				L7RuleVlanID:  newRule.L7RuleVlanID,
				Action:        newRule.Action,
				Priority:      ofPriority,
				FlowID:        ofID,
				TableID:       table,
				PolicyRef:     newRule.SourceRef,
				EnableLogging: newRule.EnableLogging,
				LogLabel:      newRule.LogLabel,
			}
			err := r.idAllocator.allocateForRule(ofRule)
			if err != nil {
				return err
			}
			if err = r.installOFRule(ofRule); err != nil {
				return err
			}
			lastRealized.ofIDs[igmpServicesKey] = ofRule.FlowID
		} else {
			addedTo := ofPortsToOFAddresses(newOFPorts.Difference(lastRealized.podOFPorts[igmpServicesKey]))
			deletedTo := ofPortsToOFAddresses(lastRealized.podOFPorts[igmpServicesKey].Difference(newOFPorts))
			if err := r.updateOFRule(ofID, nil, addedTo, nil, deletedTo, ofPriority, newRule.EnableLogging, false); err != nil {
				return err
			}
		}
		lastRealized.podOFPorts[igmpServicesKey] = newOFPorts
		return nil
	} else if isIGMP {
		// IGMP report
		return nil
	}
	// As rule identifier is calculated from the rule's content, the update can
	// only happen to Group members.
	if newRule.Direction == v1beta2.DirectionIn {
		isRuleAppliedToService := isRuleAppliedToService(newRule.TargetMembers)
		from1 := groupMembersToOFAddresses(newRule.FromAddresses)
		from2 := ipBlocksToOFAddresses(newRule.From.IPBlocks, r.ipv4Enabled, r.ipv6Enabled, isRuleAppliedToService)
		addedFrom := ipsToOFAddresses(newRule.FromAddresses.IPDifference(lastRealized.FromAddresses))
		deletedFrom := ipsToOFAddresses(lastRealized.FromAddresses.IPDifference(newRule.FromAddresses))

		membersByServicesMap, servicesMap := groupMembersByServices(newRule.Services, newRule.TargetMembers)
		for svcKey, members := range membersByServicesMap {
			newOFPorts := r.getOFPorts(members)
			newGroupIDSet := r.getSvcGroupIDs(members)
			var toAddresses []types.Address
			if isRuleAppliedToService {
				toAddresses = svcGroupIDsToOFAddresses(newGroupIDSet)
			} else {
				toAddresses = ofPortsToOFAddresses(newOFPorts)
			}
			ofID, exists := lastRealized.ofIDs[svcKey]
			// Install a new Openflow rule if this group doesn't exist, otherwise do incremental update.
			if !exists {
				ofRule := &types.PolicyRule{
					Direction:     v1beta2.DirectionIn,
					From:          append(from1, from2...),
					To:            toAddresses,
					Service:       filterUnresolvablePort(servicesMap[svcKey]),
					L7Protocols:   newRule.L7Protocols,
					L7RuleVlanID:  newRule.L7RuleVlanID,
					Action:        newRule.Action,
					Priority:      ofPriority,
					FlowID:        ofID,
					TableID:       table,
					PolicyRef:     newRule.SourceRef,
					EnableLogging: newRule.EnableLogging,
					LogLabel:      newRule.LogLabel,
				}
				err := r.idAllocator.allocateForRule(ofRule)
				if err != nil {
					return err
				}
				if err = r.installOFRule(ofRule); err != nil {
					return err
				}
				lastRealized.ofIDs[svcKey] = ofRule.FlowID
			} else {
				var addedTo, deletedTo []types.Address
				if isRuleAppliedToService {
					originalGroupIDSet := sets.New[int64]()
					if lastRealized.serviceGroupIDs != nil {
						originalGroupIDSet = lastRealized.serviceGroupIDs
					}
					addedTo = svcGroupIDsToOFAddresses(newGroupIDSet.Difference(originalGroupIDSet))
					deletedTo = svcGroupIDsToOFAddresses(originalGroupIDSet.Difference(newGroupIDSet))
				} else {
					originalOfPortsSet := sets.New[int32]()
					if lastRealized.podOFPorts[svcKey] != nil {
						originalOfPortsSet = lastRealized.podOFPorts[svcKey]
					}
					addedTo = ofPortsToOFAddresses(newOFPorts.Difference(originalOfPortsSet))
					deletedTo = ofPortsToOFAddresses(originalOfPortsSet.Difference(newOFPorts))
				}
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo, ofPriority, newRule.EnableLogging, len(newRule.From.LabelIdentities) > 0); err != nil {
					return err
				}
				// Delete valid servicesKey from staleOFIDs.
				delete(staleOFIDs, svcKey)
			}
			lastRealized.podOFPorts[svcKey] = newOFPorts
			lastRealized.serviceGroupIDs = newGroupIDSet
		}
	} else {
		if r.fqdnController != nil && len(newRule.To.FQDNs) > 0 {
			if err := r.fqdnController.addFQDNRule(newRule.ID, newRule.To.FQDNs, r.getOFPorts(newRule.TargetMembers)); err != nil {
				return fmt.Errorf("error when adding FQDN rule %s: %w", newRule.ID, err)
			}
		}
		newIPs := r.getIPs(newRule.TargetMembers)
		from := ipsToOFAddresses(newIPs)
		addedFrom := ipsToOFAddresses(newIPs.Difference(lastRealized.podIPs))
		deletedFrom := ipsToOFAddresses(lastRealized.podIPs.Difference(newIPs))

		memberByServicesMap, servicesMap := groupMembersByServices(newRule.Services, newRule.ToAddresses)
		// Same as the process in `add`, we must ensure the group for the original services is present
		// in memberByServicesMap, so that this group won't be removed and its "From" will be updated.
		originalSvcKey := normalizeServices(newRule.Services)
		if _, exists := memberByServicesMap[originalSvcKey]; !exists {
			memberByServicesMap[originalSvcKey] = v1beta2.NewGroupMemberSet()
			servicesMap[originalSvcKey] = newRule.Services
		}
		prevMembersByServicesMap, _ := groupMembersByServices(lastRealized.Services, lastRealized.ToAddresses)
		for svcKey, members := range memberByServicesMap {
			ofID, exists := lastRealized.ofIDs[svcKey]
			if !exists {
				ofRule := &types.PolicyRule{
					Direction:     v1beta2.DirectionOut,
					From:          from,
					To:            groupMembersToOFAddresses(members),
					Service:       filterUnresolvablePort(servicesMap[svcKey]),
					L7Protocols:   newRule.L7Protocols,
					L7RuleVlanID:  newRule.L7RuleVlanID,
					Action:        newRule.Action,
					Priority:      ofPriority,
					FlowID:        ofID,
					TableID:       table,
					PolicyRef:     newRule.SourceRef,
					EnableLogging: newRule.EnableLogging,
					LogLabel:      newRule.LogLabel,
				}
				// If the PolicyRule for the original services doesn't exist and IPBlocks is present, it means the
				// podReconciler hasn't installed flows for IPBlocks, then it must be added to the new PolicyRule.
				if svcKey == originalSvcKey && len(newRule.To.IPBlocks) > 0 {
					to := ipBlocksToOFAddresses(newRule.To.IPBlocks, r.ipv4Enabled, r.ipv6Enabled, false)
					ofRule.To = append(ofRule.To, to...)
				}
				err := r.idAllocator.allocateForRule(ofRule)
				if err != nil {
					return fmt.Errorf("error allocating Openflow ID")
				}
				if err = r.installOFRule(ofRule); err != nil {
					return err
				}
				lastRealized.ofIDs[svcKey] = ofRule.FlowID
			} else {
				addedTo := ipsToOFAddresses(members.IPDifference(prevMembersByServicesMap[svcKey]))
				deletedTo := ipsToOFAddresses(prevMembersByServicesMap[svcKey].IPDifference(members))
				originalFQDNAddressSet, newFQDNAddressSet := sets.New[string](), sets.New[string]()
				if r.fqdnController != nil {
					if lastRealized.fqdnIPAddresses != nil {
						originalFQDNAddressSet = lastRealized.fqdnIPAddresses
					}
					if svcKey == originalSvcKey && len(newRule.To.FQDNs) > 0 {
						matchedIPs := r.fqdnController.getIPsForFQDNSelectors(newRule.To.FQDNs)
						for _, ipAddr := range matchedIPs {
							newFQDNAddressSet.Insert(ipAddr.String())
						}
						addedFQDNAddress := newFQDNAddressSet.Difference(originalFQDNAddressSet)
						removedFQDNAddress := originalFQDNAddressSet.Difference(newFQDNAddressSet)
						for a := range addedFQDNAddress {
							addedTo = append(addedTo, openflow.NewIPAddress(net.ParseIP(a)))
						}
						for r := range removedFQDNAddress {
							deletedTo = append(deletedTo, openflow.NewIPAddress(net.ParseIP(r)))
						}
					}
				}
				originalGroupIDSet, newGroupIDSet := sets.New[int64](), sets.New[int64]()
				if len(newRule.To.ToServices) > 0 {
					if lastRealized.serviceGroupIDs != nil {
						originalGroupIDSet = lastRealized.serviceGroupIDs
					}
					newGroupIDSet = r.svcRefsToGroupIDs(newRule.To.ToServices)
					addedTo = svcGroupIDsToOFAddresses(newGroupIDSet.Difference(originalGroupIDSet))
					deletedTo = svcGroupIDsToOFAddresses(originalGroupIDSet.Difference(newGroupIDSet))
				}
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo, ofPriority, newRule.EnableLogging, false); err != nil {
					return err
				}
				if r.fqdnController != nil {
					// Update the FQDN address set if rule installation succeeds.
					lastRealized.fqdnIPAddresses = newFQDNAddressSet
				}
				// Update the groupID address set if rule installation succeeds.
				lastRealized.serviceGroupIDs = newGroupIDSet
				// Delete valid servicesKey from staleOFIDs.
				delete(staleOFIDs, svcKey)
			}
		}
		lastRealized.podIPs = newIPs
	}
	// Remove stale Openflow rules.
	for svcKey, ofID := range staleOFIDs {
		if err := r.uninstallOFRule(ofID, table); err != nil {
			return err
		}
		delete(lastRealized.ofIDs, svcKey)
		delete(lastRealized.podOFPorts, svcKey)
	}
	lastRealized.CompletedRule = newRule
	return nil
}

func (r *podReconciler) installOFRule(ofRule *types.PolicyRule) error {
	klog.V(2).InfoS("Installing ofRule", "id", ofRule.FlowID, "direction", ofRule.Direction, "from", len(ofRule.From), "to", len(ofRule.To), "service", len(ofRule.Service))
	if err := r.ofClient.InstallPolicyRuleFlows(ofRule); err != nil {
		r.idAllocator.forgetRule(ofRule.FlowID)
		return fmt.Errorf("error installing ofRule %v: %v", ofRule.FlowID, err)
	}
	return nil
}

func (r *podReconciler) updateOFRule(ofID uint32, addedFrom []types.Address, addedTo []types.Address, deletedFrom []types.Address, deletedTo []types.Address, priority *uint16, enableLogging, isMCNPRule bool) error {
	klog.V(2).InfoS("Updating ofRule", "id", ofID, "addedFrom", len(addedFrom), "addedTo", len(addedTo), "deletedFrom", len(deletedFrom), "deletedTo", len(deletedTo))
	// TODO: This might be unnecessarily complex and hard for error handling, consider revising the Openflow interfaces.
	if len(addedFrom) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.SrcAddress, addedFrom, priority, enableLogging, isMCNPRule); err != nil {
			return fmt.Errorf("error adding policy rule source addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(addedTo) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.DstAddress, addedTo, priority, enableLogging, isMCNPRule); err != nil {
			return fmt.Errorf("error adding policy rule destination addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(deletedFrom) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(ofID, types.SrcAddress, deletedFrom, priority); err != nil {
			return fmt.Errorf("error deleting policy rule source addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(deletedTo) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(ofID, types.DstAddress, deletedTo, priority); err != nil {
			return fmt.Errorf("error deleting policy rule destination addresses for ofRule %v: %v", ofID, err)
		}
	}
	return nil
}

func (r *podReconciler) uninstallOFRule(ofID uint32, table uint8) error {
	klog.V(2).InfoS("Uninstalling ofRule", "id", ofID)
	stalePriorities, err := r.ofClient.UninstallPolicyRuleFlows(ofID)
	if err != nil {
		return fmt.Errorf("error uninstalling ofRule %v: %v", ofID, err)
	}
	if len(stalePriorities) > 0 {
		for _, p := range stalePriorities {
			klog.V(2).InfoS("Releasing stale priority value", "priority", p)
			priorityNum, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				// Cannot parse the priority str. Theoretically this should never happen.
				return err
			}
			// If there are stalePriorities, priorityAssigners[table] must not be nil.
			priorityAssigner, _ := r.priorityAssigners[table]
			priorityAssigner.assigner.release(uint16(priorityNum))
		}
	}
	r.idAllocator.forgetRule(ofID)
	return nil
}

// Forget invokes UninstallPolicyRuleFlows to uninstall Openflow entries
// associated with the provided ruleID if it was enforced before.
func (r *podReconciler) Forget(ruleID string) error {
	klog.InfoS("Forgetting rule", "rule", ruleID)

	value, exists := r.lastRealizeds.Load(ruleID)
	if !exists {
		// No-op if the rule was not realized before.
		return nil
	}

	lastRealized := value.(*podPolicyLastRealized)
	table := r.getOFRuleTable(lastRealized.CompletedRule)
	priorityAssigner, exists := r.priorityAssigners[table]
	if exists {
		priorityAssigner.mutex.Lock()
		defer priorityAssigner.mutex.Unlock()
	}
	for svcKey, ofID := range lastRealized.ofIDs {
		if err := r.uninstallOFRule(ofID, table); err != nil {
			return err
		}
		delete(lastRealized.ofIDs, svcKey)
		delete(lastRealized.podOFPorts, svcKey)
	}
	if r.fqdnController != nil {
		r.fqdnController.deleteFQDNRule(ruleID, lastRealized.To.FQDNs)
	}
	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *podReconciler) isIGMPRule(rule *CompletedRule) bool {
	isIGMP := false
	if len(rule.Services) > 0 && (rule.Services[0].Protocol != nil) &&
		(*rule.Services[0].Protocol == v1beta2.ProtocolIGMP) {
		isIGMP = true
	}
	return isIGMP
}

func (r *podReconciler) GetRuleByFlowID(ruleFlowID uint32) (*types.PolicyRule, bool, error) {
	return r.idAllocator.getRuleFromAsyncCache(ruleFlowID)
}

func (r *podReconciler) getOFPorts(members v1beta2.GroupMemberSet) sets.Set[int32] {
	ofPorts := sets.New[int32]()
	for _, m := range members {
		var entityName, ns string
		var ifaces []*interfacestore.InterfaceConfig
		if m.Pod != nil {
			entityName, ns = m.Pod.Name, m.Pod.Namespace
			ifaces = r.ifaceStore.GetContainerInterfacesByPod(entityName, ns)
		} else if m.ExternalEntity != nil {
			entityName, ns = m.ExternalEntity.Name, m.ExternalEntity.Namespace
			ifaces = r.ifaceStore.GetInterfacesByEntity(entityName, ns)
		}
		if len(ifaces) == 0 {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.InfoS("Can't find matching interface for entity, skipping", "entity", klog.KRef(ns, entityName))
			continue
		}
		for _, iface := range ifaces {
			klog.V(2).InfoS("Found OFPort for entity", "entity", klog.KRef(ns, entityName), "ofPort", iface.OFPort)
			ofPorts.Insert(iface.OFPort)
		}
	}
	return ofPorts
}

func (r *podReconciler) getIPs(members v1beta2.GroupMemberSet) sets.Set[string] {
	ips := sets.New[string]()
	for _, m := range members {
		var entityName, ns string
		var ifaces []*interfacestore.InterfaceConfig
		if m.Pod != nil {
			entityName, ns = m.Pod.Name, m.Pod.Namespace
			ifaces = r.ifaceStore.GetContainerInterfacesByPod(entityName, ns)
		} else if m.ExternalEntity != nil {
			entityName, ns = m.ExternalEntity.Name, m.ExternalEntity.Namespace
			ifaces = r.ifaceStore.GetInterfacesByEntity(entityName, ns)
		}
		if len(ifaces) == 0 {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.InfoS("Can't find matching interface for entity, skipping", "entity", klog.KRef(ns, entityName))
			continue
		}
		for _, iface := range ifaces {
			for _, ipAddr := range iface.IPs {
				if ipAddr != nil {
					klog.V(2).InfoS("Found IP for entity", "entity", klog.KRef(ns, entityName), "ip", ipAddr)
					ips.Insert(ipAddr.String())
				}
			}
		}
	}
	return ips
}

func (r *podReconciler) getSvcGroupIDs(members v1beta2.GroupMemberSet) sets.Set[int64] {
	var svcRefs []v1beta2.ServiceReference
	for _, m := range members {
		if m.Service != nil {
			svcRefs = append(svcRefs, v1beta2.ServiceReference{
				Name:      m.Service.Name,
				Namespace: m.Service.Namespace,
			})
		}
	}
	return r.svcRefsToGroupIDs(svcRefs)
}

// groupMembersByServices groups the provided groupMembers based on their services resolving result.
// A map of servicesHash to the grouped members and a map of servicesHash to the services resolving result will be returned.
func groupMembersByServices(services []v1beta2.Service, memberSet v1beta2.GroupMemberSet) (map[servicesKey]v1beta2.GroupMemberSet, map[servicesKey][]v1beta2.Service) {
	membersByServicesMap := map[servicesKey]v1beta2.GroupMemberSet{}
	servicesMap := map[servicesKey][]v1beta2.Service{}

	// If there is no named port in services, all members are in same group.
	namedPortServiceExist := false
	for _, svc := range services {
		if svc.Port != nil && svc.Port.Type == intstr.String {
			namedPortServiceExist = true
			break
		}
	}
	if !namedPortServiceExist {
		svcKey := normalizeServices(services)
		membersByServicesMap[svcKey] = memberSet
		servicesMap[svcKey] = services
		return membersByServicesMap, servicesMap
	}
	// Reuse the slice to avoid memory reallocations in the following loop. The
	// optimization makes difference as the number of group members might get up to tens
	// of thousands.
	resolvedServices := make([]v1beta2.Service, len(services))
	for memberKey, member := range memberSet {
		for i := range services {
			resolvedServices[i] = *resolveService(&services[i], member)
		}
		svcKey := normalizeServices(resolvedServices)
		if _, exists := membersByServicesMap[svcKey]; !exists {
			membersByServicesMap[svcKey] = v1beta2.NewGroupMemberSet()
			// Copy resolvedServices as it may be updated in next iteration.
			servicesMap[svcKey] = make([]v1beta2.Service, len(resolvedServices))
			copy(servicesMap[svcKey], resolvedServices)
		}
		membersByServicesMap[svcKey][memberKey] = member
	}
	return membersByServicesMap, servicesMap
}

func ofPortsToOFAddresses(ofPorts sets.Set[int32]) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(ofPorts))
	for _, ofPort := range sets.List(ofPorts) {
		addresses = append(addresses, openflow.NewOFPortAddress(ofPort))
	}
	return addresses
}

func (r *podReconciler) svcRefsToGroupIDs(svcRefs []v1beta2.ServiceReference) sets.Set[int64] {
	groupIDs := sets.New[int64]()
	for _, svcRef := range svcRefs {
		for _, groupCounter := range r.groupCounters {
			for _, groupID := range groupCounter.GetAllGroupIDs(k8s.NamespacedName(svcRef.Namespace, svcRef.Name)) {
				groupIDs.Insert(int64(groupID))
			}
		}
	}
	return groupIDs
}

func svcGroupIDsToOFAddresses(groupIDs sets.Set[int64]) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(groupIDs))
	for _, groupID := range sets.List(groupIDs) {
		addresses = append(addresses, openflow.NewServiceGroupIDAddress(binding.GroupIDType(groupID)))
	}
	return addresses
}

func groupMembersToOFAddresses(groupMemberSet v1beta2.GroupMemberSet) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(groupMemberSet))
	for _, member := range groupMemberSet {
		for _, ip := range member.IPs {
			addresses = append(addresses, openflow.NewIPAddress(net.IP(ip)))
		}
	}
	return addresses
}

func ipBlocksToOFAddresses(ipBlocks []v1beta2.IPBlock, ipv4Enabled, ipv6Enabled, ctMatch bool) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0)
	for _, b := range ipBlocks {
		blockCIDR := ip.IPNetToNetIPNet(&b.CIDR)
		if !isIPNetSupportedByAF(blockCIDR, ipv4Enabled, ipv6Enabled) {
			// This is part of normal operations: "allow all" in a policy is represented
			// by the combination of 2 CIDRs. One is "0.0.0.0/0" (any v4) and one is
			// "::/0" (any v6). In single-stack clusters, one of these CIDRs is
			// irrelevant and should be ignored.
			klog.V(2).InfoS("IPBlock is using unsupported address family, skipping it", "cidr", blockCIDR.String())
			continue
		}
		exceptIPNets := make([]*net.IPNet, 0, len(b.Except))
		for i := range b.Except {
			c := b.Except[i]
			except := ip.IPNetToNetIPNet(&c)
			exceptIPNets = append(exceptIPNets, except)
		}
		diffCIDRs, err := ip.DiffFromCIDRs(blockCIDR, exceptIPNets)
		if err != nil {
			klog.ErrorS(err, "Error when computing effective CIDRs by removing except IPNets from IPBlock")
			continue
		}
		for _, d := range diffCIDRs {
			if ctMatch {
				addresses = append(addresses, openflow.NewCTIPNetAddress(*d))
			} else {
				addresses = append(addresses, openflow.NewIPNetAddress(*d))
			}
		}
	}

	return addresses
}

func labelIDToOFAddresses(labelIDs []uint32) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(labelIDs))
	for _, labelID := range labelIDs {
		addresses = append(addresses, openflow.NewLabelIDAddress(labelID))
	}
	return addresses
}

func isIPNetSupportedByAF(ipnet *net.IPNet, ipv4Enabled, ipv6Enabled bool) bool {
	if (ipnet.IP.To4() != nil && ipv4Enabled) || (ipnet.IP.To4() == nil && ipv6Enabled) {
		return true
	}
	return false
}

func ipsToOFAddresses(ips sets.Set[string]) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	from := make([]types.Address, 0, len(ips))
	for ipAddr := range ips {
		from = append(from, openflow.NewIPAddress(net.ParseIP(ipAddr)))
	}
	return from
}

func filterUnresolvablePort(in []v1beta2.Service) []v1beta2.Service {
	// Empty or nil slice means allowing all ports in Kubernetes.
	// nil must be returned to meet ofClient's expectation for this behavior.
	if len(in) == 0 {
		return nil
	}
	// It makes sure `out` won't be nil, so that even if only named ports are
	// specified and none of them are resolvable, the rule just falls back to
	// allowing no port, instead of all ports.
	out := make([]v1beta2.Service, 0, len(in))
	for _, s := range in {
		if s.Port != nil {
			// All resolvable named port have been converted to intstr.Int,
			// ignore unresolvable ones.
			if s.Port.Type == intstr.String {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

// resolveService resolves the port name of the provided service to a port number for the provided groupMember.
// This function should eventually supersede resolveServiceForPod.
func resolveService(service *v1beta2.Service, member *v1beta2.GroupMember) *v1beta2.Service {
	// If port is not specified or is already a number, return it as is.
	if service.Port == nil || service.Port.Type == intstr.Int {
		return service
	}
	for _, port := range member.Ports {
		// For K8s NetworkPolicy and Antrea-native policies, the Service.Protocol field will never be nil since TCP
		// will be filled as default. However, for AdminNetworkPolicy and BaselineAdminNetworkPolicy, the Protocol
		// field will be nil for ports written as named ports. In that case, the member port will match as long
		// as the port name is matched.
		if port.Name == service.Port.StrVal && (service.Protocol == nil || port.Protocol == *service.Protocol) {
			resolvedPort := intstr.FromInt(int(port.Port))
			resolvedProtocol := service.Protocol
			if resolvedProtocol == nil {
				// Derive named port protocol from the container spec
				resolvedProtocol = &port.Protocol
			}
			return &v1beta2.Service{Protocol: resolvedProtocol, Port: &resolvedPort}
		}
	}
	klog.InfoS("Cannot resolve Service port for endpoints", "port", service.Port.StrVal, "member", member)
	// If not resolvable, return it as is.
	// The group members that cannot resolve it will be grouped together.
	return service
}

func isRuleAppliedToService(memberSet v1beta2.GroupMemberSet) bool {
	for _, member := range memberSet.Items() {
		if member.Service != nil {
			return true
		} else {
			return false
		}
	}
	return false
}

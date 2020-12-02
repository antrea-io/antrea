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
	"time"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/util/ip"
)

var (
	baselineTierPriority int32 = 253
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

// lastRealized is the struct cached by reconciler. It's used to track the
// actual state of rules we have enforced, so that we can know how to reconcile
// a rule when it's updated/removed.
// It includes the last version of CompletedRule the reconciler has realized
// and the related runtime information including the ofIDs, the Openflow ports
// or the IP addresses of the target Pods got from the InterfaceStore.
//
// Note that a policy rule can be split into multiple Openflow rules based on
// the named port resolving result. Pods that have same port numbers for the
// port names defined in the rule will share an Openflow rule. For example,
// if an ingress rule applies to 3 Pods like below:
//
// NetworkPolicy rule:
// spec:
//  ingress:
//  - from:
//    - namespaceSelector: {}
//    ports:
//    - port: http
//      protocol: TCP
//
// Pod A and Pod B:
// spec:
//   containers:
//   - ports:
//     - containerPort: 80
//       name: http
//       protocol: TCP
//
// Pod C:
// spec:
//   containers:
//   - ports:
//     - containerPort: 8080
//       name: http
//       protocol: TCP
//
// Then Pod A and B will share an Openflow rule as both of them resolve "http" to 80,
// while Pod C will have another Openflow rule as it resolves "http" to 8080.
// In the implementation, we group Pods by their resolved services value so Pod A and B
// can be mapped to same group.
type lastRealized struct {
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
	podOFPorts map[servicesKey]sets.Int32
	// The IP set we have realized for target Pods. Same as podOFPorts.
	// It's only used for egress rule as its "from" addresses.
	// It's same in all Openflow rules, because named port is only for
	// destination Pods.
	podIPs sets.String
}

func newLastRealized(rule *CompletedRule) *lastRealized {
	return &lastRealized{
		ofIDs:         map[servicesKey]uint32{},
		CompletedRule: rule,
		podOFPorts:    map[servicesKey]sets.Int32{},
		podIPs:        nil,
	}
}

// tablePriorityAssigner groups the priorityAssigner and mutex for a single OVS table
// that is reserved for installing Antrea policy rules.
type tablePriorityAssigner struct {
	assigner *priorityAssigner
	mutex    sync.RWMutex
}

// reconciler implements Reconciler.
// Note that although its Reconcile and Forget methods are thread-safe, it's
// assumed each rule can only be processed by a single client at any given
// time. Different rules can be processed in parallel.
type reconciler struct {
	// ofClient is the Openflow interface.
	ofClient openflow.Client

	// ifaceStore provides container interface OFPort and IP information.
	ifaceStore interfacestore.InterfaceStore

	// lastRealizeds caches the last realized rules.
	// It's a mapping from ruleID to *lastRealized.
	lastRealizeds sync.Map

	// idAllocator provides interfaces to allocateForRule and release uint32 id.
	idAllocator *idAllocator

	// priorityAssigners provides interfaces to manage OF priorities for each OVS table.
	priorityAssigners map[binding.TableIDType]*tablePriorityAssigner
	// ipv4Enabled tells if IPv4 is supported on this Node or not.
	ipv4Enabled bool
	// ipv6Enabled tells is IPv6 is supported on this Node or not.
	ipv6Enabled bool
}

// newReconciler returns a new *reconciler.
func newReconciler(ofClient openflow.Client, ifaceStore interfacestore.InterfaceStore, asyncRuleDeleteInterval time.Duration) *reconciler {
	priorityAssigners := map[binding.TableIDType]*tablePriorityAssigner{}
	for _, table := range openflow.GetAntreaPolicyBaselineTierTables() {
		priorityAssigners[table] = &tablePriorityAssigner{
			assigner: newPriorityAssigner(true),
		}
	}
	for _, table := range openflow.GetAntreaPolicyMultiTierTables() {
		priorityAssigners[table] = &tablePriorityAssigner{
			assigner: newPriorityAssigner(false),
		}
	}
	reconciler := &reconciler{
		ofClient:          ofClient,
		ifaceStore:        ifaceStore,
		lastRealizeds:     sync.Map{},
		idAllocator:       newIDAllocator(asyncRuleDeleteInterval),
		priorityAssigners: priorityAssigners,
	}
	// Check if ofClient is nil or not to be compatible with unit tests.
	if ofClient != nil {
		reconciler.ipv4Enabled = ofClient.IsIPv4Enabled()
		reconciler.ipv6Enabled = ofClient.IsIPv6Enabled()
	}
	return reconciler
}

// RunIDAllocatorWorker runs the worker that deletes the rules from the cache in
// idAllocator.
func (r *reconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {
	defer r.idAllocator.deleteQueue.ShutDown()
	go wait.Until(r.idAllocator.worker, time.Second, stopCh)
	<-stopCh
}

// Reconcile checks whether the provided rule have been enforced or not, and
// invoke the add or update method accordingly.
func (r *reconciler) Reconcile(rule *CompletedRule) error {
	klog.Infof("Reconciling rule %s of NetworkPolicy %s", rule.ID, rule.SourceRef.ToString())
	var err error
	var ofPriority *uint16

	value, exists := r.lastRealizeds.Load(rule.ID)
	ruleTable := r.getOFRuleTable(rule)
	priorityAssigner, _ := r.priorityAssigners[ruleTable]
	if rule.isAntreaNetworkPolicyRule() {
		// For CNP, only release priorityMutex after rule is installed on OVS. Otherwise,
		// priority re-assignments for flows that have already been assigned priorities but
		// not yet installed on OVS will be missed.
		priorityAssigner.mutex.Lock()
		defer priorityAssigner.mutex.Unlock()
	}
	ofPriority, err = r.getOFPriority(rule, ruleTable, priorityAssigner)
	if err != nil {
		return err
	}
	var ofRuleInstallErr error
	if !exists {
		ofRuleInstallErr = r.add(rule, ofPriority, ruleTable)
	} else {
		ofRuleInstallErr = r.update(value.(*lastRealized), rule, ofPriority, ruleTable)
	}
	if ofRuleInstallErr != nil && ofPriority != nil {
		priorityAssigner.assigner.Release(*ofPriority)
	}
	return ofRuleInstallErr
}

// getOFRuleTable retreives the OpenFlow table to install the CompletedRule.
// The decision is made based on whether the rule is created for a CNP/ANP, and
// the Tier of that NetworkPolicy.
func (r *reconciler) getOFRuleTable(rule *CompletedRule) binding.TableIDType {
	if !rule.isAntreaNetworkPolicyRule() {
		if rule.Direction == v1beta2.DirectionIn {
			return openflow.IngressRuleTable
		} else {
			return openflow.EgressRuleTable
		}
	}
	var ruleTables []binding.TableIDType
	if rule.Direction == v1beta2.DirectionIn {
		ruleTables = openflow.GetAntreaPolicyIngressTables()
	} else {
		ruleTables = openflow.GetAntreaPolicyEgressTables()
	}
	if *rule.TierPriority != baselineTierPriority {
		return ruleTables[0]
	}
	return ruleTables[1]
}

// getOFPriority retrieves the OFPriority for the input CompletedRule to be installed,
// and re-arranges installed priorities on OVS if necessary.
func (r *reconciler) getOFPriority(rule *CompletedRule, table binding.TableIDType, pa *tablePriorityAssigner) (*uint16, error) {
	if !rule.isAntreaNetworkPolicyRule() {
		klog.V(2).Infof("Assigning default priority for k8s NetworkPolicy.")
		return nil, nil
	}
	p := types.Priority{
		TierPriority:   *rule.TierPriority,
		PolicyPriority: *rule.PolicyPriority,
		RulePriority:   rule.Priority,
	}
	ofPriority, registered := pa.assigner.GetOFPriority(p)
	if !registered {
		allPrioritiesInPolicy := make([]types.Priority, rule.MaxPriority+1)
		for i := int32(0); i <= rule.MaxPriority; i++ {
			allPrioritiesInPolicy[i] = types.Priority{
				TierPriority:   *rule.TierPriority,
				PolicyPriority: *rule.PolicyPriority,
				RulePriority:   i,
			}
		}
		priorityUpdates, revertFunc, err := pa.assigner.RegisterPriorities(allPrioritiesInPolicy)
		if err != nil {
			return nil, err
		}
		// Re-assign installed priorities on OVS
		if len(priorityUpdates) > 0 {
			err := r.ofClient.ReassignFlowPriorities(priorityUpdates, table)
			if err != nil {
				revertFunc()
				return nil, err
			}
		}
		ofPriority, _ = pa.assigner.GetOFPriority(p)
	}
	klog.V(2).Infof("Assigning OFPriority %v for rule %v", ofPriority, rule.ID)
	return &ofPriority, nil
}

// BatchReconcile reconciles the desired state of the provided CompletedRules
// with the actual state of Openflow entries in batch. It should only be invoked
// if all rules are newly added without last realized status.
func (r *reconciler) BatchReconcile(rules []*CompletedRule) error {
	var rulesToInstall []*CompletedRule
	var priorities []*uint16
	prioritiesByTable := map[binding.TableIDType][]*uint16{}
	for _, rule := range rules {
		if _, exists := r.lastRealizeds.Load(rule.ID); exists {
			klog.Errorf("rule %s already realized during the initialization phase", rule.ID)
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
		klog.V(2).Infof("Adding rule %s of NetworkPolicy %s to be reconciled in batch", rule.ID, rule.SourceRef.ToString())
		ofPriority, _ := r.getOFPriority(rule, ruleTable, priorityAssigner)
		priorities = append(priorities, ofPriority)
		if ofPriority != nil {
			prioritiesByTable[ruleTable] = append(prioritiesByTable[ruleTable], ofPriority)
		}
	}
	ofRuleInstallErr := r.batchAdd(rulesToInstall, priorities)
	if ofRuleInstallErr != nil {
		for tableID, ofPriorities := range prioritiesByTable {
			pa := r.priorityAssigners[tableID]
			for _, ofPriority := range ofPriorities {
				pa.assigner.Release(*ofPriority)
			}
		}
	}
	return ofRuleInstallErr
}

// registerOFPriorities constructs a Priority type for each CompletedRule in the input list,
// and registers those Priorities with appropriate tablePriorityAssigner based on Tier.
func (r *reconciler) registerOFPriorities(rules []*CompletedRule) error {
	prioritiesToRegister := map[binding.TableIDType][]types.Priority{}
	for _, rule := range rules {
		if rule.isAntreaNetworkPolicyRule() {
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
		if _, _, err := r.priorityAssigners[tableID].assigner.RegisterPriorities(priorities); err != nil {
			return err
		}
	}
	return nil
}

// add converts CompletedRule to PolicyRule(s) and invokes installOFRule to install them.
func (r *reconciler) add(rule *CompletedRule, ofPriority *uint16, table binding.TableIDType) error {
	klog.V(2).Infof("Adding new rule %v", rule)
	ofRuleByServicesMap, lastRealized := r.computeOFRulesForAdd(rule, ofPriority, table)
	for svcKey, ofRule := range ofRuleByServicesMap {
		// Each pod group gets an Openflow ID.
		err := r.idAllocator.allocateForRule(ofRule)
		if err != nil {
			return fmt.Errorf("error allocating Openflow ID")
		}
		if err = r.installOFRule(ofRule); err != nil {
			return err
		}
		// Record ofID only if its Openflow is installed successfully.
		lastRealized.ofIDs[svcKey] = ofRule.FlowID
	}
	return nil
}

func (r *reconciler) computeOFRulesForAdd(rule *CompletedRule, ofPriority *uint16, table binding.TableIDType) (
	map[servicesKey]*types.PolicyRule, *lastRealized) {
	lastRealized := newLastRealized(rule)
	// TODO: Handle the case that the following processing fails or partially succeeds.
	r.lastRealizeds.Store(rule.ID, lastRealized)

	ofRuleByServicesMap := map[servicesKey]*types.PolicyRule{}

	if rule.Direction == v1beta2.DirectionIn {
		// Addresses got from source GroupMembers' IPs.
		from1 := groupMembersToOFAddresses(rule.FromAddresses)
		// Get addresses that in From IPBlock but not in Except IPBlocks.
		from2 := ipBlocksToOFAddresses(rule.From.IPBlocks, r.ipv4Enabled, r.ipv6Enabled)

		podsByServicesMap, servicesMap := groupMembersByServices(rule.Services, rule.TargetMembers)

		for svcKey, pods := range podsByServicesMap {
			ofPorts := r.getPodOFPorts(pods)
			lastRealized.podOFPorts[svcKey] = ofPorts
			ofRuleByServicesMap[svcKey] = &types.PolicyRule{
				Direction:     v1beta2.DirectionIn,
				From:          append(from1, from2...),
				To:            ofPortsToOFAddresses(ofPorts),
				Service:       filterUnresolvablePort(servicesMap[svcKey]),
				Action:        rule.Action,
				Priority:      ofPriority,
				TableID:       table,
				PolicyRef:     rule.SourceRef,
				EnableLogging: rule.EnableLogging,
			}
		}
	} else {
		ips := r.getPodIPs(rule.TargetMembers)
		lastRealized.podIPs = ips
		from := ipsToOFAddresses(ips)
		memberByServicesMap, servicesMap := groupMembersByServices(rule.Services, rule.ToAddresses)
		for svcKey, members := range memberByServicesMap {
			ofRuleByServicesMap[svcKey] = &types.PolicyRule{
				Direction:     v1beta2.DirectionOut,
				From:          from,
				To:            groupMembersToOFAddresses(members),
				Service:       filterUnresolvablePort(servicesMap[svcKey]),
				Action:        rule.Action,
				Priority:      ofPriority,
				TableID:       table,
				PolicyRef:     rule.SourceRef,
				EnableLogging: rule.EnableLogging,
			}
		}

		// If there are no "ToAddresses", the above process doesn't create any PolicyRule.
		// We must ensure there is at least one PolicyRule, otherwise the Pods won't be
		// isolated, so we create a PolicyRule with the original services if it doesn't exist.
		// If there are IPBlocks or Pods that cannot resolve any named port, they will share
		// this PolicyRule. Antrea policies do not need this default isolation.
		if !rule.isAntreaNetworkPolicyRule() || len(rule.To.IPBlocks) > 0 {
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
					Priority:      nil,
					TableID:       table,
					PolicyRef:     rule.SourceRef,
					EnableLogging: rule.EnableLogging,
				}
				ofRuleByServicesMap[svcKey] = ofRule
			}
			if len(rule.To.IPBlocks) > 0 {
				// Diff Addresses between To and Except of IPBlocks
				to := ipBlocksToOFAddresses(rule.To.IPBlocks, r.ipv4Enabled, r.ipv6Enabled)
				ofRule.To = append(ofRule.To, to...)
			}
		}
	}
	return ofRuleByServicesMap, lastRealized
}

// batchAdd converts CompletedRules to PolicyRules and invokes BatchInstallPolicyRuleFlows to install them.
func (r *reconciler) batchAdd(rules []*CompletedRule, ofPriorities []*uint16) error {
	lastRealizeds := make([]*lastRealized, len(rules))
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
func (r *reconciler) update(lastRealized *lastRealized, newRule *CompletedRule, ofPriority *uint16, table binding.TableIDType) error {
	klog.V(2).Infof("Updating existing rule %v", newRule)
	// staleOFIDs tracks servicesKey that are no long needed.
	// Firstly fill it with the last realized ofIDs.
	staleOFIDs := make(map[servicesKey]uint32, len(lastRealized.ofIDs))
	for svcKey, ofID := range lastRealized.ofIDs {
		staleOFIDs[svcKey] = ofID
	}

	// As rule identifier is calculated from the rule's content, the update can
	// only happen to Group members.
	if newRule.Direction == v1beta2.DirectionIn {
		from1 := groupMembersToOFAddresses(newRule.FromAddresses)
		from2 := ipBlocksToOFAddresses(newRule.From.IPBlocks, r.ipv4Enabled, r.ipv6Enabled)
		addedFrom := groupMembersToOFAddresses(newRule.FromAddresses.Difference(lastRealized.FromAddresses))
		deletedFrom := groupMembersToOFAddresses(lastRealized.FromAddresses.Difference(newRule.FromAddresses))

		podsByServicesMap, servicesMap := groupMembersByServices(newRule.Services, newRule.TargetMembers)
		for svcKey, pods := range podsByServicesMap {
			newOFPorts := r.getPodOFPorts(pods)
			ofID, exists := lastRealized.ofIDs[svcKey]
			// Install a new Openflow rule if this group doesn't exist, otherwise do incremental update.
			if !exists {
				ofRule := &types.PolicyRule{
					Direction:     v1beta2.DirectionIn,
					From:          append(from1, from2...),
					To:            ofPortsToOFAddresses(newOFPorts),
					Service:       filterUnresolvablePort(servicesMap[svcKey]),
					Action:        newRule.Action,
					Priority:      ofPriority,
					FlowID:        ofID,
					TableID:       table,
					PolicyRef:     newRule.SourceRef,
					EnableLogging: newRule.EnableLogging,
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
				addedTo := ofPortsToOFAddresses(newOFPorts.Difference(lastRealized.podOFPorts[svcKey]))
				deletedTo := ofPortsToOFAddresses(lastRealized.podOFPorts[svcKey].Difference(newOFPorts))
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo, ofPriority); err != nil {
					return err
				}
				// Delete valid servicesKey from staleOFIDs.
				delete(staleOFIDs, svcKey)
			}
			lastRealized.podOFPorts[svcKey] = newOFPorts
		}
	} else {
		newIPs := r.getPodIPs(newRule.TargetMembers)
		from := ipsToOFAddresses(newIPs)
		addedFrom := ipsToOFAddresses(newIPs.Difference(lastRealized.podIPs))
		deletedFrom := ipsToOFAddresses(lastRealized.podIPs.Difference(newIPs))

		memberByServicesMap, servicesMap := groupMembersByServices(newRule.Services, newRule.ToAddresses)
		// Same as the process in `add`, we must ensure the group for the original services is present
		// in memberByServicesMap, so that this group won't be removed and its "From" will be updated.
		svcKey := normalizeServices(newRule.Services)
		if _, exists := memberByServicesMap[svcKey]; !exists {
			memberByServicesMap[svcKey] = v1beta2.NewGroupMemberSet()
			servicesMap[svcKey] = newRule.Services
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
					Action:        newRule.Action,
					Priority:      ofPriority,
					FlowID:        ofID,
					TableID:       table,
					PolicyRef:     newRule.SourceRef,
					EnableLogging: newRule.EnableLogging,
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
				addedTo := groupMembersToOFAddresses(members.Difference(prevMembersByServicesMap[svcKey]))
				deletedTo := groupMembersToOFAddresses(prevMembersByServicesMap[svcKey].Difference(members))
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo, ofPriority); err != nil {
					return err
				}
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

func (r *reconciler) installOFRule(ofRule *types.PolicyRule) error {
	klog.V(2).Infof("Installing ofRule %d (Direction: %v, From: %d, To: %d, Service: %d)",
		ofRule.FlowID, ofRule.Direction, len(ofRule.From), len(ofRule.To), len(ofRule.Service))
	if err := r.ofClient.InstallPolicyRuleFlows(ofRule); err != nil {
		r.idAllocator.forgetRule(ofRule.FlowID)
		return fmt.Errorf("error installing ofRule %v: %v", ofRule.FlowID, err)
	}
	return nil
}

func (r *reconciler) updateOFRule(ofID uint32, addedFrom []types.Address, addedTo []types.Address, deletedFrom []types.Address, deletedTo []types.Address, priority *uint16) error {
	klog.V(2).Infof("Updating ofRule %d (addedFrom: %d, addedTo: %d, deleteFrom: %d, deletedTo: %d)",
		ofID, len(addedFrom), len(addedTo), len(deletedFrom), len(deletedTo))
	// TODO: This might be unnecessarily complex and hard for error handling, consider revising the Openflow interfaces.
	if len(addedFrom) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.SrcAddress, addedFrom, priority); err != nil {
			return fmt.Errorf("error adding policy rule source addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(addedTo) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.DstAddress, addedTo, priority); err != nil {
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

func (r *reconciler) uninstallOFRule(ofID uint32, table binding.TableIDType) error {
	klog.V(2).Infof("Uninstalling ofRule %d", ofID)
	stalePriorities, err := r.ofClient.UninstallPolicyRuleFlows(ofID)
	if err != nil {
		return fmt.Errorf("error uninstalling ofRule %v: %v", ofID, err)
	}
	if len(stalePriorities) > 0 {
		for _, p := range stalePriorities {
			klog.V(2).Infof("Releasing stale priority %v", p)
			priorityNum, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				// Cannot parse the priority str. Theoretically this should never happen.
				return err
			}
			// If there are stalePriorities, priorityAssigners[table] must not be nil.
			priorityAssigner, _ := r.priorityAssigners[table]
			priorityAssigner.assigner.Release(uint16(priorityNum))
		}
	}
	r.idAllocator.forgetRule(ofID)
	return nil
}

// Forget invokes UninstallPolicyRuleFlows to uninstall Openflow entries
// associated with the provided ruleID if it was enforced before.
func (r *reconciler) Forget(ruleID string) error {
	klog.Infof("Forgetting rule %v", ruleID)

	value, exists := r.lastRealizeds.Load(ruleID)
	if !exists {
		// No-op if the rule was not realized before.
		return nil
	}

	lastRealized := value.(*lastRealized)
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

	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *reconciler) GetRuleByFlowID(ruleFlowID uint32) (*types.PolicyRule, bool, error) {
	return r.idAllocator.getRuleFromAsyncCache(ruleFlowID)
}

func (r *reconciler) getPodOFPorts(members v1beta2.GroupMemberSet) sets.Int32 {
	ofPorts := sets.NewInt32()
	for _, m := range members {
		if m.Pod == nil {
			continue
		}
		ifaces := r.ifaceStore.GetContainerInterfacesByPod(m.Pod.Name, m.Pod.Namespace)
		if len(ifaces) == 0 {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.Infof("Can't find interface for Pod %s/%s, skipping", m.Pod.Namespace, m.Pod.Name)
			continue
		}
		for _, iface := range ifaces {
			klog.V(2).Infof("Got OFPort %v for Pod %s/%s", iface.OFPort, m.Pod.Namespace, m.Pod.Name)
			ofPorts.Insert(iface.OFPort)
		}
	}
	return ofPorts
}

func (r *reconciler) getPodIPs(members v1beta2.GroupMemberSet) sets.String {
	ips := sets.NewString()
	for _, m := range members {
		if m.Pod == nil {
			continue
		}
		ifaces := r.ifaceStore.GetContainerInterfacesByPod(m.Pod.Name, m.Pod.Namespace)
		if len(ifaces) == 0 {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.Infof("Can't find interface for Pod %s/%s, skipping", m.Pod.Namespace, m.Pod.Name)
			continue
		}
		for _, iface := range ifaces {
			for _, ipAddr := range iface.IPs {
				if ipAddr != nil {
					klog.V(2).Infof("Got IP %v for Pod %s/%s", iface.IPs, m.Pod.Namespace, m.Pod.Name)
					ips.Insert(ipAddr.String())
				}
			}
		}
	}
	return ips
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

func ofPortsToOFAddresses(ofPorts sets.Int32) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(ofPorts))
	for _, ofPort := range ofPorts.List() {
		addresses = append(addresses, openflow.NewOFPortAddress(ofPort))
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

func ipBlocksToOFAddresses(ipBlocks []v1beta2.IPBlock, ipv4Enabled, ipv6Enabled bool) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0)
	for _, b := range ipBlocks {
		blockCIDR := ip.IPNetToNetIPNet(&b.CIDR)
		if !isIPNetSupportedByAF(blockCIDR, ipv4Enabled, ipv6Enabled) {
			klog.Infof("IPBlock %s is using unsupported address family, skip it", blockCIDR.String())
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
			klog.Errorf("Error when determining diffCIDRs: %v", err)
			continue
		}
		for _, d := range diffCIDRs {
			addresses = append(addresses, openflow.NewIPNetAddress(*d))
		}
	}

	return addresses
}

func isIPNetSupportedByAF(ipnet *net.IPNet, ipv4Enabled, ipv6Enabled bool) bool {
	if (ipnet.IP.To4() != nil && ipv4Enabled) || (ipnet.IP.To4() == nil && ipv6Enabled) {
		return true
	}
	return false
}

func ipsToOFAddresses(ips sets.String) []types.Address {
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
		if port.Name == service.Port.StrVal && port.Protocol == *service.Protocol {
			resolvedPort := intstr.FromInt(int(port.Port))
			return &v1beta2.Service{Protocol: service.Protocol, Port: &resolvedPort}
		}
	}
	klog.Warningf("Can not resolve port %s for endpoints %v", service.Port.StrVal, member)
	// If not resolvable, return it as is.
	// The group members that cannot resolve it will be grouped together.
	return service
}

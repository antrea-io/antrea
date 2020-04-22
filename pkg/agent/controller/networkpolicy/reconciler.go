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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

var (
	printer = spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
)

// Reconciler is an interface that knows how to reconcile the desired state of
// CompletedRule with the actual state of Openflow entries.
type Reconciler interface {
	// Reconcile reconciles the desired state of the provided CompletedRule
	// with the actual state of Openflow entries.
	Reconcile(rule *CompletedRule) error

	// Forget cleanups the actual state of Openflow entries of the specified ruleID.
	Forget(ruleID string) error
}

// servicesHash is used to uniquely identify Services.
type servicesHash string

// hashServices uses the spew library which follows pointers and prints
// actual values of the nested objects to ensure the hash does not change when
// a pointer changes.
func hashServices(services []v1beta1.Service) servicesHash {
	hasher := md5.New()
	printer.Fprintf(hasher, "%#v", services)
	return servicesHash(hex.EncodeToString(hasher.Sum(nil)[0:]))
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
	// It's a map of servicesHash to Openflow rule ID.
	ofIDs map[servicesHash]uint32
	// The desired state of a policy rule.
	*CompletedRule
	// The OFPort set we have realized for target Pods. We need to record them
	// because this info will be removed from InterfaceStore after CNI DEL, we
	// can't know which OFPort to delete when deleting a Pod from the rule. So
	// we compare the last realized OFPorts and the new desired one to identify
	// difference, which could also cover the stale OFPorts produced by the case
	// that Kubelet calls CNI ADD for a Pod more than once due to non CNI issues.
	// It's only used for ingress rule as its "to" addresses.
	// It's grouped by services hash, mapping to multiple Openflow rules.
	podOFPorts map[servicesHash]sets.Int32
	// The IP set we have realized for target Pods. Same as podOFPorts.
	// It's only used for egress rule as its "from" addresses.
	// It's same in all Openflow rules, because named port is only for
	// destination Pods.
	podIPs sets.String
}

func newLastRealized(rule *CompletedRule) *lastRealized {
	return &lastRealized{
		ofIDs:         map[servicesHash]uint32{},
		CompletedRule: rule,
		podOFPorts:    map[servicesHash]sets.Int32{},
		podIPs:        nil,
	}
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

	// idAllocator provides interfaces to allocate and release uint32 id.
	idAllocator *idAllocator
}

// newReconciler returns a new *reconciler.
func newReconciler(ofClient openflow.Client, ifaceStore interfacestore.InterfaceStore) *reconciler {
	reconciler := &reconciler{
		ofClient:      ofClient,
		ifaceStore:    ifaceStore,
		lastRealizeds: sync.Map{},
		idAllocator:   newIDAllocator(),
	}
	return reconciler
}

// Reconcile checks whether the provided rule have been enforced or not, and
// invoke the add or update method accordingly.
func (r *reconciler) Reconcile(rule *CompletedRule) error {
	klog.Infof("Reconciling rule %s of NetworkPolicy %s/%s", rule.ID, rule.PolicyNamespace, rule.PolicyName)

	value, exists := r.lastRealizeds.Load(rule.ID)
	if !exists {
		return r.add(rule)
	}
	return r.update(value.(*lastRealized), rule)
}

// add converts CompletedRule to PolicyRule(s) and invokes installOFRule to install them.
func (r *reconciler) add(rule *CompletedRule) error {
	klog.V(2).Infof("Adding new rule %v", rule)
	lastRealized := newLastRealized(rule)
	// TODO: Handle the case that the following processing fails or partially succeeds.
	r.lastRealizeds.Store(rule.ID, lastRealized)

	ofRuleByServicesMap := map[servicesHash]*types.PolicyRule{}
	if rule.Direction == v1beta1.DirectionIn {
		// Addresses got from source Pod IPs.
		from1 := podsToOFAddresses(rule.FromAddresses)
		// Addresses and ExceptAddresses got from IPBlocks.
		from2, exceptFrom := ipBlocksToOFAddresses(rule.From.IPBlocks)

		podsByServicesMap, servicesMap := groupPodsByServices(rule.Services, rule.Pods)
		for svcHash, pods := range podsByServicesMap {
			ofPorts := r.getPodOFPorts(pods)
			lastRealized.podOFPorts[svcHash] = ofPorts
			ofRuleByServicesMap[svcHash] = &types.PolicyRule{
				Direction:  v1beta1.DirectionIn,
				From:       append(from1, from2...),
				ExceptFrom: exceptFrom,
				To:         ofPortsToOFAddresses(ofPorts),
				Service:    filterUnresolvablePort(servicesMap[svcHash]),
			}
		}
	} else {
		ips := r.getPodIPs(rule.Pods)
		lastRealized.podIPs = ips
		from := ipsToOFAddresses(ips)

		podsByServicesMap, servicesMap := groupPodsByServices(rule.Services, rule.ToAddresses)
		for svcHash, pods := range podsByServicesMap {
			ofRuleByServicesMap[svcHash] = &types.PolicyRule{
				Direction: v1beta1.DirectionOut,
				From:      from,
				To:        podsToOFAddresses(pods),
				Service:   filterUnresolvablePort(servicesMap[svcHash]),
			}
		}

		// If there are no "ToAddresses", the above process doesn't create any PolicyRule.
		// We must ensure there is at least one PolicyRule, otherwise the Pods won't be
		// isolated, so we create a PolicyRule with the original services if it doesn't exist.
		// If there are IPBlocks or Pods that cannot resolve any named port, they will share
		// this PolicyRule.
		svcHash := hashServices(rule.Services)
		ofRule, exists := ofRuleByServicesMap[svcHash]
		// Create a new Openflow rule if the group doesn't exist.
		if !exists {
			ofRule = &types.PolicyRule{
				Direction: v1beta1.DirectionOut,
				From:      from,
				To:        []types.Address{},
				Service:   filterUnresolvablePort(rule.Services),
			}
			ofRuleByServicesMap[svcHash] = ofRule
		}
		if len(rule.To.IPBlocks) > 0 {
			to, exceptTo := ipBlocksToOFAddresses(rule.To.IPBlocks)
			ofRule.To = append(ofRule.To, to...)
			ofRule.ExceptTo = append(ofRule.ExceptTo, exceptTo...)
		}
	}

	for svcHash, ofRule := range ofRuleByServicesMap {
		npName := lastRealized.CompletedRule.PolicyName
		npNamespace := lastRealized.CompletedRule.PolicyNamespace
		ofID, err := r.installOFRule(ofRule, npName, npNamespace)
		if err != nil {
			return err
		}
		// Record ofID only if its Openflow is installed successfully.
		lastRealized.ofIDs[svcHash] = ofID
	}

	return nil
}

// update calculates the difference of Addresses between oldRule and newRule,
// and invokes Openflow client's methods to reconcile them.
func (r *reconciler) update(lastRealized *lastRealized, newRule *CompletedRule) error {
	klog.V(2).Infof("Updating existing rule %v", newRule)
	// staleOFIDs tracks servicesHash that are no long needed.
	// Firstly fill it with the last realized ofIDs.
	staleOFIDs := make(map[servicesHash]uint32, len(lastRealized.ofIDs))
	for svcHash, ofID := range lastRealized.ofIDs {
		staleOFIDs[svcHash] = ofID
	}

	// As rule identifier is calculated from the rule's content, the update can
	// only happen to Group members.
	if newRule.Direction == v1beta1.DirectionIn {
		from1 := podsToOFAddresses(newRule.FromAddresses)
		from2, exceptFrom := ipBlocksToOFAddresses(newRule.From.IPBlocks)
		addedFrom := podsToOFAddresses(newRule.FromAddresses.Difference(lastRealized.FromAddresses))
		deletedFrom := podsToOFAddresses(lastRealized.FromAddresses.Difference(newRule.FromAddresses))

		podsByServicesMap, servicesMap := groupPodsByServices(newRule.Services, newRule.Pods)
		for svcHash, pods := range podsByServicesMap {
			newOFPorts := r.getPodOFPorts(pods)
			ofID, exists := lastRealized.ofIDs[svcHash]
			// Install a new Openflow rule if this group doesn't exist, otherwise do incremental update.
			if !exists {
				ofRule := &types.PolicyRule{
					Direction:  v1beta1.DirectionIn,
					From:       append(from1, from2...),
					ExceptFrom: exceptFrom,
					To:         ofPortsToOFAddresses(newOFPorts),
					Service:    filterUnresolvablePort(servicesMap[svcHash]),
				}
				ofID, err := r.installOFRule(ofRule, newRule.PolicyName, newRule.PolicyNamespace)
				if err != nil {
					return err
				}
				lastRealized.ofIDs[svcHash] = ofID
			} else {
				addedTo := ofPortsToOFAddresses(newOFPorts.Difference(lastRealized.podOFPorts[svcHash]))
				deletedTo := ofPortsToOFAddresses(lastRealized.podOFPorts[svcHash].Difference(newOFPorts))
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo); err != nil {
					return err
				}
				// Delete valid servicesHash from staleOFIDs.
				delete(staleOFIDs, svcHash)
			}
			lastRealized.podOFPorts[svcHash] = newOFPorts
		}
	} else {
		newIPs := r.getPodIPs(newRule.Pods)
		from := ipsToOFAddresses(newIPs)
		addedFrom := ipsToOFAddresses(newIPs.Difference(lastRealized.podIPs))
		deletedFrom := ipsToOFAddresses(lastRealized.podIPs.Difference(newIPs))

		podsByServicesMap, servicesMap := groupPodsByServices(newRule.Services, newRule.ToAddresses)
		// Same as the process in `add`, we must ensure the group for the original services is present
		// in podsByServicesMap, so that this group won't be removed and its "From" will be updated.
		svcHash := hashServices(newRule.Services)
		if _, exists := podsByServicesMap[svcHash]; !exists {
			podsByServicesMap[svcHash] = v1beta1.NewGroupMemberPodSet()
			servicesMap[svcHash] = newRule.Services
		}
		prevPodsByServicesMap, _ := groupPodsByServices(lastRealized.Services, lastRealized.ToAddresses)
		for svcHash, pods := range podsByServicesMap {
			ofID, exists := lastRealized.ofIDs[svcHash]
			if !exists {
				ofRule := &types.PolicyRule{
					Direction: v1beta1.DirectionOut,
					From:      from,
					To:        podsToOFAddresses(pods),
					Service:   filterUnresolvablePort(servicesMap[svcHash]),
				}
				ofID, err := r.installOFRule(ofRule, newRule.PolicyName, newRule.PolicyNamespace)
				if err != nil {
					return err
				}
				lastRealized.ofIDs[svcHash] = ofID
			} else {
				addedTo := podsToOFAddresses(pods.Difference(prevPodsByServicesMap[svcHash]))
				deletedTo := podsToOFAddresses(prevPodsByServicesMap[svcHash].Difference(pods))
				if err := r.updateOFRule(ofID, addedFrom, addedTo, deletedFrom, deletedTo); err != nil {
					return err
				}
				// Delete valid servicesHash from staleOFIDs.
				delete(staleOFIDs, svcHash)
			}
		}
		lastRealized.podIPs = newIPs
	}
	// Remove stale Openflow rules.
	for svcHash, ofID := range staleOFIDs {
		if err := r.uninstallOFRule(ofID); err != nil {
			return err
		}
		delete(lastRealized.ofIDs, svcHash)
	}
	lastRealized.CompletedRule = newRule
	return nil
}

func (r *reconciler) installOFRule(ofRule *types.PolicyRule, npName, npNamespace string) (uint32, error) {
	// Each pod group gets an Openflow ID.
	ofID, err := r.idAllocator.allocate()
	if err != nil {
		return 0, fmt.Errorf("error allocating Openflow ID")
	}
	klog.V(2).Infof("Installing ofRule %d (Direction: %v, From: %d, ExceptFrom: %d, To: %d, ExceptTo: %d, Service: %d)",
		ofID, ofRule.Direction, len(ofRule.From), len(ofRule.ExceptFrom), len(ofRule.To), len(ofRule.ExceptTo), len(ofRule.Service))
	if err := r.ofClient.InstallPolicyRuleFlows(ofID, ofRule, npName, npNamespace); err != nil {
		r.idAllocator.release(ofID)
		return 0, fmt.Errorf("error installing ofRule %v: %v", ofID, err)
	}
	return ofID, nil
}

func (r *reconciler) updateOFRule(ofID uint32, addedFrom []types.Address, addedTo []types.Address, deletedFrom []types.Address, deletedTo []types.Address) error {
	klog.V(2).Infof("Updating ofRule %d (addedFrom: %d, addedTo: %d, deleteFrom: %d, deletedTo: %d)",
		ofID, len(addedFrom), len(addedTo), len(deletedFrom), len(deletedTo))
	// TODO: This might be unnecessarily complex and hard for error handling, consider revising the Openflow interfaces.
	if len(addedFrom) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.SrcAddress, addedFrom); err != nil {
			return fmt.Errorf("error adding policy rule source addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(addedTo) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(ofID, types.DstAddress, addedTo); err != nil {
			return fmt.Errorf("error adding policy rule destination addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(deletedFrom) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(ofID, types.SrcAddress, deletedFrom); err != nil {
			return fmt.Errorf("error deleting policy rule source addresses for ofRule %v: %v", ofID, err)
		}
	}
	if len(deletedTo) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(ofID, types.DstAddress, deletedTo); err != nil {
			return fmt.Errorf("error deleting policy rule destination addresses for ofRule %v: %v", ofID, err)
		}
	}
	return nil
}

func (r *reconciler) uninstallOFRule(ofID uint32) error {
	klog.V(2).Infof("Uninstalling ofRule %d", ofID)
	if err := r.ofClient.UninstallPolicyRuleFlows(ofID); err != nil {
		return fmt.Errorf("error uninstalling ofRule %v: %v", ofID, err)
	}
	if err := r.idAllocator.release(ofID); err != nil {
		// This should never happen. If it does, it is a programming error.
		klog.Errorf("Error releasing Openflow ID for ofRule %v: %v", ofID, err)
	}
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
	for svcHash, ofID := range lastRealized.ofIDs {
		if err := r.uninstallOFRule(ofID); err != nil {
			return err
		}
		delete(lastRealized.ofIDs, svcHash)
	}

	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *reconciler) getPodOFPorts(pods v1beta1.GroupMemberPodSet) sets.Int32 {
	ofPorts := sets.NewInt32()
	for _, pod := range pods {
		iface, found := r.ifaceStore.GetContainerInterface(pod.Pod.Name, pod.Pod.Namespace)
		if !found {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.Infof("Can't find interface for Pod %s/%s, skipping", pod.Pod.Namespace, pod.Pod.Name)
			continue
		}
		klog.V(2).Infof("Got OFPort %v for Pod %s/%s", iface.OFPort, pod.Pod.Namespace, pod.Pod.Name)
		ofPorts.Insert(iface.OFPort)
	}
	return ofPorts
}

func (r *reconciler) getPodIPs(pods v1beta1.GroupMemberPodSet) sets.String {
	ips := sets.NewString()
	for _, pod := range pods {
		iface, found := r.ifaceStore.GetContainerInterface(pod.Pod.Name, pod.Pod.Namespace)
		if !found {
			// This might be because the container has been deleted during realization or hasn't been set up yet.
			klog.Infof("Can't find interface for Pod %s/%s, skipping", pod.Pod.Namespace, pod.Pod.Name)
			continue
		}
		klog.V(2).Infof("Got IP %v for Pod %s/%s", iface.IP, pod.Pod.Namespace, pod.Pod.Name)
		ips.Insert(iface.IP.String())
	}
	return ips
}

// groupPodsByServices groups the provided Pods based on their services resolving result.
// A map of servicesHash to the Pod groups and a map of servicesHash to the services resolving result will be returned.
func groupPodsByServices(services []v1beta1.Service, pods v1beta1.GroupMemberPodSet) (map[servicesHash]v1beta1.GroupMemberPodSet, map[servicesHash][]v1beta1.Service) {
	podsByServicesMap := map[servicesHash]v1beta1.GroupMemberPodSet{}
	servicesMap := map[servicesHash][]v1beta1.Service{}
	for _, pod := range pods {
		var resolvedServices []v1beta1.Service
		for _, service := range services {
			resolvedService := resolveService(&service, pod)
			resolvedServices = append(resolvedServices, *resolvedService)
		}
		svcHash := hashServices(resolvedServices)
		if _, exists := podsByServicesMap[svcHash]; !exists {
			podsByServicesMap[svcHash] = v1beta1.NewGroupMemberPodSet()
			servicesMap[svcHash] = resolvedServices
		}
		podsByServicesMap[svcHash].Insert(pod)
	}
	return podsByServicesMap, servicesMap
}

func ofPortsToOFAddresses(ofPorts sets.Int32) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(ofPorts))
	for _, ofPort := range ofPorts.List() {
		addresses = append(addresses, openflow.NewOFPortAddress(ofPort))
	}
	return addresses
}

func podsToOFAddresses(podSet v1beta1.GroupMemberPodSet) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(podSet))
	for _, p := range podSet {
		addresses = append(addresses, openflow.NewIPAddress(net.IP(p.IP)))
	}
	return addresses
}

func ipBlocksToOFAddresses(ipBlocks []v1beta1.IPBlock) ([]types.Address, []types.Address) {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	addresses := make([]types.Address, 0, len(ipBlocks))
	var exceptAddresses []types.Address
	for _, b := range ipBlocks {
		addresses = append(addresses, ipNetToOFAddress(b.CIDR))
		for _, e := range b.Except {
			exceptAddresses = append(exceptAddresses, ipNetToOFAddress(e))
		}
	}
	return addresses, exceptAddresses
}

func ipNetToOFAddress(in v1beta1.IPNet) *openflow.IPNetAddress {
	ipNet := net.IPNet{
		IP:   net.IP(in.IP),
		Mask: net.CIDRMask(int(in.PrefixLength), 32),
	}
	return openflow.NewIPNetAddress(ipNet)
}

func ipsToOFAddresses(ips sets.String) []types.Address {
	// Must not return nil as it means not restricted by addresses in Openflow implementation.
	from := make([]types.Address, 0, len(ips))
	for ip := range ips {
		from = append(from, openflow.NewIPAddress(net.ParseIP((ip))))
	}
	return from
}

func filterUnresolvablePort(in []v1beta1.Service) []v1beta1.Service {
	// Empty or nil slice means allowing all ports in Kubernetes.
	// nil must be returned to meet ofClient's expectation for this behavior.
	if len(in) == 0 {
		return nil
	}
	// It makes sure `out` won't be nil, so that even if only named ports are
	// specified and none of them are resolvable, the rule just falls back to
	// allowing no port, instead of all ports.
	out := make([]v1beta1.Service, 0, len(in))
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

// resolveService resolves the port name of the provided service to a port number
// for the provided Pod.
func resolveService(service *v1beta1.Service, pod *v1beta1.GroupMemberPod) *v1beta1.Service {
	// If port is not specified or is already a number, return it as is.
	if service.Port == nil || service.Port.Type == intstr.Int {
		return service
	}
	for _, port := range pod.Ports {
		if port.Name == service.Port.StrVal && port.Protocol == *service.Protocol {
			resolvedPort := intstr.FromInt(int(port.Port))
			return &v1beta1.Service{Protocol: service.Protocol, Port: &resolvedPort}
		}
	}
	klog.Warningf("Can not resolve port %s for Pod %v", service.Port.StrVal, pod)
	// If not resolvable, return it as is.
	// The Pods that cannot resolve it will be grouped together.
	return service
}

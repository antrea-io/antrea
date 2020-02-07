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
	"fmt"
	"net"
	"sync"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
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

// lastRealized is the struct cached by reconciler. It's used to track the
// actual state of rules we have enforced, so that we can know how to reconcile
// a rule when it's updated/removed.
// It includes the last version of CompletedRule the reconciler has realized
// and the related runtime information including the unique ofID, the Openflow
// ports or the IP addresses of the target Pods got from the InterfaceStore.
type lastRealized struct {
	// ofID identifies a rule in Openflow implementation.
	ofID uint32
	// The desired state of a policy rule.
	*CompletedRule
	// The OFPort set we have realized for target Pods. We need to record them
	// because this info will be removed from InterfaceStore after CNI DEL, we
	// can't know which OFPort to delete when deleting a Pod from the rule. So
	// we compare the last realized OFPorts and the new desired one to identify
	// difference, which could also cover the stale OFPorts produced by the case
	// that Kubelet calls CNI ADD for a Pod more than once due to non CNI issues.
	podOFPorts sets.Int32
	// The IP set we have realized for target Pods. Same as podOFPorts.
	podIPs sets.String
}

// reconciler implements Reconciler.
// Note that although its Reconcile and Forget methods are thread-safe, it's
// assumed each rule can only be processed by a single client at any given
// time. Different rules can be processed in parallel.
type reconciler struct {
	// ofClient is the Openflow interface.
	ofClient openflow.Client

	// ofClient is the Openflow interface.
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
	klog.Infof("Reconciling rule %v", rule.ID)

	value, exists := r.lastRealizeds.Load(rule.ID)
	if !exists {
		return r.add(rule)
	}
	return r.update(value.(*lastRealized), rule)
}

// add allocates an unique Openflow ID for the provide CompletedRule, converts
// it to PolicyRule, and invoke InstallPolicyRuleFlows to install the later.
func (r *reconciler) add(rule *CompletedRule) error {
	klog.V(2).Infof("Adding new rule %v", rule)
	ofID, err := r.idAllocator.allocate()
	if err != nil {
		return fmt.Errorf("error allocating Openflow ID")
	}
	// Release the ID if encountering any error.
	defer func() {
		if err != nil {
			r.idAllocator.release(ofID)
		}
	}()

	lastRealized := &lastRealized{ofID: ofID, CompletedRule: rule}
	// TODO: Update types.PolicyRule to use Antrea Direction type.
	var direction networkingv1.PolicyType
	var from, exceptFrom, to, exceptTo []types.Address
	if rule.Direction == v1beta1.DirectionIn {
		direction = networkingv1.PolicyTypeIngress
		from, exceptFrom = ipsToOFAddresses(rule.FromAddresses, rule.From.IPBlocks)
		ofPorts := r.podsToOFPorts(rule.Pods)
		// "to" must not be nil, otherwise destination address won't be a match condition in ofClient.
		to = make([]types.Address, 0, len(ofPorts))
		for ofPort := range ofPorts {
			to = append(to, openflow.NewOFPortAddress(ofPort))
		}
		lastRealized.podOFPorts = ofPorts
	} else {
		direction = networkingv1.PolicyTypeEgress
		ips := r.podsToIPs(rule.Pods)
		// "from" must not be nil, otherwise source address won't be a match condition in ofClient.
		from = make([]types.Address, 0, len(ips))
		for ip := range ips {
			from = append(from, ipStringToOFAddress(ip))
		}
		to, exceptTo = ipsToOFAddresses(rule.ToAddresses, rule.To.IPBlocks)
		lastRealized.podIPs = ips
	}

	// TODO: Update types.PolicyRule to use Antrea Service type.
	services := servicesToNetworkPolicyPort(rule.Services)

	ofRule := &types.PolicyRule{
		ID:         ofID,
		Direction:  direction,
		From:       from,
		ExceptFrom: exceptFrom,
		To:         to,
		ExceptTo:   exceptTo,
		Service:    services,
	}

	klog.V(2).Infof("Installing ofRule %d (Direction: %v, From: %d, ExceptFrom: %d, To: %d, ExceptTo: %d, Service: %d)",
		ofRule.ID, ofRule.Direction, len(ofRule.From), len(ofRule.ExceptFrom), len(ofRule.To), len(ofRule.ExceptTo), len(ofRule.Service))
	if err := r.ofClient.InstallPolicyRuleFlows(ofRule); err != nil {
		return fmt.Errorf("error installing ofRule %v: %v", ofRule.ID, err)
	}

	r.lastRealizeds.Store(rule.ID, lastRealized)
	return nil
}

func ipsToOFAddresses(podSet v1beta1.GroupMemberPodSet, ipBlocks []v1beta1.IPBlock) ([]types.Address, []types.Address) {
	// Note that addresses must not return nil because it means not restricted by addresses
	// in Openflow implementation.
	addresses := make([]types.Address, 0, len(podSet)+len(ipBlocks))
	for _, p := range podSet {
		addresses = append(addresses, ipAddressToOFAddress(p.IP))
	}
	var exceptAddresses []types.Address
	for _, b := range ipBlocks {
		addresses = append(addresses, ipNetToOFAddress(b.CIDR))
		for _, e := range b.Except {
			exceptAddresses = append(exceptAddresses, ipNetToOFAddress(e))
		}
	}
	return addresses, exceptAddresses
}

func servicesToNetworkPolicyPort(in []v1beta1.Service) []*networkingv1.NetworkPolicyPort {
	// Empty or nil slice means allowing all ports in Kubernetes.
	// nil must be returned to meet ofClient's expectation for this behavior.
	if len(in) == 0 {
		return nil
	}
	// It makes sure out won't be nil, so that if only named ports are defined,
	// we don't enforce the rule as allowing all ports by mistake.
	out := make([]*networkingv1.NetworkPolicyPort, 0, len(in))
	for _, s := range in {
		service := &networkingv1.NetworkPolicyPort{}
		if s.Protocol != nil {
			protoStr := string(*s.Protocol)
			proto := corev1.Protocol(protoStr)
			service.Protocol = &proto
		}
		if s.Port != nil {
			// Ignore named port for now.
			if s.Port.Type == intstr.String {
				continue
			}
			service.Port = s.Port
		}
		out = append(out, service)
	}
	return out
}

// update calculates the difference of Addresses between oldRule and newRule,
// and invokes Openflow client's methods to reconcile them.
func (r *reconciler) update(lastRealized *lastRealized, newRule *CompletedRule) error {
	klog.V(2).Infof("Updating existing rule %v", newRule)
	// As rule identifier is calculated from the rule's content, the update can
	// only happen to Group members.
	var addedFrom, addedTo, deletedFrom, deletedTo []types.Address
	var newOFPorts sets.Int32
	var newIPs sets.String
	if newRule.Direction == v1beta1.DirectionIn {
		for _, a := range newRule.FromAddresses.Difference(lastRealized.FromAddresses) {
			addedFrom = append(addedFrom, ipAddressToOFAddress(a.IP))
		}
		for _, a := range lastRealized.FromAddresses.Difference(newRule.FromAddresses) {
			deletedFrom = append(deletedFrom, ipAddressToOFAddress(a.IP))
		}
		newOFPorts = r.podsToOFPorts(newRule.Pods)
		for p := range newOFPorts.Difference(lastRealized.podOFPorts) {
			addedTo = append(addedTo, openflow.NewOFPortAddress(p))
		}
		for p := range lastRealized.podOFPorts.Difference(newOFPorts) {
			deletedTo = append(deletedTo, openflow.NewOFPortAddress(p))
		}
	} else {
		newIPs = r.podsToIPs(newRule.Pods)
		for ip := range newIPs.Difference(lastRealized.podIPs) {
			addedFrom = append(addedTo, ipStringToOFAddress(ip))
		}
		for ip := range lastRealized.podIPs.Difference(newIPs) {
			deletedFrom = append(addedTo, ipStringToOFAddress(ip))
		}
		for _, a := range newRule.ToAddresses.Difference(lastRealized.ToAddresses) {
			addedTo = append(addedTo, ipAddressToOFAddress(a.IP))
		}
		for _, a := range lastRealized.ToAddresses.Difference(newRule.ToAddresses) {
			deletedTo = append(deletedTo, ipAddressToOFAddress(a.IP))
		}
	}

	klog.V(2).Infof("Updating ofRule %d (Direction: %v, addedFrom: %d, addedTo: %d, deleteFrom: %d, deletedTo: %d)",
		lastRealized.ofID, lastRealized.Direction, len(addedFrom), len(addedTo), len(deletedFrom), len(deletedTo))

	// TODO: This might be unnecessarily complex and hard for error handling, consider revising the Openflow interfaces.
	if len(addedFrom) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(lastRealized.ofID, types.SrcAddress, addedFrom); err != nil {
			return fmt.Errorf("error adding policy rule source addresses for ofRule %v: %v", lastRealized.ofID, err)
		}
	}
	if len(addedTo) > 0 {
		if err := r.ofClient.AddPolicyRuleAddress(lastRealized.ofID, types.DstAddress, addedTo); err != nil {
			return fmt.Errorf("error adding policy rule destination addresses for ofRule %v: %v", lastRealized.ofID, err)
		}
	}
	if len(deletedFrom) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(lastRealized.ofID, types.SrcAddress, deletedFrom); err != nil {
			return fmt.Errorf("error deleting policy rule source addresses for ofRule %v: %v", lastRealized.ofID, err)
		}
	}
	if len(deletedTo) > 0 {
		if err := r.ofClient.DeletePolicyRuleAddress(lastRealized.ofID, types.DstAddress, deletedTo); err != nil {
			return fmt.Errorf("error deleting policy rule destination addresses for ofRule %v: %v", lastRealized.ofID, err)
		}
	}

	lastRealized.podOFPorts = newOFPorts
	lastRealized.podIPs = newIPs
	lastRealized.CompletedRule = newRule
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
	klog.V(3).Infof("Uninstalling ofRule %d", lastRealized.ofID)
	if err := r.ofClient.UninstallPolicyRuleFlows(lastRealized.ofID); err != nil {
		return fmt.Errorf("error uninstalling ofRule %v: %v", lastRealized.ofID, err)
	}

	if err := r.idAllocator.release(lastRealized.ofID); err != nil {
		// This should never happen. If it does, it is a programming error.
		klog.Errorf("Error releasing Openflow ID for ofRule %v: %v", lastRealized.ofID, err)
	}

	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *reconciler) podsToOFPorts(pods v1beta1.GroupMemberPodSet) sets.Int32 {
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

func (r *reconciler) podsToIPs(pods v1beta1.GroupMemberPodSet) sets.String {
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

func ipNetToOFAddress(in v1beta1.IPNet) *openflow.IPNetAddress {
	ipNet := net.IPNet{
		IP:   net.IP(in.IP),
		Mask: net.CIDRMask(int(in.PrefixLength), 32),
	}
	return openflow.NewIPNetAddress(ipNet)
}

func ipAddressToOFAddress(in v1beta1.IPAddress) *openflow.IPAddress {
	return openflow.NewIPAddress(net.IP(in))
}

func ipStringToOFAddress(in string) *openflow.IPAddress {
	return openflow.NewIPAddress(net.ParseIP(in))
}

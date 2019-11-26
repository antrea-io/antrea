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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy/v1beta1"
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

// lastRealized is the struct cached by reconciler.
type lastRealized struct {
	// ofID identifies a rule in Openflow implementation.
	ofID uint32
	// The desired state of a policy rule.
	*CompletedRule
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
	klog.V(2).Infof("Adding new rule %v (%v, %d FromAddresses, %d ToAddresses, %d Pods)",
		rule.ID, rule.Direction, len(rule.FromAddresses), len(rule.ToAddresses), len(rule.Pods))
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
	// TODO: Update types.PolicyRule to use Antrea Direction type.
	var direction networkingv1.PolicyType
	// TODO: Differentiate rule that match everything and rule that match nothing.
	// nil slice should match everything and empty slice should match nothing.
	var from, to []types.Address
	if rule.Direction == v1beta1.DirectionIn {
		direction = networkingv1.PolicyTypeIngress

		if rule.FromAddresses != nil || rule.From.IPBlocks != nil {
			from = make([]types.Address, 0, len(rule.FromAddresses)+len(rule.From.IPBlocks))
		}
		for a := range rule.FromAddresses {
			from = append(from, openflow.NewIPAddress(net.ParseIP(a)))
		}
		// TODO: handle except field.
		for _, b := range rule.From.IPBlocks {
			from = append(from, openflow.NewIPNetAddress(antreaIPNetToIPNet(b.CIDR)))
		}

		to = r.podsToOFPortAddresses(rule.Pods)
	} else {
		direction = networkingv1.PolicyTypeEgress

		from = r.podsToIPAddresses(rule.Pods)

		if rule.ToAddresses != nil || rule.To.IPBlocks != nil {
			to = make([]types.Address, 0, len(rule.ToAddresses)+len(rule.To.IPBlocks))
		}
		for a := range rule.ToAddresses {
			to = append(to, openflow.NewIPAddress(net.ParseIP(a)))
		}
		// TODO: handle except field.
		for _, b := range rule.To.IPBlocks {
			to = append(to, openflow.NewIPNetAddress(antreaIPNetToIPNet(b.CIDR)))
		}
	}

	// TODO: Update types.PolicyRule to use Antrea Service type.
	services := servicesToNetworkPolicyPort(rule.Services)

	ofRule := &types.PolicyRule{
		ID:        ofID,
		Direction: direction,
		From:      from,
		To:        to,
		Service:   services,
	}

	klog.V(2).Infof("Installing ofRule %d (%v, %d From, %d To, %d Service)",
		ofRule.ID, ofRule.Direction, len(ofRule.From), len(ofRule.To), len(ofRule.Service))
	if err := r.ofClient.InstallPolicyRuleFlows(ofRule); err != nil {
		return fmt.Errorf("error installing ofRule %v: %v", ofRule.ID, err)
	}

	r.lastRealizeds.Store(rule.ID, &lastRealized{ofID, rule})
	return nil
}

func servicesToNetworkPolicyPort(in []v1beta1.Service) []*networkingv1.NetworkPolicyPort {
	var out []*networkingv1.NetworkPolicyPort
	for _, s := range in {
		service := &networkingv1.NetworkPolicyPort{}
		if s.Protocol != nil {
			protoStr := string(*s.Protocol)
			proto := corev1.Protocol(protoStr)
			service.Protocol = &proto
		}
		if s.Port != nil {
			// We have converted named port to int port in antrea-controller.
			// Here it's just to adapt the PolicyRule type, and can be removed
			// once switching to use Antrea Service type.
			port := intstr.FromInt(int(*s.Port))
			service.Port = &port
		}
		out = append(out, service)
	}
	return out
}

// update calculates the difference of Addresses between oldRule and newRule,
// and invokes Openflow client's methods to reconcile them.
func (r *reconciler) update(lastRealized *lastRealized, newRule *CompletedRule) error {
	klog.V(2).Infof("Updating existing rule %v (%v, %d FromAddresses, %d ToAddresses, %d Pods)",
		newRule.ID, newRule.Direction, len(newRule.FromAddresses), len(newRule.ToAddresses), len(newRule.Pods))
	// As rule identifier is calculated from the rule's content, the update can
	// only happen to Group members.
	var addedFrom, addedTo, deletedFrom, deletedTo []types.Address
	if newRule.Direction == v1beta1.DirectionIn {
		for a := range newRule.FromAddresses.Difference(lastRealized.FromAddresses) {
			addedFrom = append(addedFrom, openflow.NewIPAddress(net.ParseIP(a)))
		}
		for a := range lastRealized.FromAddresses.Difference(newRule.FromAddresses) {
			deletedFrom = append(deletedFrom, openflow.NewIPAddress(net.ParseIP(a)))
		}
		addedTo = r.podsToOFPortAddresses(newRule.Pods.Difference(lastRealized.Pods))
		deletedTo = r.podsToOFPortAddresses(lastRealized.Pods.Difference(lastRealized.Pods))
	} else {
		addedFrom = r.podsToIPAddresses(newRule.Pods.Difference(lastRealized.Pods))
		deletedFrom = r.podsToIPAddresses(lastRealized.Pods.Difference(newRule.Pods))
		for a := range newRule.ToAddresses.Difference(lastRealized.ToAddresses) {
			addedTo = append(addedTo, openflow.NewIPAddress(net.ParseIP(a)))
		}
		for a := range lastRealized.ToAddresses.Difference(newRule.ToAddresses) {
			deletedTo = append(deletedTo, openflow.NewIPAddress(net.ParseIP(a)))
		}
	}

	klog.V(2).Infof("Updating ofRule %d (%d addedFrom, %d addedTo, %d deleteFrom, %d deletedTo)",
		lastRealized.ofID, len(addedFrom), len(addedTo), len(deletedFrom), len(deletedTo))

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

func (r *reconciler) podsToOFPortAddresses(pods podSet) []types.Address {
	// If pods is nil, nil must be returned, can't be empty slice.
	if pods == nil {
		return nil
	}
	addresses := make([]types.Address, 0, len(pods))
	for pod := range pods {
		iface, found := r.ifaceStore.GetContainerInterface(pod.Name, pod.Namespace)
		if !found {
			// This might be because the container has been deleted during realization.
			klog.Warningf("Can't find interface for Pod %s/%s, skipping", pod.Namespace, pod.Name)
			continue
		}
		klog.V(2).Infof("Got OFPort %v for Pod %s/%s", iface.OFPort, pod.Namespace, pod.Name)
		addresses = append(addresses, openflow.NewOFPortAddress(iface.OFPort))
	}
	return addresses
}

func (r *reconciler) podsToIPAddresses(pods podSet) []types.Address {
	// If pods is nil, nil must be returned, can't be empty slice.
	if pods == nil {
		return nil
	}
	addresses := make([]types.Address, 0, len(pods))
	for pod := range pods {
		iface, found := r.ifaceStore.GetContainerInterface(pod.Name, pod.Namespace)
		if !found {
			// This might be because the container has been deleted during realization.
			klog.Warningf("Can't find interface for Pod %s/%s, skipping", pod.Namespace, pod.Name)
			continue
		}
		klog.V(2).Infof("Got IP %v for Pod %s/%s", iface.IP, pod.Namespace, pod.Name)
		addresses = append(addresses, openflow.NewIPAddress(iface.IP))
	}
	return addresses
}

func antreaIPNetToIPNet(in v1beta1.IPNet) net.IPNet {
	return net.IPNet{
		IP:   net.IP(in.IP),
		Mask: net.CIDRMask(int(in.PrefixLength), 32),
	}
}

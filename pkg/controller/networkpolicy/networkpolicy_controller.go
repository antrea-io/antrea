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

// Package networkpolicy provides NetworkPolicyController implementation to manage
// and synchronize the Pods and Namespaces affected by Network Policies and enforce
// their rules.

package networkpolicy

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/satori/go.uuid"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

const (
	// Interval of synchronizing status from apiserver.
	syncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a NetworkPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a NetworkPolicy change.
	defaultWorkers = 4
)

var (
	keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

	// uuidNamespace is a uuid.UUID type generated from a string to be
	// used to generate uuid.UUID for internal Antrea objects like
	// AppliedToGroup, AddressGroup etc.
	// 5a5e7dd9-e3fb-49bb-b263-9bab25c95841 was generated using
	// uuid.NewV4() function.
	uuidNamespace = uuid.FromStringOrNil("5a5e7dd9-e3fb-49bb-b263-9bab25c95841")

	// matchAllPeer is a NetworkPolicyPeer matching all source/destination IP addresses.
	matchAllPeer = networkpolicy.NetworkPolicyPeer{
		IPBlocks: []networkpolicy.IPBlock{{CIDR: networkpolicy.IPNet{IP: networkpolicy.IPAddress(net.IPv4zero), PrefixLength: 0}}},
	}
	// denyAllIngressRule is a NetworkPolicyRule which denies all ingress traffic.
	denyAllIngressRule = networkpolicy.NetworkPolicyRule{Direction: networkpolicy.DirectionIn}
	// denyAllEgressRule is a NetworkPolicyRule which denies all egress traffic.
	denyAllEgressRule = networkpolicy.NetworkPolicyRule{Direction: networkpolicy.DirectionOut}
)

// NetworkPolicyController is responsible for synchronizing the Namespaces and Pods
// affected by a Network Policy.
type NetworkPolicyController struct {
	kubeClient  clientset.Interface
	podInformer coreinformers.PodInformer

	// podLister is able to list/get Pods and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	podLister corelisters.PodLister

	// podListerSynced is a function which returns true if the Pod shared informer has been synced at least once.
	podListerSynced cache.InformerSynced

	namespaceInformer coreinformers.NamespaceInformer

	// namespaceLister is able to list/get Namespaces and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	namespaceLister corelisters.NamespaceLister

	// namespaceListerSynced is a function which returns true if the Namespace shared informer has been synced at least once.
	namespaceListerSynced cache.InformerSynced

	networkPolicyInformer networkinginformers.NetworkPolicyInformer

	// networkPolicyLister is able to list/get Network Policies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	networkPolicyLister networkinglisters.NetworkPolicyLister

	// networkPolicyListerSynced is a function which returns true if the Network Policy shared informer has been synced at least once.
	networkPolicyListerSynced cache.InformerSynced

	// addressGroupStore is the storage where the populated Address Groups are stored.
	addressGroupStore storage.Interface

	// appliedToGroupStore is the storage where the populated AppliedTo Groups are stored.
	appliedToGroupStore storage.Interface

	// internalNetworkPolicyStore is the storage where the populated internal Network Policy are stored.
	internalNetworkPolicyStore storage.Interface

	// appliedToGroupQueue maintains the networkpolicy.AppliedToGroup objects that
	// need to be synced.
	appliedToGroupQueue workqueue.RateLimitingInterface

	// addressGroupQueue maintains the networkpolicy.AddressGroup objects that
	// need to be synced.
	addressGroupQueue workqueue.RateLimitingInterface

	// internalNetworkPolicyQueue maintains the networkpolicy.NetworkPolicy objects that
	// need to be synced.
	internalNetworkPolicyQueue workqueue.RateLimitingInterface

	// internalNetworkPolicyMutex protects the internalNetworkPolicyStore from
	// concurrent access during updates to the internal NetworkPolicy object.
	internalNetworkPolicyMutex sync.RWMutex
}

// NewNetworkPolicyController returns a new *NetworkPolicyController.
func NewNetworkPolicyController(kubeClient clientset.Interface,
	podInformer coreinformers.PodInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	networkPolicyInformer networkinginformers.NetworkPolicyInformer,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	internalNetworkPolicyStore storage.Interface) *NetworkPolicyController {
	n := &NetworkPolicyController{
		kubeClient:                 kubeClient,
		podInformer:                podInformer,
		podLister:                  podInformer.Lister(),
		podListerSynced:            podInformer.Informer().HasSynced,
		namespaceInformer:          namespaceInformer,
		namespaceLister:            namespaceInformer.Lister(),
		namespaceListerSynced:      namespaceInformer.Informer().HasSynced,
		networkPolicyInformer:      networkPolicyInformer,
		networkPolicyLister:        networkPolicyInformer.Lister(),
		networkPolicyListerSynced:  networkPolicyInformer.Informer().HasSynced,
		addressGroupStore:          addressGroupStore,
		appliedToGroupStore:        appliedToGroupStore,
		internalNetworkPolicyStore: internalNetworkPolicyStore,
		appliedToGroupQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "appliedToGroup"),
		addressGroupQueue:          workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "addressGroup"),
		internalNetworkPolicyQueue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalNetworkPolicy"),
	}
	// Add handlers for Pod events.
	podInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addPod,
			UpdateFunc: n.updatePod,
			DeleteFunc: n.deletePod,
		},
		syncPeriod,
	)
	// Add handlers for Namespace events.
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addNamespace,
			UpdateFunc: n.updateNamespace,
			DeleteFunc: n.deleteNamespace,
		},
		syncPeriod,
	)
	// Add handlers for NetworkPolicy events.
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addNetworkPolicy,
			UpdateFunc: n.updateNetworkPolicy,
			DeleteFunc: n.deleteNetworkPolicy,
		},
		syncPeriod,
	)
	return n
}

// toGroupSelector converts the podSelector and namespaceSelector
// and NetworkPolicy Namespace to a networkpolicy.GroupSelector object.
func toGroupSelector(namespace string, podSelector, nsSelector *metav1.LabelSelector) *antreatypes.GroupSelector {
	groupSelector := antreatypes.GroupSelector{
		PodSelector: podSelector,
	}
	if nsSelector == nil {
		// No namespaceSelector indicates that the pods must be selected within
		// the NetworkPolicy's Namespace.
		groupSelector.Namespace = namespace
	} else {
		groupSelector.NamespaceSelector = nsSelector
	}
	name := generateNormalizedName(groupSelector.Namespace, groupSelector.PodSelector, groupSelector.NamespaceSelector)
	groupSelector.NormalizedName = name
	return &groupSelector
}

// normalizeExpr converts an expression to the form "key1 OP [value1...]".
func normalizeExpr(key string, operator metav1.LabelSelectorOperator, values []string) string {
	if len(values) == 0 {
		return fmt.Sprintf("%s %s", key, operator)
	} else {
		return fmt.Sprintf("%s %s %s", key, operator, values)
	}
}

// selectorToString creates a string corresponding to a labelSelector in the form of
// "key1 IN [value1,...] And key2 NotIn [value2,...] And ...".
func selectorToString(selector *metav1.LabelSelector) string {
	selSlice := make([]string, 0, len(selector.MatchLabels)+len(selector.MatchExpressions))
	// emptyValue is a placeholder empty slice to send to normalizeExpr for Exists, NotExist operators.
	var emptyValue []string
	// Append labels in matchLabels as "key In [value]".
	for key, value := range selector.MatchLabels {
		valueSlice := []string{value}
		selSlice = append(selSlice, normalizeExpr(key, metav1.LabelSelectorOpIn, valueSlice))
	}
	for _, expr := range selector.MatchExpressions {
		switch expr.Operator {
		case metav1.LabelSelectorOpIn:
			selSlice = append(selSlice, normalizeExpr(expr.Key, metav1.LabelSelectorOpIn, expr.Values))
		case metav1.LabelSelectorOpNotIn:
			selSlice = append(selSlice, normalizeExpr(expr.Key, metav1.LabelSelectorOpNotIn, expr.Values))
		case metav1.LabelSelectorOpExists:
			selSlice = append(selSlice, normalizeExpr(expr.Key, metav1.LabelSelectorOpExists, emptyValue))
		case metav1.LabelSelectorOpDoesNotExist:
			selSlice = append(selSlice, normalizeExpr(expr.Key, metav1.LabelSelectorOpDoesNotExist, emptyValue))
		}
	}
	sort.Strings(selSlice)
	normalizedStr := strings.Join(selSlice, " And ")
	return normalizedStr
}

// getNormalizedUID generates a unique UUID based on a given string.
// For example, it can be used to generate keys using normalized selectors
// unique within the Namespace by adding the constant UID.
func getNormalizedUID(name string) string {
	return uuid.NewV5(uuidNamespace, name).String()
}

// generateNormalizedName generates a string, based on the selectors, in
// the following format: "namespace=NamespaceName And podSelector=normalizedPodSelector".
// Note: Namespace and nsSelector may or may not be set depending on the
// selector. However, they cannot be set simultaneously.
func generateNormalizedName(namespace string, podSelector, nsSelector *metav1.LabelSelector) string {
	normalizedName := []string{}
	if nsSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("namespaceSelector=%s", selectorToString(nsSelector)))
	} else if namespace != "" {
		normalizedName = append(normalizedName, fmt.Sprintf("namespace=%s", namespace))
	}
	if podSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("podSelector=%s", selectorToString(podSelector)))
	}
	sort.Strings(normalizedName)
	return strings.Join(normalizedName, " And ")
}

// createAppliedToGroup creates an AppliedToGroup object in store if it is not created already.
func (n *NetworkPolicyController) createAppliedToGroup(np *networkingv1.NetworkPolicy) string {
	groupSelector := toGroupSelector(np.ObjectMeta.Namespace, &np.Spec.PodSelector, nil)
	appliedToGroupUID := getNormalizedUID(groupSelector.NormalizedName)
	// Get or create a AppliedToGroup for the generated UID.
	_, found, _ := n.appliedToGroupStore.Get(appliedToGroupUID)
	if found {
		klog.V(4).Infof("Found existing AppliedToGroup %s", appliedToGroupUID)
		return appliedToGroupUID
	}
	// Construct a new AppliedToGroup.
	newAppliedToGroup := &antreatypes.AppliedToGroup{
		Name:     appliedToGroupUID,
		UID:      types.UID(appliedToGroupUID),
		Selector: *groupSelector,
	}
	klog.V(2).Infof("Creating new AppliedToGroup %s", newAppliedToGroup.Name)
	n.appliedToGroupStore.Create(newAppliedToGroup)
	n.enqueueAppliedToGroup(appliedToGroupUID)
	return appliedToGroupUID
}

// labelsMatchGroupSelector matches a Pod's labels to the
// GroupSelector object and returns true, if and only if the labels
// match any of the selector criteria present in the GroupSelector.
func (n *NetworkPolicyController) labelsMatchGroupSelector(pod *v1.Pod, podNS *v1.Namespace, sel antreatypes.GroupSelector) bool {
	if sel.Namespace != "" {
		if sel.Namespace != pod.Namespace {
			// Pods must be matched within the same Namespace.
			klog.V(4).Infof("Pod's Namespace %s does not match selector Namespace %s", pod.Namespace, sel.Namespace)
			return false
		}
		// Convert labelSelector to a Selector.
		selector, _ := metav1.LabelSelectorAsSelector(sel.PodSelector)
		if !selector.Matches(labels.Set(pod.Labels)) {
			// podSelector does not match the Pod's labels.
			return false
		}
		// podSelector matches the Pod's labels.
		klog.V(4).Infof("Pod labels %v match PodSelector", pod.Labels)
		return true
	} else if sel.NamespaceSelector != nil && sel.PodSelector != nil {
		// Selector is a multi-selector where Pods must be selected if namespaceSelector matches Pod's Namespace.
		// Convert Namespace labelSelector to a Selector.
		nSelector, _ := metav1.LabelSelectorAsSelector(sel.NamespaceSelector)
		// Pod event may arrive before Pod's Namespace event. In this case, we must
		// ensure that the Pod Namespace is not nil.
		if podNS == nil || !nSelector.Matches(labels.Set(podNS.Labels)) {
			// Pod's Namespace do not match namespaceSelector.
			return false
		}
		klog.V(4).Infof("Namespace labels match NamespaceSelector. Evaluating Pods in Namespace %s", podNS.Name)
		// Convert Pod labelSelector to a Selector.
		pSelector, _ := metav1.LabelSelectorAsSelector(sel.PodSelector)
		if !pSelector.Matches(labels.Set(pod.Labels)) {
			// Pod's Namespace matches namespaceSelector but Pod's labels do not match
			// the podSelector.
			return false
		}
		// Pod's Namespace matches namespaceSelector and Pod's labels matches
		// podSelector.
		klog.V(4).Infof("Pod labels %v match PodSelector", pod.Labels)
		return true
	} else if sel.NamespaceSelector != nil {
		// Selector only has a NamespaceSelector.
		nSelector, _ := metav1.LabelSelectorAsSelector(sel.NamespaceSelector)
		// Pod event may arrive before Pod's Namespace event. In this case, we must
		// ensure that the Pod Namespace is not nil.
		if podNS == nil || !nSelector.Matches(labels.Set(podNS.Labels)) {
			// Namespace labels do not match namespaceSelector.
			return false
		}
		// Namespace labels match namespaceSelector.
		klog.V(4).Infof("Namespace labels %v match NamespaceSelector", podNS.Labels)
		return true
	}
	return false
}

// filterAddressGroupsForNamespace computes a list of AddressGroup keys which
// match the Namespace's labels.
func (n *NetworkPolicyController) filterAddressGroupsForNamespace(namespace *v1.Namespace) sets.String {
	matchingKeys := sets.String{}
	addressGroups := n.addressGroupStore.List()
	for _, group := range addressGroups {
		addrGroup := group.(*antreatypes.AddressGroup)
		if addrGroup.Selector.NamespaceSelector == nil {
			// This addressGroup selector does not have a namespaceSelector,
			// skip processing.
			continue
		}
		nSelector, _ := metav1.LabelSelectorAsSelector(addrGroup.Selector.NamespaceSelector)
		if nSelector.Matches(labels.Set(namespace.Labels)) {
			matchingKeys.Insert(addrGroup.Name)
			klog.V(2).Infof("Namespace %s appended to AddressGroup %s", namespace.Name, addrGroup.Name)
			continue
		}
		klog.V(4).Infof("Namespace %s labels do not match AddressGroup %s", namespace.Name, addrGroup.Name)
	}
	return matchingKeys
}

// filterAddressGroupsForPod computes a list of AddressGroup keys which
// match the Pod's labels.
func (n *NetworkPolicyController) filterAddressGroupsForPod(pod *v1.Pod) sets.String {
	matchingKeySet := sets.String{}
	addressGroups := n.addressGroupStore.List()
	podNS, _ := n.namespaceLister.Get(pod.Namespace)
	for _, group := range addressGroups {
		addrGroup := group.(*antreatypes.AddressGroup)
		if n.labelsMatchGroupSelector(pod, podNS, addrGroup.Selector) {
			matchingKeySet.Insert(addrGroup.Name)
			klog.V(2).Infof("Pod %s/%s appended to AddressGroup %s", pod.Namespace, pod.Name, addrGroup.Name)
			continue
		}
		klog.V(4).Infof("Pod %s/%s labels do not match AddressGroup %s", pod.Namespace, pod.Name, addrGroup.Name)
	}
	return matchingKeySet
}

// filterAppliedToGroupsForPod computes a list of AppliedToGroup keys which
// match the Pod's labels.
func (n *NetworkPolicyController) filterAppliedToGroupsForPod(pod *v1.Pod) sets.String {
	matchingKeySet := sets.String{}
	appliedToGroups := n.appliedToGroupStore.List()
	podNS, _ := n.namespaceLister.Get(pod.Namespace)
	for _, group := range appliedToGroups {
		appGroup := group.(*antreatypes.AppliedToGroup)
		if n.labelsMatchGroupSelector(pod, podNS, appGroup.Selector) {
			matchingKeySet.Insert(appGroup.Name)
			klog.V(2).Infof("Pod %s/%s appended to AppliedToGroup %s", pod.Namespace, pod.Name, appGroup.Name)
			continue
		}
		klog.V(4).Infof("Pod %s/%s labels do not match AppliedToGroup %v", pod.Namespace, pod.Name, appGroup.Name)
	}
	return matchingKeySet
}

// createAddressGroup creates an AddressGroup object corresponding to a
// NetworkPolicyPeer object in NetworkPolicyRule. This function simply
// creates the object without actually populating the PodAddresses as the
// affected Pods are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroup(peer networkingv1.NetworkPolicyPeer, np *networkingv1.NetworkPolicy) string {
	groupSelector := toGroupSelector(np.ObjectMeta.Namespace, peer.PodSelector, peer.NamespaceSelector)
	normalizedUID := getNormalizedUID(groupSelector.NormalizedName)
	// Get or create an AddressGroup for the generated UID.
	_, found, _ := n.addressGroupStore.Get(normalizedUID)
	if found {
		return normalizedUID
	}
	// Create an AddressGroup object per Peer object.
	addressGroup := &antreatypes.AddressGroup{
		UID:      types.UID(normalizedUID),
		Name:     normalizedUID,
		Selector: *groupSelector,
	}
	klog.V(2).Infof("Creating new AddressGroup %s", addressGroup.Name)
	n.addressGroupStore.Create(addressGroup)
	return normalizedUID
}

// toAntreaProtocol converts a v1.Protocol object to an Antrea Protocol object.
func toAntreaProtocol(npProtocol *v1.Protocol) *networkpolicy.Protocol {
	// If Protocol is unset, it must default to TCP protocol.
	internalProtocol := networkpolicy.ProtocolTCP
	if npProtocol != nil {
		internalProtocol = networkpolicy.Protocol(*npProtocol)
	}
	return &internalProtocol
}

// toAntreaServices converts a networkingv1.NetworkPolicyPort object to an
// Antrea Service object.
func toAntreaServices(npPorts []networkingv1.NetworkPolicyPort) []networkpolicy.Service {
	var antreaServices []networkpolicy.Service
	for _, npPort := range npPorts {
		antreaService := networkpolicy.Service{
			Protocol: toAntreaProtocol(npPort.Protocol),
		}
		if npPort.Port != nil {
			// TODO(abhiraut): Retrieve ports for named ports.
			port := int32(npPort.Port.IntValue())
			antreaService.Port = &port
		}
		antreaServices = append(antreaServices, antreaService)
	}
	return antreaServices
}

// toAntreaIPBlock converts a networkingv1.IPBlock to an Antrea IPBlock.
func toAntreaIPBlock(ipBlock *networkingv1.IPBlock) (*networkpolicy.IPBlock, error) {
	// Convert the allowed IPBlock to networkpolicy.IPNet.
	ipNet, err := store.CIDRStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	exceptNets := []networkpolicy.IPNet{}
	for _, exc := range ipBlock.Except {
		// Convert the except IPBlock to networkpolicy.IPNet.
		exceptNet, err := store.CIDRStrToIPNet(exc)
		if err != nil {
			return nil, err
		}
		exceptNets = append(exceptNets, *exceptNet)
	}
	antreaIPBlock := &networkpolicy.IPBlock{
		CIDR:   *ipNet,
		Except: exceptNets,
	}
	return antreaIPBlock, nil
}

// processNetworkPolicy creates an internal NetworkPolicy instance corresponding
// to the networkingv1.NetworkPolicy object. This method does not commit the
// internal NetworkPolicy in store, instead returns an instance to the caller
// wherein, it will be either stored as a new Object in case of ADD event or
// modified and store the updated instance, in case of an UPDATE event.
func (n *NetworkPolicyController) processNetworkPolicy(np *networkingv1.NetworkPolicy) *antreatypes.NetworkPolicy {
	appliedToGroupKey := n.createAppliedToGroup(np)
	appliedToGroupNames := []string{appliedToGroupKey}
	rules := make([]networkpolicy.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	var ingressRuleExists, egressRuleExists bool
	// Compute NetworkPolicyRule for Ingress Rule.
	for _, ingressRule := range np.Spec.Ingress {
		ingressRuleExists = true
		rules = append(rules, networkpolicy.NetworkPolicyRule{
			Direction: networkpolicy.DirectionIn,
			From:      *n.toAntreaPeer(ingressRule.From, np),
			Services:  toAntreaServices(ingressRule.Ports),
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for _, egressRule := range np.Spec.Egress {
		egressRuleExists = true
		rules = append(rules, networkpolicy.NetworkPolicyRule{
			Direction: networkpolicy.DirectionOut,
			To:        *n.toAntreaPeer(egressRule.To, np),
			Services:  toAntreaServices(egressRule.Ports),
		})
	}

	// Traffic in a direction must be isolated if Spec.PolicyTypes specify it explicitly.
	var ingressIsolated, egressIsolated bool
	for _, policyType := range np.Spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress {
			ingressIsolated = true
		} else if policyType == networkingv1.PolicyTypeEgress {
			egressIsolated = true
		}
	}

	// If ingress isolation is specified explicitly and there's no ingress rule, append a deny-all ingress rule.
	// See https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-ingress-traffic
	if ingressIsolated && !ingressRuleExists {
		rules = append(rules, denyAllIngressRule)
	}
	// If egress isolation is specified explicitly and there's no egress rule, append a deny-all egress rule.
	// See https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-egress-traffic
	if egressIsolated && !egressRuleExists {
		rules = append(rules, denyAllEgressRule)
	}

	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:            np.ObjectMeta.Name,
		Namespace:       np.ObjectMeta.Namespace,
		UID:             np.ObjectMeta.UID,
		AppliedToGroups: appliedToGroupNames,
		Rules:           rules,
	}
	return internalNetworkPolicy
}

func (n *NetworkPolicyController) toAntreaPeer(peers []networkingv1.NetworkPolicyPeer, np *networkingv1.NetworkPolicy) *networkpolicy.NetworkPolicyPeer {
	// Empty NetworkPolicyPeer is supposed to match all addresses.
	// See https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-allow-all-ingress-traffic.
	// It's treated as an IPBlock "0.0.0.0/0".
	if len(peers) == 0 {
		return &matchAllPeer
	}
	var ipBlocks []networkpolicy.IPBlock
	var addressGroups []string
	for _, peer := range peers {
		// A networking.NetworkPolicyPeer will either have an IPBlock or a
		// podSelector and/or namespaceSelector set.
		if peer.IPBlock != nil {
			ipBlock, err := toAntreaIPBlock(peer.IPBlock)
			if err != nil {
				klog.Errorf("Failure processing NetworkPolicy %s/%s IPBlock %v: %v", np.Namespace, np.Name, peer.IPBlock, err)
				continue
			}
			ipBlocks = append(ipBlocks, *ipBlock)
		} else {
			normalizedUID := n.createAddressGroup(peer, np)
			addressGroups = append(addressGroups, normalizedUID)
		}
	}
	return &networkpolicy.NetworkPolicyPeer{AddressGroups: addressGroups, IPBlocks: ipBlocks}
}

// addNetworkPolicy receives NetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addNetworkPolicy(obj interface{}) {
	np := obj.(*networkingv1.NetworkPolicy)
	defer klog.V(2).Infof("Finished processing NetworkPolicy %s/%s ADD event", np.ObjectMeta.Namespace, np.ObjectMeta.Name)
	// Create an internal NetworkPolicy object correspoding to this NetworkPolicy
	// and enqueue task to internal NetworkPolicy Workqueue.
	internalNP := n.processNetworkPolicy(np)
	klog.V(2).Infof("Creating new internal NetworkPolicy %s/%s", internalNP.Namespace, internalNP.Name)
	n.internalNetworkPolicyStore.Create(internalNP)
	key, _ := keyFunc(np)
	n.enqueueInternalNetworkPolicy(key)
}

// updateNetworkPolicy receives NetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateNetworkPolicy(old, cur interface{}) {
	np := cur.(*networkingv1.NetworkPolicy)
	defer klog.V(2).Infof("Finished processing NetworkPolicy %s/%s UPDATE event", np.ObjectMeta.Namespace, np.ObjectMeta.Name)
	// Update an internal NetworkPolicy ID, correspoding to this NetworkPolicy and
	// enqueue task to internal NetworkPolicy Workqueue.
	curInternalNP := n.processNetworkPolicy(np)
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s/%s", curInternalNP.Namespace, curInternalNP.Name)
	// Retrieve old networkingv1.NetworkPolicy object.
	oldNP := old.(*networkingv1.NetworkPolicy)
	// Old and current NetworkPolicy share the same key.
	key, _ := keyFunc(oldNP)
	// Lock access to internal NetworkPolicy store such that concurrent access
	// to an internal NetworkPolicy is not allowed. This will avoid the
	// case in which an Update to an internal NetworkPolicy object may
	// cause the SpanMeta member to be overridden with stale SpanMeta members
	// from an older internal NetworkPolicy.
	n.internalNetworkPolicyMutex.Lock()
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	// AppliedToGroups currently only supports a single member.
	oldAppliedToGroupUID := oldInternalNP.AppliedToGroups[0]
	// Must preserve old internal NetworkPolicy Span.
	curInternalNP.SpanMeta = oldInternalNP.SpanMeta
	n.internalNetworkPolicyStore.Update(curInternalNP)
	// Unlock the internal NetworkPolicy store.
	n.internalNetworkPolicyMutex.Unlock()
	// Enqueue addressGroup keys to update their Node span.
	for _, rule := range curInternalNP.Rules {
		for _, addrGroupName := range rule.From.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
		for _, addrGroupName := range rule.To.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
	}
	n.enqueueInternalNetworkPolicy(key)
	// AppliedToGroups currently only supports a single member.
	curAppliedToGroupUID := curInternalNP.AppliedToGroups[0]
	// Delete the old AppliedToGroup object if it is not referenced by any
	// internal NetworkPolicy.
	if oldAppliedToGroupUID != curAppliedToGroupUID {
		n.deleteDereferencedAppliedToGroup(oldAppliedToGroupUID)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// deleteNetworkPolicy receives NetworkPolicy DELETED events and deletes resources
// which can be consumed by agents to delete corresponding rules on the Nodes.
func (n *NetworkPolicyController) deleteNetworkPolicy(old interface{}) {
	np := old.(*networkingv1.NetworkPolicy)
	defer klog.V(2).Infof("Finished processing NetworkPolicy %s/%s DELETE event", np.ObjectMeta.Namespace, np.ObjectMeta.Name)
	key, _ := keyFunc(np)
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	// AppliedToGroups currently only supports a single member.
	oldAppliedToGroupUID := oldInternalNP.AppliedToGroups[0]
	// Delete corresponding internal NetworkPolicy from store.
	err := n.internalNetworkPolicyStore.Delete(key)
	if err != nil {
		klog.Errorf("Error deleting internal NetworkPolicy during NetworkPolicy %s/%s delete: %v", np.ObjectMeta.Namespace, np.ObjectMeta.Name, err)
		return
	}
	n.deleteDereferencedAppliedToGroup(oldAppliedToGroupUID)
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// addPod retrieves all AddressGroups and AppliedToGroups which match the Pod's
// labels and enqueues the groups key for further processing.
func (n *NetworkPolicyController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.V(2).Infof("Processing NetworkPolicies for new Pod %s/%s with labels %v", pod.Namespace, pod.Name, pod.Labels)
	// Find all AppliedToGroup keys which match the Pod's labels.
	appliedToGroupKeySet := n.filterAppliedToGroupsForPod(pod)
	// Find all AddressGroup keys which match the Pod's labels.
	addressGroupKeySet := n.filterAddressGroupsForPod(pod)
	// Enqueue groups to their respective queues for group processing.
	for group := range appliedToGroupKeySet {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeySet {
		n.enqueueAddressGroup(group)
	}
}

// updatePod retrieves all AddressGroups and AppliedToGroups which match the
// updated and old Pod's labels and enqueues the group keys for further
// processing.
func (n *NetworkPolicyController) updatePod(oldObj, curObj interface{}) {
	oldPod := oldObj.(*v1.Pod)
	curPod := curObj.(*v1.Pod)
	klog.V(2).Infof("Processing NetworkPolicies for updated Pod %s/%s with labels %v", curPod.Namespace, curPod.Name, curPod.Labels)
	// No need to trigger processing of groups if there is no change in the
	// Pod labels or Pods Node or Pods IP.
	labelsEqual := labels.Equals(labels.Set(oldPod.Labels), labels.Set(curPod.Labels))
	if labelsEqual && oldPod.Spec.NodeName == curPod.Spec.NodeName && oldPod.Status.PodIP == curPod.Status.PodIP {
		klog.V(4).Infof("No change in Pod %s/%s. Skipping NetworkPolicy evaluation.", curPod.Namespace, curPod.Name)
		return
	}
	// Find groups matching the old Pod's labels.
	oldAddressGroupKeySet := n.filterAddressGroupsForPod(oldPod)
	oldAppliedToGroupKeySet := n.filterAppliedToGroupsForPod(oldPod)
	// Find groups matching the new Pod's labels.
	curAppliedToGroupKeySet := n.filterAppliedToGroupsForPod(curPod)
	curAddressGroupKeySet := n.filterAddressGroupsForPod(curPod)
	// Create set to hold the group keys to enqueue.
	var appliedToGroupKeys sets.String
	var addressGroupKeys sets.String
	// AppliedToGroup keys must be enqueued only if the Pod's Node or IP has changed or
	// if Pod's label change causes it to match new Groups.
	if oldPod.Status.PodIP != curPod.Status.PodIP || oldPod.Spec.NodeName != curPod.Spec.NodeName {
		appliedToGroupKeys = oldAppliedToGroupKeySet.Union(curAppliedToGroupKeySet)
	} else if !labelsEqual {
		// No need to enqueue common AppliedToGroups as they already have latest Pod
		// information.
		appliedToGroupKeys = oldAppliedToGroupKeySet.Difference(curAppliedToGroupKeySet).Union(curAppliedToGroupKeySet.Difference(oldAppliedToGroupKeySet))
	}
	// AddressGroup keys must be enqueued only if the Pod's IP has changed or
	// if Pod's label change causes it to match new Groups.
	if oldPod.Status.PodIP != curPod.Status.PodIP {
		addressGroupKeys = oldAddressGroupKeySet.Union(curAddressGroupKeySet)
	} else if !labelsEqual {
		// No need to enqueue common AddressGroups as they already have latest Pod
		// information.
		addressGroupKeys = oldAddressGroupKeySet.Difference(curAddressGroupKeySet).Union(curAddressGroupKeySet.Difference(oldAddressGroupKeySet))
	}
	for group := range appliedToGroupKeys {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// deletePod retrieves all AddressGroups and AppliedToGroups which match the Pod's
// labels and enqueues the groups key for further processing.
func (n *NetworkPolicyController) deletePod(old interface{}) {
	pod := old.(*v1.Pod)
	klog.V(2).Infof("Processing NetworkPolicies for deleted Pod %s/%s with labels %v", pod.Namespace, pod.Name, pod.Labels)
	// Find all AppliedToGroup keys which match the Pod's labels.
	appliedToGroupKeys := n.filterAppliedToGroupsForPod(pod)
	// Find all AddressGroup keys which match the Pod's labels.
	addressGroupKeys := n.filterAddressGroupsForPod(pod)
	// Enqueue groups to their respective queues for group processing.
	for group := range appliedToGroupKeys {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// addNamespace retrieves all AddressGroups which match the Namespace
// labels and enqueues the group keys for further processing.
func (n *NetworkPolicyController) addNamespace(obj interface{}) {
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing NetworkPolicies for new Namespace %s with labels %v", namespace.Name, namespace.Labels)
	addressGroupKeys := n.filterAddressGroupsForNamespace(namespace)
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// updateNamespace retrieves all AddressGroups which match the current and old
// Namespace labels and enqueues the group keys for further processing.
func (n *NetworkPolicyController) updateNamespace(oldObj, curObj interface{}) {
	oldNamespace := oldObj.(*v1.Namespace)
	curNamespace := curObj.(*v1.Namespace)
	klog.V(2).Infof("Processing NetworkPolicies for updated Namespace %s with labels %v", curNamespace.Name, curNamespace.Labels)
	// No need to trigger processing of groups if there is no change in the
	// Namespace labels.
	if labels.Equals(labels.Set(oldNamespace.Labels), labels.Set(curNamespace.Labels)) {
		klog.V(4).Infof("No change in Namespace %s labels", curNamespace.Name)
		return
	}
	// Find groups matching the new Namespace's labels.
	curAddressGroupKeySet := n.filterAddressGroupsForNamespace(curNamespace)
	// Find groups matching the old Namespace's labels.
	oldAddressGroupKeySet := n.filterAddressGroupsForNamespace(oldNamespace)
	addressGroupKeys := sets.String{}
	// No need to enqueue common AddressGroups as they already have latest
	// Namespace information.
	addressGroupKeys = oldAddressGroupKeySet.Difference(curAddressGroupKeySet).Union(curAddressGroupKeySet.Difference(oldAddressGroupKeySet))
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// deleteNamespace retrieves all AddressGroups which match the Namespace's
// labels and enqueues the group keys for further processing.
func (n *NetworkPolicyController) deleteNamespace(old interface{}) {
	namespace := old.(*v1.Namespace)
	klog.V(2).Infof("Processing NetworkPolicies for deleted Namespace %s with labels %v", namespace.Name, namespace.Labels)
	// Find groups matching deleted Namespace's labels and enqueue them
	// for further processing.
	addressGroupKeys := n.filterAddressGroupsForNamespace(namespace)
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

func (n *NetworkPolicyController) enqueueAppliedToGroup(key string) {
	klog.V(4).Infof("Adding new key %s to AppliedToGroup queue", key)
	n.appliedToGroupQueue.Add(key)
}

// deleteDereferencedAddressGroups deletes the AddressGroup keys which are no
// longer referenced by any internal NetworPolicy.
func (n *NetworkPolicyController) deleteDereferencedAddressGroups(internalNP *antreatypes.NetworkPolicy) {
	addressGroupKeys := []string{}
	for _, rule := range internalNP.Rules {
		// Populate AddressGroupKeys for ingress rules.
		addressGroupKeys = append(addressGroupKeys, rule.From.AddressGroups...)
		// Populate AddressGroupKeys for egress rules.
		addressGroupKeys = append(addressGroupKeys, rule.To.AddressGroups...)
	}
	// Delete any AddressGroup key which is no longer referenced by any internal
	// NetworkPolicy.
	for _, key := range addressGroupKeys {
		// Get all internal NetworkPolicy objects that refers this AddressGroup.
		nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AddressGroupIndex, key)
		if err != nil {
			klog.Errorf("Unable to filter internal NetworkPolicies for AddressGroup %s: %v", key, err)
			continue
		}
		if len(nps) == 0 {
			klog.V(2).Infof("Deleting unreferenced AddressGroup %s", key)
			// No internal NetworkPolicy refers to this Group. Safe to delete.
			err = n.addressGroupStore.Delete(key)
			if err != nil {
				klog.Errorf("Unable to delete AddressGroup %s from store: %v", key, err)
			}
		}
	}
}

// deleteDereferencedAppliedToGroup deletes the AppliedToGroup key if it is no
// longer referenced by any internal NetworPolicy.
func (n *NetworkPolicyController) deleteDereferencedAppliedToGroup(key string) {
	// Get all internal NetworkPolicy objects that refers the old AppliedToGroup.
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AppliedToGroupIndex, key)
	if err != nil {
		klog.Errorf("Unable to filter internal NetworkPolicies for AppliedToGroup %s: %v", key, err)
		return
	}
	if len(nps) == 0 {
		// No internal NetworkPolicy refers to this Group. Safe to delete.
		klog.V(2).Infof("Deleting unreferenced AppliedToGroup %s", key)
		err := n.appliedToGroupStore.Delete(key)
		if err != nil {
			klog.Errorf("Unable to delete AppliedToGroup %s from store: %v", key, err)
		}
	}
}

func (n *NetworkPolicyController) enqueueAddressGroup(key string) {
	klog.V(4).Infof("Adding new key %s to AddressGroup queue", key)
	n.addressGroupQueue.Add(key)
}

func (n *NetworkPolicyController) enqueueInternalNetworkPolicy(key string) {
	klog.V(4).Infof("Adding new key %s to internal NetworkPolicy queue", key)
	n.internalNetworkPolicyQueue.Add(key)
}

// Run begins watching and syncing of a NetworkPolicyController.
func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.appliedToGroupQueue.ShutDown()
	defer n.addressGroupQueue.ShutDown()
	defer n.internalNetworkPolicyQueue.ShutDown()

	klog.Info("Starting NetworkPolicy controller")
	defer klog.Info("Shutting down NetworkPolicy controller")

	klog.Info("Waiting for caches to sync for NetworkPolicy controller")
	if !cache.WaitForCacheSync(stopCh, n.podListerSynced, n.namespaceListerSynced, n.networkPolicyListerSynced) {
		klog.Error("Unable to sync caches for NetworkPolicy controller")
		return
	}
	klog.Info("Caches are synced for NetworkPolicy controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.appliedToGroupWorker, time.Second, stopCh)
		go wait.Until(n.addressGroupWorker, time.Second, stopCh)
		go wait.Until(n.internalNetworkPolicyWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (n *NetworkPolicyController) appliedToGroupWorker() {
	for n.processNextAppliedToGroupWorkItem() {
	}
}

func (n *NetworkPolicyController) addressGroupWorker() {
	for n.processNextAddressGroupWorkItem() {
	}
}

func (n *NetworkPolicyController) internalNetworkPolicyWorker() {
	for n.processNextInternalNetworkPolicyWorkItem() {
	}
}

// Processes an item in the "internalNetworkPolicy" work queue, by calling
// syncInternalNetworkPolicy after casting the item to a string
// (NetworkPolicy key). If syncInternalNetworkPolicy returns an error, this
// function handles it by requeueing the item so that it can be processed again
// later. If syncInternalNetworkPolicy is successful, the NetworkPolicy is
// removed from the queue until we get notify of a new change. This function
// return false if and only if the work queue was shutdown (no more items will
// be processed).
func (n *NetworkPolicyController) processNextInternalNetworkPolicyWorkItem() bool {
	key, quit := n.internalNetworkPolicyQueue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer n.internalNetworkPolicyQueue.Done(key)

	err := n.syncInternalNetworkPolicy(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		n.internalNetworkPolicyQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync internal NetworkPolicy %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	n.internalNetworkPolicyQueue.Forget(key)
	return true
}

// Processes an item in the "addressGroup" work queue, by calling
// syncAddressGroup after casting the item to a string (addressGroup key).
// If syncAddressGroup returns an error, this function handles it by requeueing
// the item so that it can be processed again later. If syncAddressGroup is
// successful, the AddressGroup is removed from the queue until we get notify
// of a new change. This function return false if and only if the work queue
// was shutdown (no more items will be processed).
func (n *NetworkPolicyController) processNextAddressGroupWorkItem() bool {
	key, quit := n.addressGroupQueue.Get()
	if quit {
		return false
	}
	defer n.addressGroupQueue.Done(key)

	err := n.syncAddressGroup(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		n.addressGroupQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync AddressGroup %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	n.addressGroupQueue.Forget(key)
	return true
}

// Processes an item in the "appliedToGroup" work queue, by calling
// syncAppliedToGroup after casting the item to a string (appliedToGroup key).
// If syncAppliedToGroup returns an error, this function handles it by
// requeueing the item so that it can be processed again later. If
// syncAppliedToGroup is successful, the AppliedToGroup is removed from the
// queue until we get notify of a new change. This function return false if
// and only if the work queue was shutdown (no more items will be processed).
func (n *NetworkPolicyController) processNextAppliedToGroupWorkItem() bool {
	key, quit := n.appliedToGroupQueue.Get()
	if quit {
		return false
	}
	defer n.appliedToGroupQueue.Done(key)

	err := n.syncAppliedToGroup(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		n.appliedToGroupQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync AppliedToGroup %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	n.appliedToGroupQueue.Forget(key)
	return true
}

// syncAddressGroup retrieves all the internal NetworkPolicies which have a
// reference to this AddressGroup and updates it's Pod IPAddresses set to
// reflect the current state of affected Pods based on the GroupSelector.
func (n *NetworkPolicyController) syncAddressGroup(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing AddressGroup %s. (%v)", key, time.Since(startTime))
	}()
	// Get all internal NetworkPolicy objects that refers this AddressGroup.
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AddressGroupIndex, key)
	if err != nil {
		return fmt.Errorf("unable to filter internal NetworkPolicies for AddressGroup %s: %v", key, err)
	}
	addressGroupObj, found, err := n.addressGroupStore.Get(key)
	if !found {
		// AddressGroup was already deleted. No need to process further.
		klog.V(2).Infof("AddressGroup %s not found.", key)
		return nil
	}
	addressGroup := addressGroupObj.(*antreatypes.AddressGroup)
	var pods []*v1.Pod
	// NodeNames set must be considered immutable once generated and updated
	// in the store. If any change is needed, the set must be regenerated with
	// the new NodeNames and the store must be updated.
	addrGroupNodeNames := sets.String{}
	for _, internalNPObj := range nps {
		internalNP := internalNPObj.(*antreatypes.NetworkPolicy)
		addrGroupNodeNames = addrGroupNodeNames.Union(internalNP.SpanMeta.NodeNames)
	}
	spanMeta := antreatypes.SpanMeta{
		NodeNames: addrGroupNodeNames,
	}
	// Find all Pods matching its selectors and update store.
	groupSelector := addressGroup.Selector
	pSelector, _ := metav1.LabelSelectorAsSelector(groupSelector.PodSelector)
	nSelector, _ := metav1.LabelSelectorAsSelector(groupSelector.NamespaceSelector)
	if groupSelector.Namespace != "" {
		// Namespace presence indicates Pods must be selected from the same Namespace.
		pods, _ = n.podLister.Pods(groupSelector.Namespace).List(pSelector)
	} else if groupSelector.NamespaceSelector != nil && groupSelector.PodSelector != nil {
		// Pods must be selected from Namespaces matching nsSelector.
		namespaces, _ := n.namespaceLister.List(nSelector)
		for _, ns := range namespaces {
			nsPods, _ := n.podLister.Pods(ns.Name).List(pSelector)
			pods = append(pods, nsPods...)
		}
	} else if groupSelector.NamespaceSelector != nil {
		// All the Pods from Namespaces matching the nsSelector must be selected.
		namespaces, _ := n.namespaceLister.List(nSelector)
		for _, ns := range namespaces {
			nsPods, _ := n.podLister.Pods(ns.Name).List(labels.Everything())
			pods = append(pods, nsPods...)
		}
	}
	addresses := sets.String{}
	for _, pod := range pods {
		if pod.Status.PodIP == "" {
			// No need to insert Pod IPAdddress when it is unset.
			continue
		}
		addresses.Insert(pod.Status.PodIP)
	}
	updatedAddressGroup := &antreatypes.AddressGroup{
		Name:      addressGroup.Name,
		UID:       addressGroup.UID,
		Selector:  addressGroup.Selector,
		Addresses: addresses,
		SpanMeta:  spanMeta,
	}
	klog.V(2).Infof("Updated AddressGroup %s with addresses %v and Node names %v", key, addresses, addrGroupNodeNames)
	// Update the store of AddressGroup.
	n.addressGroupStore.Update(updatedAddressGroup)
	return nil
}

// syncAppliedToGroup enqueues all the internal NetworkPolicy keys that
// refer this AppliedToGroup and update the AppliedToGroup Pod
// references by Node to reflect the latest set of affected Pods based
// on it's GroupSelector.
func (n *NetworkPolicyController) syncAppliedToGroup(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing AppliedToGroup %s. (%v)", key, time.Since(startTime))
	}()
	// Get all internal NetworkPolicy objects that refers this AppliedToGroup.
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AppliedToGroupIndex, key)
	if err != nil {
		return fmt.Errorf("unable to filter internal NetworkPolicies for AppliedToGroup %s: %v", key, err)
	}
	podsByNodes := make(map[string]antreatypes.PodSet)
	var pods []*v1.Pod
	appGroupNodeNames := sets.String{}
	appliedToGroupObj, found, err := n.appliedToGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("AppliedToGroup %s not found.", key)
		return nil
	}
	appliedToGroup := appliedToGroupObj.(*antreatypes.AppliedToGroup)
	// AppliedToGroup will not have NamespaceSelector.
	podSelector := appliedToGroup.Selector.PodSelector
	selector, _ := metav1.LabelSelectorAsSelector(podSelector)
	// Retrieve all Pods matching the podSelector.
	pods, err = n.podLister.Pods(appliedToGroup.Selector.Namespace).List(selector)
	for _, pod := range pods {
		if pod.Status.PodIP == "" {
			// No need to process Pod when IPAddress is unset.
			continue
		}
		podSet := podsByNodes[pod.Spec.NodeName]
		if podSet == nil {
			podSet = make(map[networkpolicy.PodReference]sets.Empty)
		}
		podRef := networkpolicy.PodReference{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		}
		podSet[podRef] = sets.Empty{}
		// Update the Pod references by Node.
		podsByNodes[pod.Spec.NodeName] = podSet
		// Update the NodeNames in order to set the SpanMeta for AppliedToGroup.
		appGroupNodeNames.Insert(pod.Spec.NodeName)
	}
	spanMeta := antreatypes.SpanMeta{
		NodeNames: appGroupNodeNames,
	}
	updatedAppliedToGroup := &antreatypes.AppliedToGroup{
		UID:        appliedToGroup.UID,
		Name:       appliedToGroup.Name,
		Selector:   appliedToGroup.Selector,
		PodsByNode: podsByNodes,
		SpanMeta:   spanMeta,
	}
	klog.V(2).Infof("Updating existing AppliedToGroup in store %s with Pods %v and Nodes %v", key, podsByNodes, updatedAppliedToGroup.SpanMeta)
	n.appliedToGroupStore.Update(updatedAppliedToGroup)
	// Enqueue syncInternalNetworkPolicy for each affected internal NetworkPolicy so
	// that corresponding Node spans are updated.
	for _, npObj := range nps {
		// Error can be ignored as npObj is of type antreatypes.NetworkPolicy.
		npKey, _ := store.NetworkPolicyKeyFunc(npObj)
		n.enqueueInternalNetworkPolicy(npKey)
	}
	return nil
}

// syncInternalNetworkPolicy retrieves all the AppliedToGroups associated with
// itself in order to calculate the Node span for this policy.
func (n *NetworkPolicyController) syncInternalNetworkPolicy(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing internal NetworkPolicy %s. (%v)", key, time.Since(startTime))
	}()
	klog.V(2).Infof("Syncing internal NetworkPolicy %s", key)
	nodeNames := sets.String{}
	// Lock the internal NetworkPolicy store as we may have a case where in the
	// same internal NetworkPolicy is being updated in the NetworkPolicy UPDATE
	// handler.
	n.internalNetworkPolicyMutex.Lock()
	internalNPObj, found, err := n.internalNetworkPolicyStore.Get(key)
	if !found {
		// Make sure to unlock the store before returning.
		n.internalNetworkPolicyMutex.Unlock()
		return fmt.Errorf("Internal NetworkPolicy %s not found: %v", key, err)
	}
	internalNP := internalNPObj.(*antreatypes.NetworkPolicy)
	// Maintain a copy of old SpanMeta Nodenames so we can later enqueue Groups
	// only if it is updated.
	oldNodeNames := internalNP.SpanMeta.NodeNames
	// Calculate the set of Node names based on the span of the
	// AppliedToGroups referenced by this NetworkPolicy.
	for _, appliedToGroupName := range internalNP.AppliedToGroups {
		appGroupObj, found, _ := n.appliedToGroupStore.Get(appliedToGroupName)
		if !found {
			continue
		}
		appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
		nodeNames = nodeNames.Union(appGroup.SpanMeta.NodeNames)
	}
	spanMeta := antreatypes.SpanMeta{
		NodeNames: nodeNames,
	}
	updatedNetworkPolicy := &antreatypes.NetworkPolicy{
		UID:             internalNP.UID,
		Name:            internalNP.Name,
		Namespace:       internalNP.Namespace,
		Rules:           internalNP.Rules,
		AppliedToGroups: internalNP.AppliedToGroups,
		SpanMeta:        spanMeta,
	}
	n.internalNetworkPolicyStore.Update(updatedNetworkPolicy)
	// Internal NetworkPolicy update is complete. Safe to unlock the
	// critical section.
	n.internalNetworkPolicyMutex.Unlock()
	klog.V(4).Infof("Updated internal NetworkPolicy %s with new Node names %v", key, nodeNames)
	if nodeNames.Equal(oldNodeNames) {
		// Node span for internal NetworkPolicy was not modified. No need to enqueue
		// AddressGroups.
		klog.V(4).Infof("Internal NetworkPolicy %s Node span remains unchanged. No need to enqueue AddressGroups.", key)
		return nil
	}
	// Enqueue addressGroup keys to update their Node span.
	for _, rule := range internalNP.Rules {
		for _, addrGroupName := range rule.From.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
		for _, addrGroupName := range rule.To.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
	}
	return nil
}

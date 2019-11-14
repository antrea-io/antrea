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

	// UUIDNamespace is a uuid.UUID type generated from a string to be
	// used to generate uuid.UUID for internal Antrea objects like
	// AppliedToGroup, AddressGroup etc.
	// 5a5e7dd9-e3fb-49bb-b263-9bab25c95841 was generated using
	// uuid.NewV4() function.
	UUIDNamespace = uuid.FromStringOrNil("5a5e7dd9-e3fb-49bb-b263-9bab25c95841")
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
	// networkPolicyQueue maintains the networkpolicy.NetworkPolicy objects that
	// need to be synced.
	networkPolicyQueue workqueue.RateLimitingInterface

	// queue maintains the Network Policies that need to be synced.
	queue workqueue.RateLimitingInterface

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
		networkPolicyQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalNetworkPolicy"),
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicy"),
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
			AddFunc: func(cur interface{}) {
			},
			UpdateFunc: func(old, cur interface{}) {
			},
			DeleteFunc: func(old interface{}) {
			},
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
// and NetworkPolicy Namespace to a GroupSelector
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

// normalizeExpr converts an expression in the form of "key1 OP [value1...]".
func normalizeExpr(key string, operator metav1.LabelSelectorOperator, values []string) string {
	if len(values) == 0 {
		return fmt.Sprintf("%s %s", key, operator)
	} else {
		return fmt.Sprintf("%s %s %s", key, operator, values)
	}
}

// selectorToString creates a string corresponding to a labelSelector in the form of
// "key1 IN [value1,...] AND key2 NotIn [value2,...] AND ..."
func selectorToString(selector *metav1.LabelSelector) string {
	selSlice := make([]string, 0, len(selector.MatchLabels)+len(selector.MatchExpressions))
	// emptyValue is a placeholder empty slice to send to normalizeExpr for Exists, NotExist operators
	var emptyValue []string
	// Append labels in matchLabels as "key In [value]"
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
	// Sort the slice
	sort.Strings(selSlice)
	normalizedStr := strings.Join(selSlice, " And ")
	return normalizedStr
}

// getNormalizedUID generates a unique UUID based on a given string.
// For example, it can be used to generate keys using normalized selectors
// unique within the Namespace by adding the constant UID.
func getNormalizedUID(name string) string {
	return uuid.NewV5(UUIDNamespace, name).String()
}

// generateNormalizedName generates a string, based on the selectors, in
// the following format: "namespace=NamespaceName AND podSelector=normalizedPodSelector".
// Note: namespace and nsSelector may or may not be set depending on the
// selector. However, they cannot be set simulataneously.
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

// labelsMatchGroupSelector matches a given resource's labels to the
// GroupSelector object and returns true, if and only if the labels
// match any of the selector criteria present in the GroupSelector.
func (n *NetworkPolicyController) labelsMatchGroupSelector(resLabels map[string]string, resNS *v1.Namespace, sel antreatypes.GroupSelector) bool {
	if sel.Namespace != "" {
		if sel.Namespace != resNS.Name {
			// Pods must be matched within the same Namespace.
			return false
		}
		// Convert labelSelector to a Selector.
		selector, _ := metav1.LabelSelectorAsSelector(sel.PodSelector)
		if !selector.Matches(labels.Set(resLabels)) {
			// podSelector does not match the Pod's labels.
			return false
		}
		// podSelector matches the Pod's labels.
		return true
	} else {
		// Selector is a multi-selector where Pods must be selected if namespaceSelector matches Pod's Namespace.
		// Convert Namespace labelSelector to a Selector.
		nSelector, _ := metav1.LabelSelectorAsSelector(sel.NamespaceSelector)
		// Check whether Pods Namespace matches nsSelector of AddressGroup.
		if !nSelector.Matches(labels.Set(resNS.Labels)) {
			// Pod's Namespace do not match namespaceSelector.
			return false
		}
		// Convert Pod labelSelector to a Selector.
		pSelector, _ := metav1.LabelSelectorAsSelector(sel.PodSelector)
		if !pSelector.Matches(labels.Set(resLabels)) {
			// Pod's Namespace matches namespaceSelector but Pod's labels do not match
			// the podSelector.
			return false
		}
		// Pod's Namespace matches namespaceSelector and Pod's labels matches
		// podSelector.
		return true
	}
}

// filterAddressGroupsForPod computes a list of AddressGroup keys which
// match the Pod's labels.
func (n *NetworkPolicyController) filterAddressGroupsForPod(pod *v1.Pod) sets.String {
	matchingKeySet := sets.String{}
	addressGroups := n.addressGroupStore.List()
	podNS, _ := n.namespaceLister.Get(pod.Namespace)
	for _, group := range addressGroups {
		addrGroup := group.(*antreatypes.AddressGroup)
		if n.labelsMatchGroupSelector(pod.Labels, podNS, addrGroup.Selector) {
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
		if n.labelsMatchGroupSelector(pod.Labels, podNS, appGroup.Selector) {
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
	// Get or create a AddressGroup for the generated UID
	_, found, _ := n.addressGroupStore.Get(normalizedUID)
	if found {
		return normalizedUID
	}
	// Create a AddressGroup object per Peer object
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
	ipNet, err := store.CIDRStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	exceptNets := []networkpolicy.IPNet{}
	for _, exc := range ipBlock.Except {
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
	// Process the NetworkPolicy spec.podSelector and create a corresponding AppliedToGroup.
	appliedToGroupKey := n.createAppliedToGroup(np)
	appliedToGroupNames := []string{appliedToGroupKey}
	inAddressGroupNames, outAddressGroupNames := []string{}, []string{}
	rules := make([]networkpolicy.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	// Compute NetworkPolicyRule for Ingress Rule.
	for _, ingressRule := range np.Spec.Ingress {
		ipBlocks := []networkpolicy.IPBlock{}
		for _, peer := range ingressRule.From {
			// A networking.NetworkPolicyPeer will either have an IPBlock or a
			// podSelector and/or namespaceSelector set.
			if peer.IPBlock != nil {
				ipBlock, err := toAntreaIPBlock(peer.IPBlock)
				if err != nil {
					klog.Errorf("Failure processing NetworkPolicy %s/%s ingress IPBlock CIDR: %v", np.ObjectMeta.Namespace, np.ObjectMeta.Name, err)
					continue
				}
				ipBlocks = append(ipBlocks, *ipBlock)
			} else {
				normalizedUID := n.createAddressGroup(peer, np)
				inAddressGroupNames = append(inAddressGroupNames, normalizedUID)
			}
		}
		fromAddress := networkpolicy.NetworkPolicyPeer{
			AddressGroups: inAddressGroupNames,
			IPBlocks:      ipBlocks,
		}
		rules = append(rules, networkpolicy.NetworkPolicyRule{
			Direction: networkpolicy.DirectionIn,
			From:      fromAddress,
			Services:  toAntreaServices(ingressRule.Ports),
		})
	}
	for _, egressRule := range np.Spec.Egress {
		ipBlocks := []networkpolicy.IPBlock{}
		for _, peer := range egressRule.To {
			// A networking.NetworkPolicyPeer will either have an IPBlock or a
			// podSelector and/or namespaceSelector set.
			if peer.IPBlock != nil {
				ipBlock, err := toAntreaIPBlock(peer.IPBlock)
				if err != nil {
					klog.Errorf("Failure processing NetworkPolicy %s/%s egress IPBlock CIDR: %v", np.ObjectMeta.Namespace, np.ObjectMeta.Name, err)
					continue
				}
				ipBlocks = append(ipBlocks, *ipBlock)
			} else {
				normalizedUID := n.createAddressGroup(peer, np)
				outAddressGroupNames = append(outAddressGroupNames, normalizedUID)
			}
		}
		toAddress := networkpolicy.NetworkPolicyPeer{
			AddressGroups: outAddressGroupNames,
			IPBlocks:      ipBlocks,
		}
		rules = append(rules, networkpolicy.NetworkPolicyRule{
			Direction: networkpolicy.DirectionOut,
			To:        toAddress,
			Services:  toAntreaServices(egressRule.Ports),
		})
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

// addNetworkPolicy receives NetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the nodes.
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
// which can be consumed by agents to configure corresponding rules on the nodes.
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
	// cause the SpanMeta member to be overriden with stale SpanMeta members
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
// which can be consumed by agents to delete corresponding rules on the nodes.
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
	// AppliedToGroup keys must be enqueued only if the Pod's Node has changed or
	// if Pod's label change causes it to match new Groups.
	if oldPod.Spec.NodeName != curPod.Spec.NodeName {
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
	n.networkPolicyQueue.Add(key)
}

// enqueueNetworkPolicy adds an object to the controller work queue
// obj could be an *v1.NetworkPolicy, or a DeletionFinalStateUnknown item.
func (n *NetworkPolicyController) enqueueNetworkPolicy(obj interface{}) {
	key, err := keyFunc(obj)
	if err != nil {
		klog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}

	n.queue.Add(key)
}

// Run begins watching and syncing of a NetworkPolicyController.
func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.queue.ShutDown()

	klog.Info("Starting NetworkPolicy controller")
	defer klog.Info("Shutting down NetworkPolicy controller")

	klog.Info("Waiting for caches to sync for NetworkPolicy controller")
	if !cache.WaitForCacheSync(stopCh, n.podListerSynced, n.namespaceListerSynced, n.networkPolicyListerSynced) {
		klog.Error("Unable to sync caches for NetworkPolicy controller")
		return
	}
	klog.Info("Caches are synced for NetworkPolicy controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.worker, time.Second, stopCh)
	}
	<-stopCh
}

// worker runs a worker thread that just dequeues items, processes them, and marks them done.
// It enforces that the syncNetworkPolicy is never invoked concurrently with the same key.
func (n *NetworkPolicyController) worker() {
	for n.processNextWorkItem() {
	}
}

// processNextWorkItem retrieves a NetworkPolicy object from the WorkQueue until a shutdown signal is received.
func (n *NetworkPolicyController) processNextWorkItem() bool {
	obj, quit := n.queue.Get()
	if quit {
		return false
	}
	// We defer the call to Done so that the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer n.queue.Done(obj)

	// We expect strings ("NamespaceName/NetworkPolicyName") to come off the workqueue.
	key, ok := obj.(string)
	if !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueueNetworkPolicy only enqueues strings.
		n.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	}
	err := n.syncNetworkPolicy(key)
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		n.queue.AddRateLimited(key)
		klog.Errorf("Error syncing NetworkPolicy %s, requeuing. Error: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	n.queue.Forget(key)
	return true
}

func (n *NetworkPolicyController) syncNetworkPolicy(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing NetworkPolicy %s. (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	networkPolicy, err := n.networkPolicyLister.NetworkPolicies(namespace).Get(name)
	if err != nil {
		return fmt.Errorf("failed to get NetworkPolicy %s: %v", key, err)
	}
	klog.V(2).Infof("Syncing NetworkPolicy %s: %v", key, networkPolicy.Spec.PodSelector)
	return nil
}

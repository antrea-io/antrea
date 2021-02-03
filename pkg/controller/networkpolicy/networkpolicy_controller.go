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
// and synchronize the GroupMembers and Namespaces affected by Network Policies and enforce
// their rules.

package networkpolicy

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	uuid "github.com/satori/go.uuid"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
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

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	corev1a2informers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/core/v1alpha2"
	secinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/security/v1alpha1"
	corev1a2listers "github.com/vmware-tanzu/antrea/pkg/client/listers/core/v1alpha2"
	seclisters "github.com/vmware-tanzu/antrea/pkg/client/listers/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/controller/metrics"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
	"github.com/vmware-tanzu/antrea/pkg/features"
)

const (
	controllerName = "NetworkPolicyController"
	// NetworkPolicyController is the only writer of the antrea network policy
	// storages and will keep re-enqueuing failed items until they succeed.
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of a NetworkPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a NetworkPolicy change.
	defaultWorkers = 4
	// Default rule priority for K8s NetworkPolicy rules.
	defaultRulePriority = -1
	// TierIndex is used to index ClusterNetworkPolicies by Tier names.
	TierIndex = "tier"
	// PriorityIndex is used to index Tiers by their priorities.
	PriorityIndex = "priority"
)

var (
	// uuidNamespace is a uuid.UUID type generated from a string to be
	// used to generate uuid.UUID for internal Antrea objects like
	// AppliedToGroup, AddressGroup etc.
	// e4f24a48-ca1f-4d5b-819c-ea7632b22115 was generated using
	// uuid.NewV4() function.
	uuidNamespace = uuid.FromStringOrNil("e4f24a48-ca1f-4d5b-819c-ea7632b22115")

	// matchAllPeer is a NetworkPolicyPeer matching all source/destination IP addresses. Both IPv4 Any (0.0.0.0/0) and
	// IPv6 Any (::/0) are added into the IPBlocks, and Antrea Agent should decide if both two are used according the
	// supported IP protocols configured in the cluster.
	matchAllPeer = controlplane.NetworkPolicyPeer{
		IPBlocks: []controlplane.IPBlock{
			{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv4zero), PrefixLength: 0}},
			{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.IPv6zero), PrefixLength: 0}},
		},
	}
	// matchAllPodsPeer is a networkingv1.NetworkPolicyPeer matching all Pods from all Namespaces.
	matchAllPodsPeer = networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{},
	}
	// denyAllIngressRule is a NetworkPolicyRule which denies all ingress traffic.
	denyAllIngressRule = controlplane.NetworkPolicyRule{Direction: controlplane.DirectionIn}
	// denyAllEgressRule is a NetworkPolicyRule which denies all egress traffic.
	denyAllEgressRule = controlplane.NetworkPolicyRule{Direction: controlplane.DirectionOut}
	// defaultAction is a RuleAction which sets the default Action for the NetworkPolicy rule.
	defaultAction = secv1alpha1.RuleActionAllow
)

// NetworkPolicyController is responsible for synchronizing the Namespaces and Pods
// affected by a Network Policy.
type NetworkPolicyController struct {
	// kubeClient is a standard Kubernetes clientset.
	kubeClient clientset.Interface
	// crdClient is the clientset for CRD API group.
	crdClient versioned.Interface

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

	externalEntityInformer corev1a2informers.ExternalEntityInformer
	// externalEntityLister is able to list/get ExternalEntities and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	externalEntityLister corev1a2listers.ExternalEntityLister
	// externalEntitySynced is a function which returns true if the ExternalEntity shared informer has been synced at least once.
	externalEntitySynced cache.InformerSynced

	networkPolicyInformer networkinginformers.NetworkPolicyInformer
	// networkPolicyLister is able to list/get Network Policies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	networkPolicyLister networkinglisters.NetworkPolicyLister
	// networkPolicyListerSynced is a function which returns true if the Network Policy shared informer has been synced at least once.
	networkPolicyListerSynced cache.InformerSynced

	cnpInformer secinformers.ClusterNetworkPolicyInformer
	// cnpLister is able to list/get AntreaClusterNetworkPolicies and is populated by the shared informer passed to
	// NewClusterNetworkPolicyController.
	cnpLister seclisters.ClusterNetworkPolicyLister
	// cnpListerSynced is a function which returns true if the AntreaClusterNetworkPolicies shared informer has been synced at least once.
	cnpListerSynced cache.InformerSynced

	anpInformer secinformers.NetworkPolicyInformer
	// anpLister is able to list/get AntreaNetworkPolicies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	anpLister seclisters.NetworkPolicyLister
	// anpListerSynced is a function which returns true if the AntreaNetworkPolicies shared informer has been synced at least once.
	anpListerSynced cache.InformerSynced

	tierInformer secinformers.TierInformer
	// tierLister is able to list/get Tiers and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	tierLister seclisters.TierLister
	// tierListerSynced is a function which returns true if the Tiers shared informer has been synced at least once.
	tierListerSynced cache.InformerSynced

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

	// heartbeatCh is an internal channel for testing. It's used to know whether all tasks have been
	// processed, and to count executions of each function.
	heartbeatCh chan heartbeat
}

type heartbeat struct {
	name      string
	timestamp time.Time
}

// NewNetworkPolicyController returns a new *NetworkPolicyController.
func NewNetworkPolicyController(kubeClient clientset.Interface,
	crdClient versioned.Interface,
	podInformer coreinformers.PodInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	externalEntityInformer corev1a2informers.ExternalEntityInformer,
	networkPolicyInformer networkinginformers.NetworkPolicyInformer,
	cnpInformer secinformers.ClusterNetworkPolicyInformer,
	anpInformer secinformers.NetworkPolicyInformer,
	tierInformer secinformers.TierInformer,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	internalNetworkPolicyStore storage.Interface) *NetworkPolicyController {
	n := &NetworkPolicyController{
		kubeClient:                 kubeClient,
		crdClient:                  crdClient,
		podInformer:                podInformer,
		podLister:                  podInformer.Lister(),
		podListerSynced:            podInformer.Informer().HasSynced,
		namespaceInformer:          namespaceInformer,
		namespaceLister:            namespaceInformer.Lister(),
		namespaceListerSynced:      namespaceInformer.Informer().HasSynced,
		externalEntityInformer:     externalEntityInformer,
		externalEntityLister:       externalEntityInformer.Lister(),
		externalEntitySynced:       externalEntityInformer.Informer().HasSynced,
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
		resyncPeriod,
	)
	// Add handlers for Namespace events.
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addNamespace,
			UpdateFunc: n.updateNamespace,
			DeleteFunc: n.deleteNamespace,
		},
		resyncPeriod,
	)
	// Add handlers for NetworkPolicy events.
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addNetworkPolicy,
			UpdateFunc: n.updateNetworkPolicy,
			DeleteFunc: n.deleteNetworkPolicy,
		},
		resyncPeriod,
	)
	// Register Informer and add handlers for AntreaPolicy events only if the feature is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		n.cnpInformer = cnpInformer
		n.cnpLister = cnpInformer.Lister()
		n.cnpListerSynced = cnpInformer.Informer().HasSynced
		n.anpInformer = anpInformer
		n.anpLister = anpInformer.Lister()
		n.anpListerSynced = anpInformer.Informer().HasSynced
		n.tierInformer = tierInformer
		n.tierLister = tierInformer.Lister()
		n.tierListerSynced = tierInformer.Informer().HasSynced
		tierInformer.Informer().AddIndexers(
			cache.Indexers{
				PriorityIndex: func(obj interface{}) ([]string, error) {
					tr, ok := obj.(*secv1alpha1.Tier)
					if !ok {
						return []string{}, nil
					}
					return []string{strconv.FormatInt(int64(tr.Spec.Priority), 10)}, nil
				},
			},
		)
		cnpInformer.Informer().AddIndexers(
			cache.Indexers{
				TierIndex: func(obj interface{}) ([]string, error) {
					cnp, ok := obj.(*secv1alpha1.ClusterNetworkPolicy)
					if !ok {
						return []string{}, nil
					}
					return []string{cnp.Spec.Tier}, nil
				},
			},
		)
		cnpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addCNP,
				UpdateFunc: n.updateCNP,
				DeleteFunc: n.deleteCNP,
			},
			resyncPeriod,
		)
		anpInformer.Informer().AddIndexers(
			cache.Indexers{
				TierIndex: func(obj interface{}) ([]string, error) {
					anp, ok := obj.(*secv1alpha1.NetworkPolicy)
					if !ok {
						return []string{}, nil
					}
					return []string{anp.Spec.Tier}, nil
				},
			},
		)
		anpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addANP,
				UpdateFunc: n.updateANP,
				DeleteFunc: n.deleteANP,
			},
			resyncPeriod,
		)
		externalEntityInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addExternalEntity,
				UpdateFunc: n.updateExternalEntity,
				DeleteFunc: n.deleteExternalEntity,
			},
			resyncPeriod,
		)
	}
	return n
}

func (n *NetworkPolicyController) heartbeat(name string) {
	if n.heartbeatCh != nil {
		n.heartbeatCh <- heartbeat{
			name:      name,
			timestamp: time.Now(),
		}
	}
}

func (n *NetworkPolicyController) GetNetworkPolicyNum() int {
	return len(n.internalNetworkPolicyStore.List())
}

func (n *NetworkPolicyController) GetAddressGroupNum() int {
	return len(n.addressGroupStore.List())
}

func (n *NetworkPolicyController) GetAppliedToGroupNum() int {
	return len(n.appliedToGroupStore.List())
}

// GetConnectedAgentNum gets the number of Agents which are connected to this Controller.
// Since Agent will watch all the three stores (internalNetworkPolicyStore, appliedToGroupStore, addressGroupStore),
// the number of watchers of one of these three stores is equal to the number of connected Agents.
// Here, we uses the number of watchers of appliedToGroupStore to represent the number of connected Agents as
// internalNetworkPolicyStore is also watched by the StatusController of the process itself.
func (n *NetworkPolicyController) GetConnectedAgentNum() int {
	return n.appliedToGroupStore.GetWatchersNum()
}

// toGroupSelector converts the podSelector, namespaceSelector and externalEntitySelector
// and NetworkPolicy Namespace to a networkpolicy.GroupSelector object.
func toGroupSelector(namespace string, podSelector, nsSelector, extEntitySelector *metav1.LabelSelector) *antreatypes.GroupSelector {
	groupSelector := antreatypes.GroupSelector{}
	if podSelector != nil {
		pSelector, _ := metav1.LabelSelectorAsSelector(podSelector)
		groupSelector.PodSelector = pSelector
	}
	if extEntitySelector != nil {
		eSelector, _ := metav1.LabelSelectorAsSelector(extEntitySelector)
		groupSelector.ExternalEntitySelector = eSelector
	}
	if nsSelector == nil {
		// No namespaceSelector indicates that the pods must be selected within
		// the NetworkPolicy's Namespace.
		groupSelector.Namespace = namespace
	} else {
		nSelector, _ := metav1.LabelSelectorAsSelector(nsSelector)
		groupSelector.NamespaceSelector = nSelector
	}
	name := generateNormalizedName(groupSelector.Namespace, groupSelector.PodSelector, groupSelector.NamespaceSelector, groupSelector.ExternalEntitySelector)
	groupSelector.NormalizedName = name
	return &groupSelector
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
func generateNormalizedName(namespace string, podSelector, nsSelector, eeSelector labels.Selector) string {
	normalizedName := []string{}
	if nsSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("namespaceSelector=%s", nsSelector.String()))
	} else if namespace != "" {
		normalizedName = append(normalizedName, fmt.Sprintf("namespace=%s", namespace))
	}
	if podSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("podSelector=%s", podSelector.String()))
	}
	if eeSelector != nil {
		normalizedName = append(normalizedName, fmt.Sprintf("eeSelector=%s", eeSelector.String()))
	}
	sort.Strings(normalizedName)
	return strings.Join(normalizedName, " And ")
}

// createAppliedToGroup creates an AppliedToGroup object in store if it is not created already.
func (n *NetworkPolicyController) createAppliedToGroup(npNsName string, pSel, nSel, eSel *metav1.LabelSelector) string {
	groupSelector := toGroupSelector(npNsName, pSel, nSel, eSel)
	appliedToGroupUID := getNormalizedUID(groupSelector.NormalizedName)
	// Get or create a AppliedToGroup for the generated UID.
	// Ignoring returned error (here and elsewhere in this file) as with the
	// current store implementation, no error is ever returned.
	_, found, _ := n.appliedToGroupStore.Get(appliedToGroupUID)
	if found {
		return appliedToGroupUID
	}
	// Construct a new AppliedToGroup.
	newAppliedToGroup := &antreatypes.AppliedToGroup{
		Name:     appliedToGroupUID,
		UID:      types.UID(appliedToGroupUID),
		Selector: *groupSelector,
	}
	klog.V(2).Infof("Creating new AppliedToGroup %s with selector (%s)", newAppliedToGroup.Name, newAppliedToGroup.Selector.NormalizedName)
	n.appliedToGroupStore.Create(newAppliedToGroup)
	n.enqueueAppliedToGroup(appliedToGroupUID)
	return appliedToGroupUID
}

// labelsMatchGroupSelector matches an ExternalEntity or Pod's labels to the
// GroupSelector object and returns true, if and only if the labels
// match any of the selector criteria present in the GroupSelector.
func (n *NetworkPolicyController) labelsMatchGroupSelector(obj metav1.Object, ns *v1.Namespace, sel *antreatypes.GroupSelector) bool {
	objSelector := sel.ExternalEntitySelector
	if _, ok := obj.(*v1.Pod); ok {
		objSelector = sel.PodSelector
	}
	if sel.Namespace != "" {
		if sel.Namespace != obj.GetNamespace() {
			// Pods or ExternalEntities must be matched within the same Namespace.
			return false
		}
		if objSelector != nil && objSelector.Matches(labels.Set(obj.GetLabels())) {
			// podSelector or externalEntitySelector matches the ExternalEntity or Pod's labels.
			return true
		}
		// selector does not match the ExternalEntity or Pod's labels.
		return false
	} else if sel.NamespaceSelector != nil && objSelector != nil {
		// Pod or ExternalEntity event may arrive before Namespace event. In this case, we must
		// ensure that the Namespace is not nil.
		if ns == nil || !sel.NamespaceSelector.Matches(labels.Set(ns.Labels)) {
			// Pod's Namespace do not match namespaceSelector.
			return false
		}
		if !objSelector.Matches(labels.Set(obj.GetLabels())) {
			// ExternalEntity or Pod's Namespace matches namespaceSelector but
			// labels do not match the podSelector or externalEntitySelector.
			return false
		}
		// ExternalEntity or Pod's Namespace matches namespaceSelector and labels matches
		// podSelector or externalEntitySelector.
		return true
	} else if sel.NamespaceSelector != nil && sel.ExternalEntitySelector == nil && sel.PodSelector == nil {
		// Selector only has a NamespaceSelector.
		// Pod or ExternalEntity event may arrive before Namespace event. In this case, we must
		// ensure that the Namespace is not nil.
		if ns == nil || !sel.NamespaceSelector.Matches(labels.Set(ns.Labels)) {
			// Namespace labels do not match namespaceSelector.
			return false
		}
		// Namespace labels match namespaceSelector.
		return true
	} else if objSelector != nil {
		// Selector only has a PodSelector/ExternalEntitySelector and no sel.Namespace.
		// Pods/ExternalEntities must be matched from all Namespaces.
		if !objSelector.Matches(labels.Set(obj.GetLabels())) {
			// pod/ee labels do not match PodSelector/ExternalEntitySelector.
			return false
		}
		return true
	}
	return false
}

// filterAddressGroupsForNamespace computes a list of AddressGroup keys which
// match the Namespace's labels.
func (n *NetworkPolicyController) filterAddressGroupsForNamespace(namespace *v1.Namespace) sets.String {
	matchingKeys := sets.String{}
	// Only cluster scoped groups or AddressGroups created by CNP can possibly select this Namespace.
	addressGroups, _ := n.addressGroupStore.GetByIndex(cache.NamespaceIndex, "")
	for _, group := range addressGroups {
		addrGroup := group.(*antreatypes.AddressGroup)
		// AddressGroup created by CNP might not have NamespaceSelector.
		if addrGroup.Selector.NamespaceSelector != nil && addrGroup.Selector.NamespaceSelector.Matches(labels.Set(namespace.Labels)) {
			matchingKeys.Insert(addrGroup.Name)
			klog.V(2).Infof("Namespace %s matched AddressGroup %s", namespace.Name, addrGroup.Name)
		}
	}
	return matchingKeys
}

// filterAddressGroupsForPodOrExternalEntity computes a list of AddressGroup keys which
// match the ExternalEntity or Pod's labels.
func (n *NetworkPolicyController) filterAddressGroupsForPodOrExternalEntity(obj metav1.Object) sets.String {
	matchingKeySet := sets.String{}
	// AddressGroups that are in this namespace or that are cluster scoped can possibly select this Pod/ExternalEntity.
	localAddressGroups, _ := n.addressGroupStore.GetByIndex(cache.NamespaceIndex, obj.GetNamespace())
	clusterScopedAddressGroups, _ := n.addressGroupStore.GetByIndex(cache.NamespaceIndex, "")
	ns, _ := n.namespaceLister.Get(obj.GetNamespace())
	for _, group := range append(localAddressGroups, clusterScopedAddressGroups...) {
		addrGroup := group.(*antreatypes.AddressGroup)
		if n.labelsMatchGroupSelector(obj, ns, &addrGroup.Selector) {
			matchingKeySet.Insert(addrGroup.Name)
			klog.V(2).Infof("%s/%s matched AddressGroup %s", obj.GetNamespace(), obj.GetName(), addrGroup.Name)
		}
	}
	return matchingKeySet
}

// filterAppliedToGroupsForPodOrExternalEntity computes a list of AppliedToGroup keys which
// match the ExternalEntity or Pod's labels.
func (n *NetworkPolicyController) filterAppliedToGroupsForPodOrExternalEntity(obj metav1.Object) sets.String {
	matchingKeySet := sets.String{}
	// Get appliedToGroups from the namespace level
	appliedToGroups, _ := n.appliedToGroupStore.GetByIndex(cache.NamespaceIndex, obj.GetNamespace())
	// Get appliedToGroups from the cluster level
	clusterATGroups, _ := n.appliedToGroupStore.GetByIndex(cache.NamespaceIndex, "")
	appliedToGroups = append(appliedToGroups, clusterATGroups...)
	ns, _ := n.namespaceLister.Get(obj.GetNamespace())
	for _, group := range appliedToGroups {
		appGroup := group.(*antreatypes.AppliedToGroup)
		if n.labelsMatchGroupSelector(obj, ns, &appGroup.Selector) {
			matchingKeySet.Insert(appGroup.Name)
			klog.V(2).Infof("%s/%s matched AppliedToGroup %s", obj.GetNamespace(), obj.GetName(), appGroup.Name)
		}
	}
	return matchingKeySet
}

// createAddressGroup creates an AddressGroup object corresponding to a
// NetworkPolicyPeer object in NetworkPolicyRule. This function simply
// creates the object without actually populating the PodAddresses as the
// affected GroupMembers are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroup(peer networkingv1.NetworkPolicyPeer, np *networkingv1.NetworkPolicy) string {
	groupSelector := toGroupSelector(np.ObjectMeta.Namespace, peer.PodSelector, peer.NamespaceSelector, nil)
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
	klog.V(2).Infof("Creating new AddressGroup %s with selector (%s)", addressGroup.Name, addressGroup.Selector.NormalizedName)
	n.addressGroupStore.Create(addressGroup)
	return normalizedUID
}

// toAntreaProtocol converts a v1.Protocol object to an Antrea Protocol object.
func toAntreaProtocol(npProtocol *v1.Protocol) *controlplane.Protocol {
	// If Protocol is unset, it must default to TCP protocol.
	internalProtocol := controlplane.ProtocolTCP
	if npProtocol != nil {
		internalProtocol = controlplane.Protocol(*npProtocol)
	}
	return &internalProtocol
}

// toAntreaServices converts a slice of networkingv1.NetworkPolicyPort objects
// to a slice of Antrea Service objects. A bool is returned along with the
// Service objects to indicate whether any named port exists.
func toAntreaServices(npPorts []networkingv1.NetworkPolicyPort) ([]controlplane.Service, bool) {
	var antreaServices []controlplane.Service
	var namedPortExists bool
	for _, npPort := range npPorts {
		if npPort.Port != nil && npPort.Port.Type == intstr.String {
			namedPortExists = true
		}
		antreaService := controlplane.Service{
			Protocol: toAntreaProtocol(npPort.Protocol),
			Port:     npPort.Port,
		}
		antreaServices = append(antreaServices, antreaService)
	}
	return antreaServices, namedPortExists
}

// toAntreaIPBlock converts a networkingv1.IPBlock to an Antrea IPBlock.
func toAntreaIPBlock(ipBlock *networkingv1.IPBlock) (*controlplane.IPBlock, error) {
	// Convert the allowed IPBlock to networkpolicy.IPNet.
	ipNet, err := cidrStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	exceptNets := []controlplane.IPNet{}
	for _, exc := range ipBlock.Except {
		// Convert the except IPBlock to networkpolicy.IPNet.
		exceptNet, err := cidrStrToIPNet(exc)
		if err != nil {
			return nil, err
		}
		exceptNets = append(exceptNets, *exceptNet)
	}
	antreaIPBlock := &controlplane.IPBlock{
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
	appliedToGroupKey := n.createAppliedToGroup(np.Namespace, &np.Spec.PodSelector, nil, nil)
	appliedToGroupNames := []string{appliedToGroupKey}
	rules := make([]controlplane.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	var ingressRuleExists, egressRuleExists bool
	// Compute NetworkPolicyRule for Ingress Rule.
	for _, ingressRule := range np.Spec.Ingress {
		ingressRuleExists = true
		services, namedPortExists := toAntreaServices(ingressRule.Ports)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:     controlplane.DirectionIn,
			From:          *n.toAntreaPeer(ingressRule.From, np, controlplane.DirectionIn, namedPortExists),
			Services:      services,
			Priority:      defaultRulePriority,
			Action:        &defaultAction,
			EnableLogging: false,
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for _, egressRule := range np.Spec.Egress {
		egressRuleExists = true
		services, namedPortExists := toAntreaServices(egressRule.Ports)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:     controlplane.DirectionOut,
			To:            *n.toAntreaPeer(egressRule.To, np, controlplane.DirectionOut, namedPortExists),
			Services:      services,
			Priority:      defaultRulePriority,
			Action:        &defaultAction,
			EnableLogging: false,
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
		Name: internalNetworkPolicyKeyFunc(np),
		UID:  np.UID,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.K8sNetworkPolicy,
			Namespace: np.Namespace,
			Name:      np.Name,
			UID:       np.UID,
		},
		AppliedToGroups: appliedToGroupNames,
		Rules:           rules,
		Generation:      np.Generation,
	}
	return internalNetworkPolicy
}

func (n *NetworkPolicyController) toAntreaPeer(peers []networkingv1.NetworkPolicyPeer, np *networkingv1.NetworkPolicy, dir controlplane.Direction, namedPortExists bool) *controlplane.NetworkPolicyPeer {
	var addressGroups []string
	// Empty NetworkPolicyPeer is supposed to match all addresses.
	// See https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-allow-all-ingress-traffic.
	// It's treated as an IPBlock "0.0.0.0/0".
	if len(peers) == 0 {
		// For an egress Peer that specifies any named ports, it creates or
		// reuses the AddressGroup matching all Pods in all Namespaces and
		// appends the AddressGroup UID to the returned Peer such that it can be
		// used to resolve the named ports.
		// For other cases it uses the IPBlock "0.0.0.0/0" to avoid the overhead
		// of handling member updates of the AddressGroup.
		if dir == controlplane.DirectionIn || !namedPortExists {
			return &matchAllPeer
		}
		allPodsGroupUID := n.createAddressGroup(matchAllPodsPeer, np)
		podsPeer := matchAllPeer
		podsPeer.AddressGroups = append(addressGroups, allPodsGroupUID)
		return &podsPeer
	}
	var ipBlocks []controlplane.IPBlock
	for _, peer := range peers {
		// A controlplane.NetworkPolicyPeer will either have an IPBlock or a
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
	return &controlplane.NetworkPolicyPeer{AddressGroups: addressGroups, IPBlocks: ipBlocks}
}

// addNetworkPolicy receives NetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addNetworkPolicy(obj interface{}) {
	defer n.heartbeat("addNetworkPolicy")
	np := obj.(*networkingv1.NetworkPolicy)
	klog.Infof("Processing K8s NetworkPolicy %s/%s ADD event", np.Namespace, np.Name)
	// Create an internal NetworkPolicy object corresponding to this NetworkPolicy
	// and enqueue task to internal NetworkPolicy Workqueue.
	internalNP := n.processNetworkPolicy(np)
	klog.V(2).Infof("Creating new internal NetworkPolicy %s for %s", internalNP.Name, internalNP.SourceRef.ToString())
	n.internalNetworkPolicyStore.Create(internalNP)
	key := internalNetworkPolicyKeyFunc(np)
	n.enqueueInternalNetworkPolicy(key)
}

// updateNetworkPolicy receives NetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateNetworkPolicy(old, cur interface{}) {
	defer n.heartbeat("updateNetworkPolicy")
	np := cur.(*networkingv1.NetworkPolicy)
	klog.Infof("Processing K8s NetworkPolicy %s/%s UPDATE event", np.Namespace, np.Name)
	// Update an internal NetworkPolicy ID, corresponding to this NetworkPolicy and
	// enqueue task to internal NetworkPolicy Workqueue.
	curInternalNP := n.processNetworkPolicy(np)
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s for %s", curInternalNP.Name, curInternalNP.SourceRef.ToString())
	// Retrieve old networkingv1.NetworkPolicy object.
	oldNP := old.(*networkingv1.NetworkPolicy)
	// Old and current NetworkPolicy share the same key.
	key := internalNetworkPolicyKeyFunc(oldNP)
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
	np, ok := old.(*networkingv1.NetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting NetworkPolicy, invalid type: %v", old)
			return
		}
		np, ok = tombstone.Obj.(*networkingv1.NetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting NetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteNetworkPolicy")

	klog.Infof("Processing K8s NetworkPolicy %s/%s DELETE event", np.Namespace, np.Name)
	key := internalNetworkPolicyKeyFunc(np)
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	// AppliedToGroups currently only supports a single member.
	oldAppliedToGroupUID := oldInternalNP.AppliedToGroups[0]
	klog.Infof("Deleting internal NetworkPolicy %s for %s", oldInternalNP.Name, oldInternalNP.SourceRef.ToString())
	// Delete corresponding internal NetworkPolicy from store.
	err := n.internalNetworkPolicyStore.Delete(key)
	if err != nil {
		klog.Errorf("Error deleting internal NetworkPolicy during NetworkPolicy %s/%s delete: %v", np.Namespace, np.Name, err)
		return
	}
	n.deleteDereferencedAppliedToGroup(oldAppliedToGroupUID)
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// addPod retrieves all AddressGroups and AppliedToGroups which match the Pod's
// labels and enqueues the groups key for further processing.
func (n *NetworkPolicyController) addPod(obj interface{}) {
	defer n.heartbeat("addPod")
	pod := obj.(*v1.Pod)
	klog.V(2).Infof("Processing Pod %s/%s ADD event, labels: %v", pod.Namespace, pod.Name, pod.Labels)
	// Find all AppliedToGroup keys which match the Pod's labels.
	appliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(pod)
	// Find all AddressGroup keys which match the Pod's labels.
	addressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(pod)
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
	defer n.heartbeat("updatePod")
	oldPod := oldObj.(*v1.Pod)
	curPod := curObj.(*v1.Pod)
	klog.V(2).Infof("Processing Pod %s/%s UPDATE event, labels: %v", curPod.Namespace, curPod.Name, curPod.Labels)
	// No need to trigger processing of groups if there is no change in the
	// Pod labels or Pods Node or Pods IP.
	labelsEqual := labels.Equals(labels.Set(oldPod.Labels), labels.Set(curPod.Labels))
	if labelsEqual && oldPod.Spec.NodeName == curPod.Spec.NodeName && oldPod.Status.PodIP == curPod.Status.PodIP {
		klog.V(4).Infof("No change in Pod %s/%s. Skipping NetworkPolicy evaluation.", curPod.Namespace, curPod.Name)
		return
	}
	// Find groups matching the old Pod's labels.
	oldAddressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(oldPod)
	oldAppliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(oldPod)
	// Find groups matching the new Pod's labels.
	curAppliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(curPod)
	curAddressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(curPod)
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
	pod, ok := old.(*v1.Pod)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Pod, invalid type: %v", old)
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Pod, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deletePod")

	klog.V(2).Infof("Processing Pod %s/%s DELETE event, labels: %v", pod.Namespace, pod.Name, pod.Labels)
	// Find all AppliedToGroup keys which match the Pod's labels.
	appliedToGroupKeys := n.filterAppliedToGroupsForPodOrExternalEntity(pod)
	// Find all AddressGroup keys which match the Pod's labels.
	addressGroupKeys := n.filterAddressGroupsForPodOrExternalEntity(pod)
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
	defer n.heartbeat("addNamespace")
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s ADD event, labels: %v", namespace.Name, namespace.Labels)
	addressGroupKeys := n.filterAddressGroupsForNamespace(namespace)
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// updateNamespace retrieves all AddressGroups which match the current and old
// Namespace labels and enqueues the group keys for further processing.
func (n *NetworkPolicyController) updateNamespace(oldObj, curObj interface{}) {
	defer n.heartbeat("updateNamespace")
	oldNamespace := oldObj.(*v1.Namespace)
	curNamespace := curObj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s UPDATE event, labels: %v", curNamespace.Name, curNamespace.Labels)
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
	// No need to enqueue common AddressGroups as they already have latest
	// Namespace information.
	addressGroupKeys := oldAddressGroupKeySet.Difference(curAddressGroupKeySet).Union(curAddressGroupKeySet.Difference(oldAddressGroupKeySet))
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// deleteNamespace retrieves all AddressGroups which match the Namespace's
// labels and enqueues the group keys for further processing.
func (n *NetworkPolicyController) deleteNamespace(old interface{}) {
	namespace, ok := old.(*v1.Namespace)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Namespace, invalid type: %v", old)
			return
		}
		namespace, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Namespace, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteNamespace")

	klog.V(2).Infof("Processing Namespace %s DELETE event, labels: %v", namespace.Name, namespace.Labels)
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
	metrics.LengthAppliedToGroupQueue.Set(float64(n.appliedToGroupQueue.Len()))
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
	metrics.LengthAddressGroupQueue.Set(float64(n.addressGroupQueue.Len()))
}

func (n *NetworkPolicyController) enqueueInternalNetworkPolicy(key string) {
	klog.V(4).Infof("Adding new key %s to internal NetworkPolicy queue", key)
	n.internalNetworkPolicyQueue.Add(key)
	metrics.LengthInternalNetworkPolicyQueue.Set(float64(n.internalNetworkPolicyQueue.Len()))
}

// Run begins watching and syncing of a NetworkPolicyController.
func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.appliedToGroupQueue.ShutDown()
	defer n.addressGroupQueue.ShutDown()
	defer n.internalNetworkPolicyQueue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{n.podListerSynced, n.namespaceListerSynced, n.networkPolicyListerSynced}
	// Only wait for cnpListerSynced and anpListerSynced when AntreaPolicy feature gate is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		cacheSyncs = append(cacheSyncs, n.cnpListerSynced, n.anpListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.appliedToGroupWorker, time.Second, stopCh)
		go wait.Until(n.addressGroupWorker, time.Second, stopCh)
		go wait.Until(n.internalNetworkPolicyWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (n *NetworkPolicyController) appliedToGroupWorker() {
	for n.processNextAppliedToGroupWorkItem() {
		metrics.OpsAppliedToGroupProcessed.Inc()
		metrics.LengthAppliedToGroupQueue.Set(float64(n.appliedToGroupQueue.Len()))
	}
}

func (n *NetworkPolicyController) addressGroupWorker() {
	for n.processNextAddressGroupWorkItem() {
		metrics.OpsAddressGroupProcessed.Inc()
		metrics.LengthAddressGroupQueue.Set(float64(n.addressGroupQueue.Len()))
	}
}

func (n *NetworkPolicyController) internalNetworkPolicyWorker() {
	for n.processNextInternalNetworkPolicyWorkItem() {
		metrics.OpsInternalNetworkPolicyProcessed.Inc()
		metrics.LengthInternalNetworkPolicyQueue.Set(float64(n.internalNetworkPolicyQueue.Len()))
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
	defer n.heartbeat("processNextInternalNetworkPolicyWorkItem")
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
	defer n.heartbeat("processNextAddressGroupWorkItem")
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
	defer n.heartbeat("processNextAppliedToGroupWorkItem")
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
// reflect the current state of affected GroupMembers based on the GroupSelector.
func (n *NetworkPolicyController) syncAddressGroup(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.DurationAddressGroupSyncing.Observe(float64(d.Milliseconds()))
		klog.V(2).Infof("Finished syncing AddressGroup %s. (%v)", key, d)
	}()
	// Get all internal NetworkPolicy objects that refers this AddressGroup.
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AddressGroupIndex, key)
	if err != nil {
		return fmt.Errorf("unable to filter internal NetworkPolicies for AddressGroup %s: %v", key, err)
	}
	addressGroupObj, found, _ := n.addressGroupStore.Get(key)
	if !found {
		// AddressGroup was already deleted. No need to process further.
		klog.V(2).Infof("AddressGroup %s not found.", key)
		return nil
	}
	addressGroup := addressGroupObj.(*antreatypes.AddressGroup)
	// NodeNames set must be considered immutable once generated and updated
	// in the store. If any change is needed, the set must be regenerated with
	// the new NodeNames and the store must be updated.
	addrGroupNodeNames := sets.String{}
	for _, internalNPObj := range nps {
		internalNP := internalNPObj.(*antreatypes.NetworkPolicy)
		addrGroupNodeNames = addrGroupNodeNames.Union(internalNP.SpanMeta.NodeNames)
	}
	// Find all Pods and ExternalEntities matching its selectors and update store.
	groupSelector := addressGroup.Selector
	pods, externalEntities := n.processSelector(groupSelector)
	memberSet := controlplane.GroupMemberSet{}
	for _, pod := range pods {
		if len(pod.Status.PodIPs) == 0 {
			// No need to insert Pod IPAddress when it is unset.
			continue
		}
		memberSet.Insert(podToGroupMember(pod, true))
	}
	for _, entity := range externalEntities {
		memberSet.Insert(externalEntityToGroupMember(entity))
	}
	updatedAddressGroup := &antreatypes.AddressGroup{
		Name:         addressGroup.Name,
		UID:          addressGroup.UID,
		Selector:     addressGroup.Selector,
		GroupMembers: memberSet,
		SpanMeta:     antreatypes.SpanMeta{NodeNames: addrGroupNodeNames},
	}
	klog.V(2).Infof("Updating existing AddressGroup %s with %d Pods/ExternalEntities and %d Nodes", key, len(memberSet), addrGroupNodeNames.Len())
	n.addressGroupStore.Update(updatedAddressGroup)
	return nil
}

// podToGroupMember is util function to convert a Pod to a GroupMember type.
// A controlplane.NamedPort item will be set in the GroupMember, only if the
// Pod contains a Port with the name field set. PodReference will also be set
// for converting GroupMember to GroupMemberPod for clients using older version
// of the controlplane API.
func podToGroupMember(pod *v1.Pod, includeIP bool) *controlplane.GroupMember {
	memberPod := &controlplane.GroupMember{}
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			// Only include container ports with name set.
			if port.Name != "" {
				memberPod.Ports = append(memberPod.Ports, controlplane.NamedPort{
					Port:     port.ContainerPort,
					Name:     port.Name,
					Protocol: controlplane.Protocol(port.Protocol),
				})
			}
		}
	}
	if includeIP {
		for _, podIP := range pod.Status.PodIPs {
			memberPod.IPs = append(memberPod.IPs, ipStrToIPAddress(podIP.IP))
		}
	}
	podRef := controlplane.PodReference{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}
	memberPod.Pod = &podRef
	return memberPod
}

func externalEntityToGroupMember(ee *v1alpha2.ExternalEntity) *controlplane.GroupMember {
	memberEntity := &controlplane.GroupMember{}
	namedPorts := make([]controlplane.NamedPort, len(ee.Spec.Ports))
	var ips []controlplane.IPAddress
	for i, port := range ee.Spec.Ports {
		namedPorts[i] = controlplane.NamedPort{
			Port:     port.Port,
			Name:     port.Name,
			Protocol: controlplane.Protocol(port.Protocol),
		}
	}
	for _, ep := range ee.Spec.Endpoints {
		ips = append(ips, ipStrToIPAddress(ep.IP))
	}
	eeRef := controlplane.ExternalEntityReference{
		Name:      ee.Name,
		Namespace: ee.Namespace,
	}
	memberEntity.ExternalEntity = &eeRef
	memberEntity.Ports = namedPorts
	memberEntity.IPs = ips
	return memberEntity
}

func (n *NetworkPolicyController) processSelector(groupSelector antreatypes.GroupSelector) ([]*v1.Pod, []*v1alpha2.ExternalEntity) {
	var pods []*v1.Pod
	var externalEntities []*v1alpha2.ExternalEntity
	if groupSelector.Namespace != "" {
		// Namespace presence indicates Pods and ExternalEnitities must be selected from the same Namespace.
		if groupSelector.PodSelector != nil {
			pods, _ = n.podLister.Pods(groupSelector.Namespace).List(groupSelector.PodSelector)
		} else if groupSelector.ExternalEntitySelector != nil {
			externalEntities, _ = n.externalEntityLister.ExternalEntities(groupSelector.Namespace).List(groupSelector.ExternalEntitySelector)
		}
	} else if groupSelector.NamespaceSelector != nil && (groupSelector.PodSelector != nil || groupSelector.ExternalEntitySelector != nil) {
		// Pods and ExternalEntities must be selected from Namespaces matching nsSelector.
		namespaces, _ := n.namespaceLister.List(groupSelector.NamespaceSelector)
		for _, ns := range namespaces {
			if groupSelector.PodSelector != nil {
				nsPods, _ := n.podLister.Pods(ns.Name).List(groupSelector.PodSelector)
				pods = append(pods, nsPods...)
			} else if groupSelector.ExternalEntitySelector != nil {
				nsExtEntities, _ := n.externalEntityLister.ExternalEntities(ns.Name).List(groupSelector.ExternalEntitySelector)
				externalEntities = append(externalEntities, nsExtEntities...)
			}
		}
	} else if groupSelector.NamespaceSelector != nil {
		// All the Pods from Namespaces matching the nsSelector must be selected.
		namespaces, _ := n.namespaceLister.List(groupSelector.NamespaceSelector)
		for _, ns := range namespaces {
			nsPods, _ := n.podLister.Pods(ns.Name).List(labels.Everything())
			pods = append(pods, nsPods...)
		}
	} else if groupSelector.PodSelector != nil {
		// Lack of Namespace and NamespaceSelector indicates Pods must be selected
		// from all Namespaces.
		pods, _ = n.podLister.Pods("").List(groupSelector.PodSelector)
	} else if groupSelector.ExternalEntitySelector != nil {
		externalEntities, _ = n.externalEntityLister.ExternalEntities("").List(groupSelector.ExternalEntitySelector)
	}
	return pods, externalEntities
}

// syncAppliedToGroup enqueues all the internal NetworkPolicy keys that
// refer this AppliedToGroup and update the AppliedToGroup Pod
// references by Node to reflect the latest set of affected GroupMembers based
// on it's GroupSelector.
func (n *NetworkPolicyController) syncAppliedToGroup(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.DurationAppliedToGroupSyncing.Observe(float64(d.Milliseconds()))
		klog.V(2).Infof("Finished syncing AppliedToGroup %s. (%v)", key, d)
	}()
	var pods []*v1.Pod
	appGroupNodeNames := sets.String{}
	appliedToGroupObj, found, _ := n.appliedToGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("AppliedToGroup %s not found.", key)
		return nil
	}
	memberSetByNode := make(map[string]controlplane.GroupMemberSet)
	scheduledPodNum, scheduledExtEntityNum := 0, 0

	appliedToGroup := appliedToGroupObj.(*antreatypes.AppliedToGroup)
	groupSelector := appliedToGroup.Selector
	pods, externalEntities := n.processSelector(groupSelector)
	for _, pod := range pods {
		if pod.Spec.NodeName == "" {
			// No need to process Pod when it's not scheduled.
			continue
		}
		scheduledPodNum++
		podSet := memberSetByNode[pod.Spec.NodeName]
		if podSet == nil {
			podSet = controlplane.GroupMemberSet{}
		}
		podSet.Insert(podToGroupMember(pod, false))
		// Update the Pod references by Node.
		memberSetByNode[pod.Spec.NodeName] = podSet
		// Update the NodeNames in order to set the SpanMeta for AppliedToGroup.
		appGroupNodeNames.Insert(pod.Spec.NodeName)
	}
	for _, extEntity := range externalEntities {
		if extEntity.Spec.ExternalNode == "" {
			continue
		}
		scheduledExtEntityNum++
		entitySet := memberSetByNode[extEntity.Spec.ExternalNode]
		if entitySet == nil {
			entitySet = controlplane.GroupMemberSet{}
		}
		entitySet.Insert(externalEntityToGroupMember(extEntity))
		memberSetByNode[extEntity.Spec.ExternalNode] = entitySet
		appGroupNodeNames.Insert(extEntity.Spec.ExternalNode)
	}
	updatedAppliedToGroup := &antreatypes.AppliedToGroup{
		UID:               appliedToGroup.UID,
		Name:              appliedToGroup.Name,
		Selector:          appliedToGroup.Selector,
		GroupMemberByNode: memberSetByNode,
		SpanMeta:          antreatypes.SpanMeta{NodeNames: appGroupNodeNames},
	}
	klog.V(2).Infof("Updating existing AppliedToGroup %s with %d Pods and %d External Entities on %d Nodes",
		key, scheduledPodNum, scheduledExtEntityNum, appGroupNodeNames.Len())
	n.appliedToGroupStore.Update(updatedAppliedToGroup)

	// Get all internal NetworkPolicy objects that refers this AppliedToGroup.
	// Note that this must be executed after storing the result, to ensure that
	// both of the NetworkPolicies that referred it before storing it and the
	// ones after storing it can get the right span.
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.AppliedToGroupIndex, key)
	if err != nil {
		return fmt.Errorf("unable to filter internal NetworkPolicies for AppliedToGroup %s: %v", key, err)
	}
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
		d := time.Since(startTime)
		metrics.DurationInternalNetworkPolicySyncing.Observe(float64(d.Milliseconds()))
		klog.V(2).Infof("Finished syncing internal NetworkPolicy %s. (%v)", key, d)
	}()
	klog.V(2).Infof("Syncing internal NetworkPolicy %s", key)
	nodeNames := sets.String{}
	// Lock the internal NetworkPolicy store as we may have a case where in the
	// same internal NetworkPolicy is being updated in the NetworkPolicy UPDATE
	// handler.
	n.internalNetworkPolicyMutex.Lock()
	internalNPObj, found, _ := n.internalNetworkPolicyStore.Get(key)
	if !found {
		// Make sure to unlock the store before returning.
		n.internalNetworkPolicyMutex.Unlock()
		return fmt.Errorf("internal NetworkPolicy %s not found", key)
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
	updatedNetworkPolicy := &antreatypes.NetworkPolicy{
		UID:             internalNP.UID,
		Name:            internalNP.Name,
		SourceRef:       internalNP.SourceRef,
		Rules:           internalNP.Rules,
		AppliedToGroups: internalNP.AppliedToGroups,
		Priority:        internalNP.Priority,
		TierPriority:    internalNP.TierPriority,
		SpanMeta:        antreatypes.SpanMeta{NodeNames: nodeNames},
		Generation:      internalNP.Generation,
	}
	klog.V(4).Infof("Updating internal NetworkPolicy %s with %d Nodes", key, nodeNames.Len())
	n.internalNetworkPolicyStore.Update(updatedNetworkPolicy)
	// Internal NetworkPolicy update is complete. Safe to unlock the
	// critical section.
	n.internalNetworkPolicyMutex.Unlock()
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

// ipStrToIPAddress converts an IP string to a controlplane.IPAddress.
// nil will returned if the IP string is not valid.
func ipStrToIPAddress(ip string) controlplane.IPAddress {
	return controlplane.IPAddress(net.ParseIP(ip))
}

// cidrStrToIPNet converts a CIDR (eg. 10.0.0.0/16) to a *controlplane.IPNet.
func cidrStrToIPNet(cidr string) (*controlplane.IPNet, error) {
	// Split the cidr to retrieve the IP and prefix.
	s := strings.Split(cidr, "/")
	if len(s) != 2 {
		return nil, fmt.Errorf("invalid format for IPBlock CIDR: %s", cidr)
	}
	// Convert prefix length to int32
	prefixLen64, err := strconv.ParseInt(s[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid prefix length: %s", s[1])
	}
	ipNet := &controlplane.IPNet{
		IP:           ipStrToIPAddress(s[0]),
		PrefixLength: int32(prefixLen64),
	}
	return ipNet, nil
}

// internalNetworkPolicyKeyFunc knows how to generate the key for an internal NetworkPolicy based on the object metadata
// of the corresponding original NetworkPolicy resource (also referred to as the "source").
// The key must be unique across K8s NetworkPolicies, Antrea NetworkPolicies, and Antrea ClusterNetworkPolicies.
// Currently the UID of the original NetworkPolicy is used to ensure uniqueness.
func internalNetworkPolicyKeyFunc(obj metav1.Object) string {
	return string(obj.GetUID())
}

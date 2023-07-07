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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	"k8s.io/klog/v2"
	policyinformers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions/apis/v1alpha1"
	policylisters "sigs.k8s.io/network-policy-api/pkg/client/listers/apis/v1alpha1"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	crdv1b1informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdv1b1listers "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/labelidentity"
	"antrea.io/antrea/pkg/controller/metrics"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/externalnode"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
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
	// ClusterGroupIndex is used to index ClusterNetworkPolicies by ClusterGroup names.
	ClusterGroupIndex = "clustergroup"
	// GroupIndex is used to index Antrea NetworkPolicies by Group names.
	GroupIndex = "group"

	// EnableNPLoggingAnnotationKey can be added to Namespace to enable logging K8s NP.
	EnableNPLoggingAnnotationKey = "networkpolicy.antrea.io/enable-logging"

	appliedToGroupType grouping.GroupType = "appliedToGroup"
	addressGroupType   grouping.GroupType = "addressGroup"
	internalGroupType  grouping.GroupType = "internalGroup"

	perNamespaceRuleIndex      = "hasPerNamespaceRule"
	namespaceRuleLabelKeyIndex = "namespaceRuleLabelKeys"
	indexValueTrue             = "true"
)

var (
	// uuidNamespace is a uuid.UUID type generated from a string to be
	// used to generate uuid.UUID for internal Antrea objects like
	// AppliedToGroup, AddressGroup etc.
	// e4f24a48-ca1f-4d5b-819c-ea7632b22115 was generated using
	// uuid.NewRandom() function.
	uuidNamespace = uuid.Must(uuid.Parse("e4f24a48-ca1f-4d5b-819c-ea7632b22115"))

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
	defaultAction = secv1beta1.RuleActionAllow
)

func getKNPReference(knp *networkingv1.NetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type:      controlplane.K8sNetworkPolicy,
		Namespace: knp.Namespace,
		Name:      knp.Name,
		UID:       knp.UID,
	}
}

// NetworkPolicyController is responsible for synchronizing the Namespaces and Pods
// affected by a Network Policy.
type NetworkPolicyController struct {
	// kubeClient is a standard Kubernetes clientset.
	kubeClient clientset.Interface
	// crdClient is the clientset for CRD API group.
	crdClient versioned.Interface

	namespaceInformer coreinformers.NamespaceInformer
	// namespaceLister is able to list/get Namespaces and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	namespaceLister corelisters.NamespaceLister
	// namespaceListerSynced is a function which returns true if the Namespace shared informer has been synced at least once.
	namespaceListerSynced cache.InformerSynced

	serviceInformer coreinformers.ServiceInformer
	// serviceLister is able to list/get Services and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	serviceLister corelisters.ServiceLister
	// serviceListerSynced is a function which returns true if the Service shared informer has been synced at least once.
	serviceListerSynced cache.InformerSynced

	networkPolicyInformer networkinginformers.NetworkPolicyInformer
	// networkPolicyLister is able to list/get Network Policies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	networkPolicyLister networkinglisters.NetworkPolicyLister
	// networkPolicyListerSynced is a function which returns true if the Network Policy shared informer has been synced at least once.
	networkPolicyListerSynced cache.InformerSynced

	acnpInformer crdv1b1informers.ClusterNetworkPolicyInformer
	// acnpLister is able to list/get AntreaClusterNetworkPolicies and is populated by the shared informer passed to
	// NewClusterNetworkPolicyController.
	acnpLister crdv1b1listers.ClusterNetworkPolicyLister
	// acnpListerSynced is a function which returns true if the AntreaClusterNetworkPolicies shared informer has been synced at least once.
	acnpListerSynced cache.InformerSynced

	annpInformer crdv1b1informers.NetworkPolicyInformer
	// annpLister is able to list/get AntreaNetworkPolicies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	annpLister crdv1b1listers.NetworkPolicyLister
	// annpListerSynced is a function which returns true if the AntreaNetworkPolicies shared informer has been synced at least once.
	annpListerSynced cache.InformerSynced

	tierInformer crdv1b1informers.TierInformer
	// tierLister is able to list/get Tiers and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	tierLister crdv1b1listers.TierLister
	// tierListerSynced is a function which returns true if the Tiers shared informer has been synced at least once.
	tierListerSynced cache.InformerSynced

	cgInformer crdv1b1informers.ClusterGroupInformer
	// cgLister is able to list/get ClusterGroups and is populated by the shared informer passed to
	// NewClusterGroupController.
	cgLister crdv1b1listers.ClusterGroupLister
	// cgListerSynced is a function which returns true if the ClusterGroup shared informer has been synced at least
	// once.
	cgListerSynced cache.InformerSynced

	nodeInformer coreinformers.NodeInformer
	// nodeLister is able to list/get Nodes and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	nodeLister corelisters.NodeLister
	// nodeListerSynced is a function which returns true if the Node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced

	grpInformer crdv1b1informers.GroupInformer
	// grpLister is able to list/get Groups and is populated by the shared informer passed to
	// NewGroupController.
	grpLister crdv1b1listers.GroupLister
	// grpListerSynced is a function which returns true if the Group shared informer has been synced at least
	// once.
	grpListerSynced cache.InformerSynced

	adminNetworkPolicyInformer policyinformers.AdminNetworkPolicyInformer
	// adminNetworkPolicyLister is able to list/get AdminNetworkPolicy objects.
	adminNetworkPolicyLister policylisters.AdminNetworkPolicyLister
	// AdminNetworkPolicySynced is a function which returns true if the AdminNetworkPolicy shared informer has
	// been synced at least once.
	adminNetworkPolicyListerSynced cache.InformerSynced

	banpInformer policyinformers.BaselineAdminNetworkPolicyInformer
	// banpLister is able to list/get BaselineAdminNetworkPolicy objects.
	banpLister policylisters.BaselineAdminNetworkPolicyLister
	// banpListerSynced is a function which returns true if the BaselineAdminNetworkPolicy shared informer has
	// been synced at least once.
	banpListerSynced cache.InformerSynced

	// addressGroupStore is the storage where the populated Address Groups are stored.
	addressGroupStore storage.Interface
	// appliedToGroupStore is the storage where the populated AppliedTo Groups are stored.
	appliedToGroupStore storage.Interface
	// internalNetworkPolicyStore is the storage where the populated internal Network Policy are stored.
	internalNetworkPolicyStore storage.Interface
	// internalGroupStore is a simple store which maintains the internal Group types which can be later
	// converted to AppliedToGroup or AddressGroup based on usage.
	internalGroupStore storage.Interface

	// appliedToGroupQueue maintains the networkpolicy.AppliedToGroup objects that
	// need to be synced.
	appliedToGroupQueue workqueue.RateLimitingInterface
	// addressGroupQueue maintains the networkpolicy.AddressGroup objects that
	// need to be synced.
	addressGroupQueue workqueue.RateLimitingInterface
	// internalNetworkPolicyQueue maintains the networkpolicy.NetworkPolicy objects that
	// need to be synced.
	internalNetworkPolicyQueue workqueue.RateLimitingInterface
	// internalGroupQueue maintains the networkpolicy.Group objects that needs to be
	// synced.
	internalGroupQueue workqueue.RateLimitingInterface

	// internalNetworkPolicyMutex prevents concurrent processing of internal networkpolicies who refer
	// to the same addressgroups/appliedtogroups.
	internalNetworkPolicyMutex sync.RWMutex

	// appliedToGroupNotifier is responsible for notifying subscribers of an AppliedToGroup about its update.
	// The typical subscribers of AppliedToGroup are NetworkPolicies.
	appliedToGroupNotifier *notifier

	groupingInterface grouping.Interface
	// Added as a member to the struct to allow injection for testing.
	groupingInterfaceSynced func() bool

	labelIdentityInterface labelidentity.Interface
	// Enable Stretched Networkpolicy feature which allows Antrea-native policies to select peer
	// from other clusters in a ClusterSet.
	stretchNPEnabled bool
	// heartbeatCh is an internal channel for testing. It's used to know whether all tasks have been
	// processed, and to count executions of each function.
	heartbeatCh chan heartbeat
}

type heartbeat struct {
	name      string
	timestamp time.Time
}

var tierIndexers = cache.Indexers{
	PriorityIndex: func(obj interface{}) ([]string, error) {
		tr, ok := obj.(*secv1beta1.Tier)
		if !ok {
			return []string{}, nil
		}
		return []string{strconv.FormatInt(int64(tr.Spec.Priority), 10)}, nil
	},
}

var acnpIndexers = cache.Indexers{
	TierIndex: func(obj interface{}) ([]string, error) {
		acnp, ok := obj.(*secv1beta1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		return []string{acnp.Spec.Tier}, nil
	},
	ClusterGroupIndex: func(obj interface{}) ([]string, error) {
		acnp, ok := obj.(*secv1beta1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		groupNames := sets.Set[string]{}
		for _, appTo := range acnp.Spec.AppliedTo {
			if appTo.Group != "" {
				groupNames.Insert(appTo.Group)
			}
		}
		if len(acnp.Spec.Ingress) == 0 && len(acnp.Spec.Egress) == 0 {
			return sets.List(groupNames), nil
		}
		appendGroups := func(rule secv1beta1.Rule) {
			for _, peer := range rule.To {
				if peer.Group != "" {
					groupNames.Insert(peer.Group)
				}
			}
			for _, peer := range rule.From {
				if peer.Group != "" {
					groupNames.Insert(peer.Group)
				}
			}
			for _, appTo := range rule.AppliedTo {
				if appTo.Group != "" {
					groupNames.Insert(appTo.Group)
				}
			}
		}
		for _, rule := range acnp.Spec.Egress {
			appendGroups(rule)
		}
		for _, rule := range acnp.Spec.Ingress {
			appendGroups(rule)
		}
		return sets.List(groupNames), nil
	},
	perNamespaceRuleIndex: func(obj interface{}) ([]string, error) {
		acnp, ok := obj.(*secv1beta1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		if hasPerNamespaceRule(acnp) {
			return []string{indexValueTrue}, nil
		}
		return []string{}, nil
	},
	namespaceRuleLabelKeyIndex: func(obj interface{}) ([]string, error) {
		cnp, ok := obj.(*secv1beta1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		return namespaceRuleLabelKeys(cnp).UnsortedList(), nil
	},
}

var annpIndexers = cache.Indexers{
	TierIndex: func(obj interface{}) ([]string, error) {
		annp, ok := obj.(*secv1beta1.NetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		return []string{annp.Spec.Tier}, nil
	},
	GroupIndex: func(obj interface{}) ([]string, error) {
		annp, ok := obj.(*secv1beta1.NetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		ns := annp.Namespace + "/"
		groupNames := sets.Set[string]{}
		for _, appTo := range annp.Spec.AppliedTo {
			if appTo.Group != "" {
				groupNames.Insert(ns + appTo.Group)
			}
		}
		if len(annp.Spec.Ingress) == 0 && len(annp.Spec.Egress) == 0 {
			return sets.List(groupNames), nil
		}
		appendGroups := func(rule secv1beta1.Rule) {
			for _, peer := range rule.To {
				if peer.Group != "" {
					groupNames.Insert(ns + peer.Group)
				}
			}
			for _, peer := range rule.From {
				if peer.Group != "" {
					groupNames.Insert(ns + peer.Group)
				}
			}
			for _, appTo := range rule.AppliedTo {
				if appTo.Group != "" {
					groupNames.Insert(ns + appTo.Group)
				}
			}
		}
		for _, rule := range annp.Spec.Egress {
			appendGroups(rule)
		}
		for _, rule := range annp.Spec.Ingress {
			appendGroups(rule)
		}
		return sets.List(groupNames), nil
	},
}

// NewNetworkPolicyController returns a new *NetworkPolicyController.
func NewNetworkPolicyController(kubeClient clientset.Interface,
	crdClient versioned.Interface,
	groupingInterface grouping.Interface,
	labelIdentityInterface labelidentity.Interface,
	namespaceInformer coreinformers.NamespaceInformer,
	serviceInformer coreinformers.ServiceInformer,
	networkPolicyInformer networkinginformers.NetworkPolicyInformer,
	nodeInformer coreinformers.NodeInformer,
	acnpInformer crdv1b1informers.ClusterNetworkPolicyInformer,
	annpInformer crdv1b1informers.NetworkPolicyInformer,
	adminNPInformer policyinformers.AdminNetworkPolicyInformer,
	banpInformer policyinformers.BaselineAdminNetworkPolicyInformer,
	tierInformer crdv1b1informers.TierInformer,
	cgInformer crdv1b1informers.ClusterGroupInformer,
	grpInformer crdv1b1informers.GroupInformer,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	internalNetworkPolicyStore storage.Interface,
	internalGroupStore storage.Interface,
	stretchedNPEnabled bool) *NetworkPolicyController {
	n := &NetworkPolicyController{
		kubeClient:                     kubeClient,
		crdClient:                      crdClient,
		networkPolicyInformer:          networkPolicyInformer,
		networkPolicyLister:            networkPolicyInformer.Lister(),
		networkPolicyListerSynced:      networkPolicyInformer.Informer().HasSynced,
		adminNetworkPolicyInformer:     adminNPInformer,
		adminNetworkPolicyLister:       adminNPInformer.Lister(),
		adminNetworkPolicyListerSynced: adminNPInformer.Informer().HasSynced,
		banpInformer:                   banpInformer,
		banpLister:                     banpInformer.Lister(),
		banpListerSynced:               banpInformer.Informer().HasSynced,
		addressGroupStore:              addressGroupStore,
		appliedToGroupStore:            appliedToGroupStore,
		internalNetworkPolicyStore:     internalNetworkPolicyStore,
		internalGroupStore:             internalGroupStore,
		appliedToGroupQueue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "appliedToGroup"),
		addressGroupQueue:              workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "addressGroup"),
		internalNetworkPolicyQueue:     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalNetworkPolicy"),
		internalGroupQueue:             workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalGroup"),
		groupingInterface:              groupingInterface,
		groupingInterfaceSynced:        groupingInterface.HasSynced,
		labelIdentityInterface:         labelIdentityInterface,
		stretchNPEnabled:               stretchedNPEnabled,
		appliedToGroupNotifier:         newNotifier(),
	}
	n.groupingInterface.AddEventHandler(appliedToGroupType, n.enqueueAppliedToGroup)
	n.groupingInterface.AddEventHandler(addressGroupType, n.enqueueAddressGroup)
	n.groupingInterface.AddEventHandler(internalGroupType, n.enqueueInternalGroup)
	n.labelIdentityInterface.AddEventHandler(n.triggerPolicyResyncForLabelIdentityUpdates)
	// Add handlers for NetworkPolicy events.
	n.namespaceInformer = namespaceInformer
	n.namespaceLister = namespaceInformer.Lister()
	n.namespaceListerSynced = namespaceInformer.Informer().HasSynced
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    n.addNetworkPolicy,
			UpdateFunc: n.updateNetworkPolicy,
			DeleteFunc: n.deleteNetworkPolicy,
		},
		resyncPeriod,
	)
	if features.DefaultFeatureGate.Enabled(features.AdminNetworkPolicy) {
		adminNPInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addAdminNP,
				UpdateFunc: n.updateAdminNP,
				DeleteFunc: n.deleteAdminNP,
			},
			resyncPeriod,
		)
		banpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addBANP,
				UpdateFunc: n.updateBANP,
				DeleteFunc: n.deleteBANP,
			},
			resyncPeriod,
		)
	}
	// Register Informer and add handlers for AntreaPolicy events only if the feature is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		n.serviceInformer = serviceInformer
		n.serviceLister = serviceInformer.Lister()
		n.serviceListerSynced = serviceInformer.Informer().HasSynced
		n.nodeInformer = nodeInformer
		n.nodeLister = nodeInformer.Lister()
		n.nodeListerSynced = nodeInformer.Informer().HasSynced
		n.acnpInformer = acnpInformer
		n.acnpLister = acnpInformer.Lister()
		n.acnpListerSynced = acnpInformer.Informer().HasSynced
		n.annpInformer = annpInformer
		n.annpLister = annpInformer.Lister()
		n.annpListerSynced = annpInformer.Informer().HasSynced
		n.tierInformer = tierInformer
		n.tierLister = tierInformer.Lister()
		n.tierListerSynced = tierInformer.Informer().HasSynced
		n.cgInformer = cgInformer
		n.cgLister = cgInformer.Lister()
		n.cgListerSynced = cgInformer.Informer().HasSynced
		n.grpInformer = grpInformer
		n.grpLister = grpInformer.Lister()
		n.grpListerSynced = grpInformer.Informer().HasSynced
		// Add handlers for Namespace events.
		n.namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addNamespace,
				UpdateFunc: n.updateNamespace,
				DeleteFunc: n.deleteNamespace,
			},
			resyncPeriod,
		)
		n.serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addService,
				UpdateFunc: n.updateService,
				DeleteFunc: n.deleteService,
			},
			resyncPeriod,
		)
		// Add handlers for Node events.
		nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addNode,
				UpdateFunc: n.updateNode,
				DeleteFunc: n.deleteNode,
			},
			resyncPeriod,
		)
		tierInformer.Informer().AddIndexers(tierIndexers)
		acnpInformer.Informer().AddIndexers(acnpIndexers)
		acnpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addCNP,
				UpdateFunc: n.updateCNP,
				DeleteFunc: n.deleteCNP,
			},
			resyncPeriod,
		)
		annpInformer.Informer().AddIndexers(annpIndexers)
		annpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addANNP,
				UpdateFunc: n.updateANNP,
				DeleteFunc: n.deleteANNP,
			},
			resyncPeriod,
		)
		// Add event handlers for ClusterGroup notification.
		cgInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addClusterGroup,
				UpdateFunc: n.updateClusterGroup,
				DeleteFunc: n.deleteClusterGroup,
			},
			resyncPeriod,
		)
		// Add event handlers for Group notification.
		grpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addGroup,
				UpdateFunc: n.updateGroup,
				DeleteFunc: n.deleteGroup,
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

// getNormalizedUID generates a unique UUID based on a given string.
// For example, it can be used to generate keys using normalized selectors
// unique within the Namespace by adding the constant UID.
func getNormalizedUID(name string) string {
	return uuid.NewSHA1(uuidNamespace, []byte(name)).String()
}

// createAppliedToGroup creates an AppliedToGroup object corresponding to the provided selectors.
func (n *NetworkPolicyController) createAppliedToGroup(npNsName string, pSel, nSel, eSel, nodeSel *metav1.LabelSelector) *antreatypes.AppliedToGroup {
	groupSelector := antreatypes.NewGroupSelector(npNsName, pSel, nSel, eSel, nodeSel)
	appliedToGroupUID := getNormalizedUID(groupSelector.NormalizedName)
	// Construct a new AppliedToGroup.
	appliedToGroup := &antreatypes.AppliedToGroup{
		Name:     appliedToGroupUID,
		UID:      types.UID(appliedToGroupUID),
		Selector: groupSelector,
	}
	return appliedToGroup
}

// createAddressGroup creates an AddressGroup object corresponding to a
// NetworkPolicyPeer object in NetworkPolicyRule. This function simply
// creates the object without actually populating the PodAddresses as the
// affected GroupMembers are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroup(namespace string, podSelector, nsSelector, eeSelector, nodeSelector *metav1.LabelSelector) *antreatypes.AddressGroup {
	groupSelector := antreatypes.NewGroupSelector(namespace, podSelector, nsSelector, eeSelector, nodeSelector)
	normalizedUID := getNormalizedUID(groupSelector.NormalizedName)
	// Create an AddressGroup object per Peer object.
	addressGroup := &antreatypes.AddressGroup{
		UID:      types.UID(normalizedUID),
		Name:     normalizedUID,
		Selector: groupSelector,
	}
	return addressGroup
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
		antreaServices = append(antreaServices, controlplane.Service{
			Protocol: toAntreaProtocol(npPort.Protocol),
			Port:     npPort.Port,
			EndPort:  npPort.EndPort,
		})
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
func (n *NetworkPolicyController) processNetworkPolicy(np *networkingv1.NetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	// appliedToGroups tracks all distinct AppliedToGroups referred to by the K8s NetworkPolicy.
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	// addressGroups tracks all distinct AddressGroups referred to by the K8s NetworkPolicy.
	addressGroups := map[string]*antreatypes.AddressGroup{}

	newAppliedToGroup := n.createAppliedToGroup(np.Namespace, &np.Spec.PodSelector, nil, nil, nil)
	appliedToGroups = mergeAppliedToGroups(appliedToGroups, newAppliedToGroup)
	rules := make([]controlplane.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	// Retrieve Namespace logging annotation.
	enableLogging := false
	namespace, err := n.namespaceLister.Get(np.Namespace)
	if err == nil {
		enableLogging, _ = strconv.ParseBool(namespace.Annotations[EnableNPLoggingAnnotationKey])
	}
	var ingressRuleExists, egressRuleExists bool
	// Compute NetworkPolicyRule for Ingress Rule.
	for _, ingressRule := range np.Spec.Ingress {
		ingressRuleExists = true
		services, namedPortExists := toAntreaServices(ingressRule.Ports)
		peer, newAddressGroups := n.toAntreaPeer(ingressRule.From, np, controlplane.DirectionIn, namedPortExists)
		addressGroups = mergeAddressGroups(addressGroups, newAddressGroups...)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:     controlplane.DirectionIn,
			From:          *peer,
			Services:      services,
			Priority:      defaultRulePriority,
			Action:        &defaultAction,
			EnableLogging: enableLogging,
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for _, egressRule := range np.Spec.Egress {
		egressRuleExists = true
		services, namedPortExists := toAntreaServices(egressRule.Ports)
		peer, newAddressGroups := n.toAntreaPeer(egressRule.To, np, controlplane.DirectionOut, namedPortExists)
		addressGroups = mergeAddressGroups(addressGroups, newAddressGroups...)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:     controlplane.DirectionOut,
			To:            *peer,
			Services:      services,
			Priority:      defaultRulePriority,
			Action:        &defaultAction,
			EnableLogging: enableLogging,
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
		AppliedToGroups: sets.List(sets.KeySet(appliedToGroups)),
		Rules:           rules,
		Generation:      np.Generation,
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}

func (n *NetworkPolicyController) toAntreaPeer(peers []networkingv1.NetworkPolicyPeer, np *networkingv1.NetworkPolicy, dir controlplane.Direction, namedPortExists bool) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
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
			return &matchAllPeer, nil
		}
		allPodsGroup := n.createAddressGroup(np.Namespace, matchAllPodsPeer.PodSelector, matchAllPodsPeer.NamespaceSelector, nil, nil)
		addressGroups = append(addressGroups, allPodsGroup)
		podsPeer := matchAllPeer
		podsPeer.AddressGroups = append(podsPeer.AddressGroups, allPodsGroup.Name)
		return &podsPeer, addressGroups
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
			addressGroup := n.createAddressGroup(np.Namespace, peer.PodSelector, peer.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		}
	}
	return &controlplane.NetworkPolicyPeer{AddressGroups: getAddressGroupNames(addressGroups), IPBlocks: ipBlocks}, addressGroups
}

// addNetworkPolicy receives NetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addNetworkPolicy(obj interface{}) {
	defer n.heartbeat("addNetworkPolicy")
	np := obj.(*networkingv1.NetworkPolicy)
	klog.Infof("Processing K8s NetworkPolicy %s/%s ADD event", np.Namespace, np.Name)
	n.enqueueInternalNetworkPolicy(getKNPReference(np))
}

// updateNetworkPolicy receives NetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateNetworkPolicy(old, cur interface{}) {
	defer n.heartbeat("updateNetworkPolicy")
	np := cur.(*networkingv1.NetworkPolicy)
	klog.Infof("Processing K8s NetworkPolicy %s/%s UPDATE event", np.Namespace, np.Name)
	n.enqueueInternalNetworkPolicy(getKNPReference(np))
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
	n.enqueueInternalNetworkPolicy(getKNPReference(np))
}

// addService retrieves all internal Groups which refers to this Service
// and enqueues the group keys for further processing.
func (n *NetworkPolicyController) addService(obj interface{}) {
	defer n.heartbeat("addService")
	service := obj.(*v1.Service)
	klog.V(2).Infof("Processing Service %s/%s ADD event", service.Namespace, service.Name)
	// Find all internal Group keys which refers to this Service.
	groupKeySet := n.filterInternalGroupsForService(service)
	// Enqueue internal groups to its queue for group processing.
	for group := range groupKeySet {
		n.enqueueInternalGroup(group)
	}
}

// updatePod retrieves all internal Groups which refers to this Service
// and enqueues the group keys for further processing.
func (n *NetworkPolicyController) updateService(oldObj, curObj interface{}) {
	defer n.heartbeat("updateService")
	oldService := oldObj.(*v1.Service)
	curService := curObj.(*v1.Service)
	klog.V(2).Infof("Processing Service %s/%s UPDATE event, selectors: %v", curService.Namespace, curService.Name, curService.Spec.Selector)
	// No need to trigger processing of groups if there is no change in the Service selectors.
	if reflect.DeepEqual(oldService.Spec.Selector, curService.Spec.Selector) {
		klog.V(4).Infof("No change in Service %s/%s. Skipping group evaluation.", curService.Namespace, curService.Name)
		return
	}
	// Find all internal Group keys which refers to this Service.
	groupKeySet := n.filterInternalGroupsForService(curService)
	// Enqueue internal groups to its queue for group processing.
	for group := range groupKeySet {
		n.enqueueInternalGroup(group)
	}
}

// deleteService retrieves all internal Groups which refers to this Service
// and enqueues the group keys for further processing.
func (n *NetworkPolicyController) deleteService(old interface{}) {
	service, ok := old.(*v1.Service)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Service, invalid type: %v", old)
			return
		}
		service, ok = tombstone.Obj.(*v1.Service)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Service, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteService")

	klog.V(2).Infof("Processing Service %s/%s DELETE event", service.Namespace, service.Name)
	// Find all internal Group keys which refers to this Service.
	groupKeySet := n.filterInternalGroupsForService(service)
	// Enqueue internal groups to its queue for group processing.
	for group := range groupKeySet {
		n.enqueueInternalGroup(group)
	}
}

func (n *NetworkPolicyController) enqueueAppliedToGroup(key string) {
	klog.V(4).Infof("Adding new key %s to AppliedToGroup queue", key)
	n.appliedToGroupQueue.Add(key)
	metrics.LengthAppliedToGroupQueue.Set(float64(n.appliedToGroupQueue.Len()))
}

func (n *NetworkPolicyController) enqueueAddressGroup(key string) {
	klog.V(4).Infof("Adding new key %s to AddressGroup queue", key)
	n.addressGroupQueue.Add(key)
	metrics.LengthAddressGroupQueue.Set(float64(n.addressGroupQueue.Len()))
}

func (n *NetworkPolicyController) enqueueInternalNetworkPolicy(key *controlplane.NetworkPolicyReference) {
	klog.V(4).Infof("Adding new key %v to internal NetworkPolicy queue", key)
	// It must use value instead of pointer as the key, otherwise the same NetworkPolicies will not be treated as same
	// item because the pointers may be different.
	n.internalNetworkPolicyQueue.Add(*key)
	metrics.LengthInternalNetworkPolicyQueue.Set(float64(n.internalNetworkPolicyQueue.Len()))
}

// Run begins watching and syncing of a NetworkPolicyController.
func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.appliedToGroupQueue.ShutDown()
	defer n.addressGroupQueue.ShutDown()
	defer n.internalNetworkPolicyQueue.ShutDown()
	defer n.internalGroupQueue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{n.networkPolicyListerSynced, n.groupingInterfaceSynced}
	// Only wait for acnpListerSynced and annpListerSynced when AntreaPolicy feature gate is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		cacheSyncs = append(cacheSyncs, n.acnpListerSynced, n.annpListerSynced, n.cgListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.appliedToGroupWorker, time.Second, stopCh)
		go wait.Until(n.addressGroupWorker, time.Second, stopCh)
		go wait.Until(n.internalNetworkPolicyWorker, time.Second, stopCh)
		go wait.Until(n.internalGroupWorker, time.Second, stopCh)
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

	networkPolicyRef := key.(controlplane.NetworkPolicyReference)
	err := n.syncInternalNetworkPolicy(&networkPolicyRef)
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
// reference to this AddressGroup and updates its Pod IPAddresses set to
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
		klog.V(2).Infof("AddressGroup %s not found", key)
		return nil
	}
	addressGroup := addressGroupObj.(*antreatypes.AddressGroup)
	// NodeNames set must be considered immutable once generated and updated
	// in the store. If any change is needed, the set must be regenerated with
	// the new NodeNames and the store must be updated.
	addrGroupNodeNames := sets.Set[string]{}
	for _, internalNPObj := range nps {
		internalNP := internalNPObj.(*antreatypes.NetworkPolicy)
		utilsets.MergeString(addrGroupNodeNames, internalNP.SpanMeta.NodeNames)
	}
	memberSet := n.getAddressGroupMemberSet(addressGroup)
	updatedAddressGroup := &antreatypes.AddressGroup{
		Name:         addressGroup.Name,
		UID:          addressGroup.UID,
		Selector:     addressGroup.Selector,
		SourceGroup:  addressGroup.SourceGroup,
		GroupMembers: memberSet,
		SpanMeta:     antreatypes.SpanMeta{NodeNames: addrGroupNodeNames},
	}
	klog.V(2).Infof("Updating existing AddressGroup %s with %d Pods/ExternalEntities and %d Nodes", key, len(memberSet), addrGroupNodeNames.Len())
	return n.addressGroupStore.Update(updatedAddressGroup)
}

func (c *NetworkPolicyController) getNodeMemberSet(selector labels.Selector) controlplane.GroupMemberSet {
	groupMemberSet := controlplane.GroupMemberSet{}
	nodes, _ := c.nodeLister.List(selector)
	for _, node := range nodes {
		groupMemberSet.Insert(nodeToGroupMember(node, true))
	}
	return groupMemberSet
}

// getAddressGroupMemberSet knows how to construct a GroupMemberSet that contains
// all the entities selected by an AddressGroup.
func (n *NetworkPolicyController) getAddressGroupMemberSet(g *antreatypes.AddressGroup) controlplane.GroupMemberSet {
	// This AddressGroup is derived from a ClusterGroup/Group.
	if g.SourceGroup != "" {
		// Check if an internal Group object exists corresponding to this AddressGroup.
		groupObj, found, _ := n.internalGroupStore.Get(g.SourceGroup)
		if found {
			// In case the ClusterGroup/Group is defined by a mix of childGroup with selectors and
			// childGroup with ipBlocks, this function only returns the aggregated GroupMemberSet
			// computed from childGroup with selectors, as ipBlocks will be processed differently.
			group := groupObj.(*antreatypes.Group)
			members, _ := n.getInternalGroupMembers(group)
			return members
		}
		// The internal Group doesn't exist yet or has been deleted. The AddressGroup selects nothing at the moment.
		// Once the internalGroup is created, the AddressGroup will be resynced.
		return nil
	}
	// Selector can't be nil when it reaches here.
	if g.Selector.NodeSelector != nil {
		return n.getNodeMemberSet(g.Selector.NodeSelector)
	}
	return n.getMemberSetForGroupType(addressGroupType, g.Name)
}

// getInternalGroupMembers knows how to construct a GroupMemberSet and ipBlocks that contains
// all the entities selected by an internal Group. For internal Groups that has childGroups,
// the members are computed as the union of all its childGroup's members.
func (n *NetworkPolicyController) getInternalGroupMembers(group *antreatypes.Group) (controlplane.GroupMemberSet, []controlplane.IPBlock) {
	if len(group.IPBlocks) > 0 {
		return nil, group.IPBlocks
	} else if len(group.ChildGroups) == 0 {
		return n.getMemberSetForGroupType(internalGroupType, group.SourceReference.ToGroupName()), nil
	}
	var ipBlocks []controlplane.IPBlock
	groupMemberSet := controlplane.GroupMemberSet{}
	for _, childName := range group.ChildGroups {
		childName = k8s.NamespacedName(group.SourceReference.Namespace, childName)
		childGroup, found, _ := n.internalGroupStore.Get(childName)
		if found {
			child := childGroup.(*antreatypes.Group)
			members, ipb := n.getInternalGroupMembers(child)
			ipBlocks = append(ipBlocks, ipb...)
			groupMemberSet.Merge(members)
		}
	}
	return groupMemberSet, ipBlocks
}

// getMemberSetForGroupType knows how to construct a GroupMemberSet for the given
// groupType and group name.
func (n *NetworkPolicyController) getMemberSetForGroupType(groupType grouping.GroupType, name string) controlplane.GroupMemberSet {
	groupMemberSet := controlplane.GroupMemberSet{}
	pods, externalEntities := n.groupingInterface.GetEntities(groupType, name)
	for _, pod := range pods {
		// HostNetwork Pods should be excluded from group members
		// https://github.com/antrea-io/antrea/issues/3078
		if pod.Spec.HostNetwork == true || len(pod.Status.PodIPs) == 0 {
			continue
		}
		groupMemberSet.Insert(podToGroupMember(pod, true))
	}
	for _, ee := range externalEntities {
		groupMemberSet.Insert(externalEntityToGroupMember(ee, true))
	}
	return groupMemberSet
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

func nodeToGroupMember(node *v1.Node, includeIP bool) (member *controlplane.GroupMember) {
	member = &controlplane.GroupMember{Node: &controlplane.NodeReference{Name: node.Name}}
	ips, err := k8s.GetNodeAllAddrs(node)
	if err != nil {
		klog.ErrorS(err, "Error getting Node IP addresses", "Node", node.Name)
	}
	if includeIP {
		for ip := range ips {
			member.IPs = append(member.IPs, ipStrToIPAddress(ip))
		}
	}
	return
}

func serviceToGroupMember(serviceReference *controlplane.ServiceReference) (member *controlplane.GroupMember) {
	return &controlplane.GroupMember{
		Service: &controlplane.ServiceReference{
			Namespace: serviceReference.Namespace,
			Name:      serviceReference.Name,
		},
	}
}

func externalEntityToGroupMember(ee *v1alpha2.ExternalEntity, includeIP bool) *controlplane.GroupMember {
	memberEntity := &controlplane.GroupMember{}
	namedPorts := make([]controlplane.NamedPort, len(ee.Spec.Ports))
	for i, port := range ee.Spec.Ports {
		namedPorts[i] = controlplane.NamedPort{
			Port:     port.Port,
			Name:     port.Name,
			Protocol: controlplane.Protocol(port.Protocol),
		}
	}
	if includeIP {
		for _, ep := range ee.Spec.Endpoints {
			memberEntity.IPs = append(memberEntity.IPs, ipStrToIPAddress(ep.IP))
		}
	}
	eeRef := controlplane.ExternalEntityReference{
		Name:      ee.Name,
		Namespace: ee.Namespace,
	}
	memberEntity.ExternalEntity = &eeRef
	memberEntity.Ports = namedPorts
	return memberEntity
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
	appGroupNodeNames := sets.Set[string]{}
	appliedToGroupObj, found, _ := n.appliedToGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("AppliedToGroup %s not found.", key)
		return nil
	}
	appliedToGroup := appliedToGroupObj.(*antreatypes.AppliedToGroup)
	memberSetByNode := make(map[string]controlplane.GroupMemberSet)
	var updatedAppliedToGroup *antreatypes.AppliedToGroup
	if appliedToGroup.Service != nil {
		// AppliedToGroup for NodePort Service span to all Nodes.
		nodeList, err := n.nodeLister.List(labels.Everything())
		if err != nil {
			return fmt.Errorf("unable to list Nodes")
		}
		serviceGroupMemberSet := controlplane.NewGroupMemberSet(serviceToGroupMember(appliedToGroup.Service))
		for _, node := range nodeList {
			appGroupNodeNames.Insert(node.Name)
			memberSetByNode[node.Name] = serviceGroupMemberSet
		}
		updatedAppliedToGroup = &antreatypes.AppliedToGroup{
			UID:               appliedToGroup.UID,
			Name:              appliedToGroup.Name,
			Service:           appliedToGroup.Service,
			GroupMemberByNode: memberSetByNode,
			SpanMeta:          antreatypes.SpanMeta{NodeNames: appGroupNodeNames},
		}
		klog.V(2).InfoS("Updating existing AppliedToGroup", "Service", *appliedToGroup.Service, "numNodes", appGroupNodeNames.Len())
	} else {
		pods, externalEntities, nodes, err := n.getAppliedToWorkloads(appliedToGroup)
		if err != nil {
			klog.ErrorS(err, "Error when getting AppliedTo workloads for AppliedToGroup", "AppliedToGroup", appliedToGroup.Name)
			updatedAppliedToGroup = &antreatypes.AppliedToGroup{
				UID:         appliedToGroup.UID,
				Name:        appliedToGroup.Name,
				Selector:    appliedToGroup.Selector,
				SourceGroup: appliedToGroup.SourceGroup,
				SyncError:   err,
			}
		} else {
			scheduledPodNum, scheduledExtEntityNum := 0, 0
			for _, pod := range pods {
				if pod.Spec.NodeName == "" || pod.Spec.HostNetwork == true {
					// No need to process Pod when it's not scheduled.
					// HostNetwork Pods will not be applied to by policies.
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
				entityNodeKey := externalnode.GenerateEntityNodeKey(extEntity)
				if entityNodeKey == "" {
					continue
				}
				scheduledExtEntityNum++
				entitySet := memberSetByNode[entityNodeKey]
				if entitySet == nil {
					entitySet = controlplane.GroupMemberSet{}
				}
				entitySet.Insert(externalEntityToGroupMember(extEntity, false))
				memberSetByNode[entityNodeKey] = entitySet
				appGroupNodeNames.Insert(entityNodeKey)
			}
			for _, node := range nodes {
				nodeSet := memberSetByNode[node.Name]
				if nodeSet == nil {
					nodeSet = controlplane.GroupMemberSet{}
				}
				nodeSet.Insert(nodeToGroupMember(node, false))
				memberSetByNode[node.Name] = nodeSet
				appGroupNodeNames.Insert(node.Name)
			}
			updatedAppliedToGroup = &antreatypes.AppliedToGroup{
				UID:               appliedToGroup.UID,
				Name:              appliedToGroup.Name,
				Selector:          appliedToGroup.Selector,
				SourceGroup:       appliedToGroup.SourceGroup,
				GroupMemberByNode: memberSetByNode,
				SpanMeta:          antreatypes.SpanMeta{NodeNames: appGroupNodeNames},
			}
			klog.V(2).InfoS("Updating existing AppliedToGroup", "numPods", scheduledPodNum, "numExternalEntities", scheduledExtEntityNum, "numNodes", appGroupNodeNames.Len())
		}
	}
	n.appliedToGroupStore.Update(updatedAppliedToGroup)
	// Note that this must be executed after storing the result, to ensure that
	// the notified subscribers get the latest state.
	n.appliedToGroupNotifier.notify(key)
	return nil
}

// getAppliedToWorkloads returns a list of workloads (Pods, ExternalEntities or Nodes) selected by an AppliedToGroup
// for standalone selectors or Pods and ExternalEntities corresponding to a ClusterGroup.
func (n *NetworkPolicyController) getAppliedToWorkloads(g *antreatypes.AppliedToGroup) ([]*v1.Pod, []*v1alpha2.ExternalEntity, []*v1.Node, error) {
	// This AppliedToGroup is derived from a ClusterGroup/Group.
	if g.SourceGroup != "" {
		// Check if an internal Group object exists corresponding to this AppliedToGroup
		group, found, _ := n.internalGroupStore.Get(g.SourceGroup)
		if found {
			grp := group.(*antreatypes.Group)
			pods, ees, err := n.getInternalGroupWorkloads(grp)
			return pods, ees, nil, err
		}
		// The internal Group doesn't exist yet or has been deleted. The AppliedToGroup selects nothing at the moment.
		// Once the internalGroup is created, the AppliedToGroup will be resynced.
		return nil, nil, nil, nil
	}
	// Selector can't be nil when it reaches here.
	if g.Selector.NodeSelector != nil {
		nodes, err := n.nodeLister.List(g.Selector.NodeSelector)
		return nil, nil, nodes, err
	}
	pods, ees := n.groupingInterface.GetEntities(appliedToGroupType, g.Name)
	return pods, ees, nil, nil
}

// getInternalGroupWorkloads returns a list of workloads (Pods and ExternalEntities) selected by a ClusterGroup.
// For ClusterGroup that has childGroups, the workloads are computed as the union of all its childGroup's workloads.
func (n *NetworkPolicyController) getInternalGroupWorkloads(group *antreatypes.Group) ([]*v1.Pod, []*v1alpha2.ExternalEntity, error) {
	validateNamespace := func(pods []*v1.Pod, ees []*v1alpha2.ExternalEntity) bool {
		// ClusterGroup can select entities in all Namespaces when used as AppliedTo.
		if group.SourceReference.Namespace == "" {
			return true
		}
		// Namespaced Group can only select entities in the same Namespace as the Group when used as AppliedTo.
		if group.SourceReference.Namespace != "" {
			for _, pod := range pods {
				if pod.Namespace != group.SourceReference.Namespace {
					return false
				}
			}
			for _, ee := range ees {
				if ee.Namespace != group.SourceReference.Namespace {
					return false
				}
			}
		}
		return true
	}

	if len(group.ChildGroups) == 0 {
		pods, ees := n.groupingInterface.GetEntities(internalGroupType, group.SourceReference.ToGroupName())
		if !validateNamespace(pods, ees) {
			return nil, nil, &ErrNetworkPolicyAppliedToUnsupportedGroup{groupName: group.SourceReference.Name, namespace: group.SourceReference.Namespace}
		}
		return pods, ees, nil
	}
	podNameSet, eeNameSet := sets.Set[string]{}, sets.Set[string]{}
	var pods []*v1.Pod
	var ees []*v1alpha2.ExternalEntity
	for _, childName := range group.ChildGroups {
		// childNameString will either be name of the child ClusterGroup or Namespaced name of the child Group.
		childNameString := k8s.NamespacedName(group.SourceReference.Namespace, childName)
		childPods, childEEs := n.groupingInterface.GetEntities(internalGroupType, childNameString)
		if !validateNamespace(childPods, childEEs) {
			return nil, nil, &ErrNetworkPolicyAppliedToUnsupportedGroup{groupName: group.SourceReference.Name, namespace: group.SourceReference.Namespace}
		}
		for _, pod := range childPods {
			podString := k8s.NamespacedName(pod.Namespace, pod.Name)
			if !podNameSet.Has(podString) {
				podNameSet.Insert(podString)
				pods = append(pods, pod)
			}
		}
		for _, ee := range childEEs {
			eeString := k8s.NamespacedName(ee.Namespace, ee.Name)
			if !eeNameSet.Has(eeString) {
				eeNameSet.Insert(eeString)
				ees = append(ees, ee)
			}
		}
	}
	return pods, ees, nil
}

func (n *NetworkPolicyController) triggerPolicyResyncForLabelIdentityUpdates(key string) {
	klog.V(2).InfoS("Resyncing policy for LabelIdentity events", "policy", key)
	internalNPObj, found, _ := n.internalNetworkPolicyStore.Get(key)
	if !found {
		return
	}
	n.enqueueInternalNetworkPolicy(internalNPObj.(*antreatypes.NetworkPolicy).SourceRef)
}

// syncInternalNetworkPolicy retrieves all the AppliedToGroups associated with
// itself in order to calculate the Node span for this policy.
func (n *NetworkPolicyController) syncInternalNetworkPolicy(key *controlplane.NetworkPolicyReference) error {
	internalNetworkPolicyName := string(key.UID)
	klog.V(2).InfoS("Syncing internal NetworkPolicy", "key", key)
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.DurationInternalNetworkPolicySyncing.Observe(float64(d.Milliseconds()))
		klog.V(2).InfoS("Finished syncing internal NetworkPolicy", "key", key, "duration", d)
	}()

	var newInternalNetworkPolicy *antreatypes.NetworkPolicy
	var newAppliedToGroups map[string]*antreatypes.AppliedToGroup
	var newAddressGroups map[string]*antreatypes.AddressGroup

	switch key.Type {
	case controlplane.AntreaClusterNetworkPolicy:
		acnp, err := n.acnpLister.Get(key.Name)
		// We need to check if the UID matches because it's possible another policy is created with the same name after
		// the policy is deleted. It's safe to just delete the internal NetworkPolicy associated with the old policy as
		// the two policies are different items in the workqueue and internalNetworkPolicyStore due to different UIDs.
		if err != nil || acnp.UID != key.UID {
			n.deleteInternalNetworkPolicy(internalNetworkPolicyName)
			return nil
		}
		newInternalNetworkPolicy, newAppliedToGroups, newAddressGroups = n.processClusterNetworkPolicy(acnp)
	case controlplane.AntreaNetworkPolicy:
		annp, err := n.annpLister.NetworkPolicies(key.Namespace).Get(key.Name)
		if err != nil || annp.UID != key.UID {
			n.deleteInternalNetworkPolicy(internalNetworkPolicyName)
			return nil
		}
		newInternalNetworkPolicy, newAppliedToGroups, newAddressGroups = n.processAntreaNetworkPolicy(annp)
	case controlplane.K8sNetworkPolicy:
		knp, err := n.networkPolicyLister.NetworkPolicies(key.Namespace).Get(key.Name)
		if err != nil || knp.UID != key.UID {
			n.deleteInternalNetworkPolicy(internalNetworkPolicyName)
			return nil
		}
		newInternalNetworkPolicy, newAppliedToGroups, newAddressGroups = n.processNetworkPolicy(knp)
	case controlplane.AdminNetworkPolicy:
		anp, err := n.adminNetworkPolicyLister.Get(key.Name)
		if err != nil || anp.UID != key.UID {
			n.deleteInternalNetworkPolicy(internalNetworkPolicyName)
			return nil
		}
		newInternalNetworkPolicy, newAppliedToGroups, newAddressGroups = n.processAdminNetworkPolicy(anp)
	case controlplane.BaselineAdminNetworkPolicy:
		banp, err := n.banpLister.Get(key.Name)
		if err != nil || banp.UID != key.UID {
			n.deleteInternalNetworkPolicy(internalNetworkPolicyName)
			return nil
		}
		newInternalNetworkPolicy, newAppliedToGroups, newAddressGroups = n.processBaselineAdminNetworkPolicy(banp)
	}

	// The NetworkPolicy must subscribe to the updates of AppliedToGroups before calculating span based on them,
	// otherwise the calculated span may be outdated as AppliedToGroups can be updated concurrently and the
	// NetworkPolicy wouldn't be notified.
	for group := range newAppliedToGroups {
		n.appliedToGroupNotifier.subscribe(group, internalNetworkPolicyName, func() {
			n.enqueueInternalNetworkPolicy(key)
		})
	}

	newNodeNames, err := func() (sets.Set[string], error) {
		nodeNames := sets.New[string]()
		// Calculate the set of Node names based on the span of the
		// AppliedToGroups referenced by this NetworkPolicy.
		for appliedToGroupName := range newAppliedToGroups {
			appGroupObj, found, _ := n.appliedToGroupStore.Get(appliedToGroupName)
			if !found {
				continue
			}
			appGroup := appGroupObj.(*antreatypes.AppliedToGroup)
			if appGroup.SyncError != nil {
				return nil, appGroup.SyncError
			}
			utilsets.MergeString(nodeNames, appGroup.SpanMeta.NodeNames)
		}
		return nodeNames, nil
	}()
	if err != nil {
		klog.ErrorS(err, "Error when processing AppliedToGroups for internal NetworkPolicy", "key", key)
		newInternalNetworkPolicy.SyncError = err
	} else {
		newInternalNetworkPolicy.NodeNames = newNodeNames
	}

	var oldInternalNetworkPolicy *antreatypes.NetworkPolicy
	oldInternalNetworkPolicyObj, oldInternalPolicyExists, _ := n.internalNetworkPolicyStore.Get(internalNetworkPolicyName)
	if oldInternalPolicyExists {
		oldInternalNetworkPolicy = oldInternalNetworkPolicyObj.(*antreatypes.NetworkPolicy)
	}

	// appliedToGroupsToSync tracks new AppliedToGroups created by this NetworkPolicy.
	appliedToGroupsToSync := sets.New[string]()

	// Create the internal NetworkPolicy, AppliedToGroups and AddressGroups if they don't exist. They need to be updated
	// atomically to avoid race conditions between workers that process multiple NetworkPolicies.
	func() {
		n.internalNetworkPolicyMutex.Lock()
		defer n.internalNetworkPolicyMutex.Unlock()

		if !oldInternalPolicyExists {
			klog.V(2).InfoS("Creating internal NetworkPolicy", "name", internalNetworkPolicyName, "spanNodes", newInternalNetworkPolicy.NodeNames.Len())
			n.internalNetworkPolicyStore.Create(newInternalNetworkPolicy)
		} else {
			klog.V(2).InfoS("Updating internal NetworkPolicy", "name", internalNetworkPolicyName, "spanNodes", newInternalNetworkPolicy.NodeNames.Len())
			n.internalNetworkPolicyStore.Update(newInternalNetworkPolicy)
		}

		for name, appliedToGroup := range newAppliedToGroups {
			_, found, _ := n.appliedToGroupStore.Get(name)
			// AppliedToGroup is named based on its selector, so only its members can change.
			// We don't need to update its selector if it already exists.
			if found {
				continue
			}
			klog.V(2).InfoS("Creating new AppliedToGroup", "name", name, "uid", appliedToGroup.UID, "selector", appliedToGroup.Selector, "service", appliedToGroup.Service)
			n.appliedToGroupStore.Create(appliedToGroup)
			if appliedToGroup.Selector != nil {
				n.groupingInterface.AddGroup(appliedToGroupType, appliedToGroup.Name, appliedToGroup.Selector)
			}
			appliedToGroupsToSync.Insert(name)
		}
		for name, addressGroup := range newAddressGroups {
			_, found, _ := n.addressGroupStore.Get(name)
			// AddressGroup is named based on its selector, so only its members can change.
			// We don't need to update its selector if it already exists.
			if found {
				continue
			}
			klog.V(2).InfoS("Creating new AddressGroup", "name", name, "uid", addressGroup.UID, "selector", addressGroup.Selector)
			n.addressGroupStore.Create(addressGroup)
			// For an AddressGroup that selects Nodes via nodeSelector, we calculate its members via NodeLister
			// directly, instead of groupingInterface which handles Pod and ExternalEntity currently.
			if addressGroup.Selector != nil && addressGroup.Selector.NodeSelector == nil {
				n.groupingInterface.AddGroup(addressGroupType, addressGroup.Name, addressGroup.Selector)
			}
		}

		// Clean up orphan AddressGroups and AppliedToGroups that are no longer referenced by any NetworkPolicy.
		if oldInternalNetworkPolicy != nil {
			n.cleanupOrphanGroups(oldInternalNetworkPolicy)
		}
	}()

	// Enqueue AppliedToGroups that are newly created for this NetworkPolicy.
	for appliedToGroup := range appliedToGroupsToSync {
		n.enqueueAppliedToGroup(appliedToGroup)
	}

	// Enqueue AddressGroups that are affected by this NetworkPolicy.
	var oldNodeNames sets.Set[string]
	var oldAddressGroupNames sets.Set[string]
	var oldAppliedToGroupNames sets.Set[string]
	if oldInternalNetworkPolicy != nil {
		oldNodeNames = oldInternalNetworkPolicy.NodeNames
		oldAddressGroupNames = oldInternalNetworkPolicy.GetAddressGroups()
		oldAppliedToGroupNames = oldInternalNetworkPolicy.GetAppliedToGroups()
	}
	var addressGroupsToSync sets.Set[string]
	newAddressGroupNames := sets.KeySet(newAddressGroups)
	if !newNodeNames.Equal(oldNodeNames) {
		addressGroupsToSync = oldAddressGroupNames.Union(newAddressGroupNames)
		klog.V(4).InfoS("Internal NetworkPolicy's Node span changed, enqueuing all related AddressGroups", "NetworkPolicy", key, "AddressGroups", addressGroupsToSync)
	} else {
		addressGroupsToSync = utilsets.SymmetricDifferenceString(oldAddressGroupNames, newAddressGroupNames)
		klog.V(4).InfoS("Internal NetworkPolicy's Node span did not change, enqueuing all changed AddressGroups", "NetworkPolicy", key, "AddressGroups", addressGroupsToSync)
	}
	for addressGroup := range addressGroupsToSync {
		n.enqueueAddressGroup(addressGroup)
	}
	// Unsubscribe to the updates of the stale AppliedToGroups.
	for name := range oldAppliedToGroupNames {
		if _, exists := newAppliedToGroups[name]; !exists {
			n.appliedToGroupNotifier.unsubscribe(name, internalNetworkPolicyName)
		}
	}
	return nil
}

// deleteInternalNetworkPolicy deletes the internal NetworkPolicy and the referenced AppliedToGroups and AddressGroups
// if they are no longer referenced by any NetworkPolicy. They need to be updated atomically to avoid race conditions
// between workers that process multiple NetworkPolicies.
func (n *NetworkPolicyController) deleteInternalNetworkPolicy(name string) {
	n.internalNetworkPolicyMutex.Lock()
	defer n.internalNetworkPolicyMutex.Unlock()

	obj, exists, _ := n.internalNetworkPolicyStore.Get(name)
	if !exists {
		return
	}
	internalNetworkPolicy := obj.(*antreatypes.NetworkPolicy)
	n.internalNetworkPolicyStore.Delete(internalNetworkPolicy.Name)
	n.cleanupOrphanGroups(internalNetworkPolicy)
	// Unsubscribe to the updates of the AppliedToGroups.
	for appliedToGroup := range internalNetworkPolicy.GetAppliedToGroups() {
		n.appliedToGroupNotifier.unsubscribe(appliedToGroup, name)
	}
	if n.stretchNPEnabled && internalNetworkPolicy.SourceRef.Type != controlplane.K8sNetworkPolicy {
		n.labelIdentityInterface.DeletePolicySelectors(internalNetworkPolicy.Name)
	}
	// Enqueue AddressGroups previously used by this NetworkPolicy as their span may change due to the removal.
	for agName := range internalNetworkPolicy.GetAddressGroups() {
		n.enqueueAddressGroup(agName)
	}
}

// cleanupOrphanGroups deletes AddressGroups and AppliedToGroups that are no longer referenced by any NetworkPolicy.
func (n *NetworkPolicyController) cleanupOrphanGroups(internalNetworkPolicy *antreatypes.NetworkPolicy) {
	for atgName := range internalNetworkPolicy.GetAppliedToGroups() {
		objs, _ := n.internalNetworkPolicyStore.GetByIndex(store.AppliedToGroupIndex, atgName)
		if len(objs) == 0 {
			n.appliedToGroupStore.Delete(atgName)
			n.groupingInterface.DeleteGroup(appliedToGroupType, atgName)
		}
	}
	for agName := range internalNetworkPolicy.GetAddressGroups() {
		objs, _ := n.internalNetworkPolicyStore.GetByIndex(store.AddressGroupIndex, agName)
		if len(objs) == 0 {
			n.addressGroupStore.Delete(agName)
			n.groupingInterface.DeleteGroup(addressGroupType, agName)
		}
	}
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

// internalGroupKeyFunc knows how to generate the key for an internal Group based on the object metadata
// of the corresponding Group and ClusterGroup resource. Currently the Name of the ClusterGroup is used to ensure
// uniqueness. Similarly, the Namespaced Name of the Group is used to ensure uniqueness for the Group resource.
func internalGroupKeyFunc(obj metav1.Object) string {
	if len(obj.GetNamespace()) > 0 {
		return obj.GetNamespace() + "/" + obj.GetName()
	}
	return obj.GetName()
}

func getAppliedToGroupNames(groups []*antreatypes.AppliedToGroup) []string {
	if groups == nil {
		return nil
	}
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

func getAddressGroupNames(groups []*antreatypes.AddressGroup) []string {
	if groups == nil {
		return nil
	}
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.Name)
	}
	return names
}

func mergeAppliedToGroups(dst map[string]*antreatypes.AppliedToGroup, src ...*antreatypes.AppliedToGroup) map[string]*antreatypes.AppliedToGroup {
	for _, group := range src {
		dst[group.Name] = group
	}
	return dst
}

func mergeAddressGroups(dst map[string]*antreatypes.AddressGroup, src ...*antreatypes.AddressGroup) map[string]*antreatypes.AddressGroup {
	for _, group := range src {
		dst[group.Name] = group
	}
	return dst
}

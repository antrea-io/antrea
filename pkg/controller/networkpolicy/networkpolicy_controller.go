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

	uuid "github.com/satori/go.uuid"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	"antrea.io/antrea/pkg/apis/controlplane"
	secv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	secinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdv1a3informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha3"
	seclisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdv1a3listers "antrea.io/antrea/pkg/client/listers/crd/v1alpha3"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/metrics"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/features"
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

	appliedToGroupType grouping.GroupType = "appliedToGroup"
	addressGroupType   grouping.GroupType = "addressGroup"
	clusterGroupType   grouping.GroupType = "clusterGroup"
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

	cgInformer crdv1a3informers.ClusterGroupInformer
	// cgLister is able to list/get ClusterGroups and is populated by the shared informer passed to
	// NewClusterGroupController.
	cgLister crdv1a3listers.ClusterGroupLister
	// cgListerSynced is a function which returns true if the ClusterGroup shared informer has been synced at least
	// once.
	cgListerSynced cache.InformerSynced

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

	// internalNetworkPolicyMutex protects the internalNetworkPolicyStore from
	// concurrent access during updates to the internal NetworkPolicy object.
	internalNetworkPolicyMutex sync.RWMutex

	groupingInterface grouping.Interface
	// Added as a member to the struct to allow injection for testing.
	groupingInterfaceSynced func() bool
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
		tr, ok := obj.(*secv1alpha1.Tier)
		if !ok {
			return []string{}, nil
		}
		return []string{strconv.FormatInt(int64(tr.Spec.Priority), 10)}, nil
	},
}

var cnpIndexers = cache.Indexers{
	TierIndex: func(obj interface{}) ([]string, error) {
		cnp, ok := obj.(*secv1alpha1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		return []string{cnp.Spec.Tier}, nil
	},
	ClusterGroupIndex: func(obj interface{}) ([]string, error) {
		cnp, ok := obj.(*secv1alpha1.ClusterNetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		groupNames := sets.String{}
		for _, appTo := range cnp.Spec.AppliedTo {
			if appTo.Group != "" {
				groupNames.Insert(appTo.Group)
			}
		}
		if len(cnp.Spec.Ingress) == 0 && len(cnp.Spec.Egress) == 0 {
			return groupNames.List(), nil
		}
		appendGroups := func(rule secv1alpha1.Rule) {
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
		for _, rule := range cnp.Spec.Egress {
			appendGroups(rule)
		}
		for _, rule := range cnp.Spec.Ingress {
			appendGroups(rule)
		}
		return groupNames.List(), nil
	},
}

var anpIndexers = cache.Indexers{
	TierIndex: func(obj interface{}) ([]string, error) {
		anp, ok := obj.(*secv1alpha1.NetworkPolicy)
		if !ok {
			return []string{}, nil
		}
		return []string{anp.Spec.Tier}, nil
	},
}

// NewNetworkPolicyController returns a new *NetworkPolicyController.
func NewNetworkPolicyController(kubeClient clientset.Interface,
	crdClient versioned.Interface,
	groupingInterface grouping.Interface,
	namespaceInformer coreinformers.NamespaceInformer,
	serviceInformer coreinformers.ServiceInformer,
	networkPolicyInformer networkinginformers.NetworkPolicyInformer,
	cnpInformer secinformers.ClusterNetworkPolicyInformer,
	anpInformer secinformers.NetworkPolicyInformer,
	tierInformer secinformers.TierInformer,
	cgInformer crdv1a3informers.ClusterGroupInformer,
	addressGroupStore storage.Interface,
	appliedToGroupStore storage.Interface,
	internalNetworkPolicyStore storage.Interface,
	internalGroupStore storage.Interface) *NetworkPolicyController {
	n := &NetworkPolicyController{
		kubeClient:                 kubeClient,
		crdClient:                  crdClient,
		networkPolicyInformer:      networkPolicyInformer,
		networkPolicyLister:        networkPolicyInformer.Lister(),
		networkPolicyListerSynced:  networkPolicyInformer.Informer().HasSynced,
		addressGroupStore:          addressGroupStore,
		appliedToGroupStore:        appliedToGroupStore,
		internalNetworkPolicyStore: internalNetworkPolicyStore,
		internalGroupStore:         internalGroupStore,
		appliedToGroupQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "appliedToGroup"),
		addressGroupQueue:          workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "addressGroup"),
		internalNetworkPolicyQueue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalNetworkPolicy"),
		internalGroupQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "internalGroup"),
		groupingInterface:          groupingInterface,
		groupingInterfaceSynced:    groupingInterface.HasSynced,
	}
	n.groupingInterface.AddEventHandler(appliedToGroupType, n.enqueueAppliedToGroup)
	n.groupingInterface.AddEventHandler(addressGroupType, n.enqueueAddressGroup)
	n.groupingInterface.AddEventHandler(clusterGroupType, n.enqueueInternalGroup)
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
		n.namespaceInformer = namespaceInformer
		n.namespaceLister = namespaceInformer.Lister()
		n.namespaceListerSynced = namespaceInformer.Informer().HasSynced
		n.serviceInformer = serviceInformer
		n.serviceLister = serviceInformer.Lister()
		n.serviceListerSynced = serviceInformer.Informer().HasSynced
		n.cnpInformer = cnpInformer
		n.cnpLister = cnpInformer.Lister()
		n.cnpListerSynced = cnpInformer.Informer().HasSynced
		n.anpInformer = anpInformer
		n.anpLister = anpInformer.Lister()
		n.anpListerSynced = anpInformer.Informer().HasSynced
		n.tierInformer = tierInformer
		n.tierLister = tierInformer.Lister()
		n.tierListerSynced = tierInformer.Informer().HasSynced
		n.cgInformer = cgInformer
		n.cgLister = cgInformer.Lister()
		n.cgListerSynced = cgInformer.Informer().HasSynced
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
		tierInformer.Informer().AddIndexers(tierIndexers)
		cnpInformer.Informer().AddIndexers(cnpIndexers)
		cnpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addCNP,
				UpdateFunc: n.updateCNP,
				DeleteFunc: n.deleteCNP,
			},
			resyncPeriod,
		)
		anpInformer.Informer().AddIndexers(anpIndexers)
		anpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    n.addANP,
				UpdateFunc: n.updateANP,
				DeleteFunc: n.deleteANP,
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
	return uuid.NewV5(uuidNamespace, name).String()
}

// createAppliedToGroup creates an AppliedToGroup object in store if it is not created already.
func (n *NetworkPolicyController) createAppliedToGroup(npNsName string, pSel, nSel, eSel *metav1.LabelSelector) string {
	groupSelector := antreatypes.NewGroupSelector(npNsName, pSel, nSel, eSel)
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
	n.groupingInterface.AddGroup(appliedToGroupType, newAppliedToGroup.Name, groupSelector)
	n.enqueueAppliedToGroup(appliedToGroupUID)
	return appliedToGroupUID
}

// createAddressGroup creates an AddressGroup object corresponding to a
// NetworkPolicyPeer object in NetworkPolicyRule. This function simply
// creates the object without actually populating the PodAddresses as the
// affected GroupMembers are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroup(namespace string, podSelector, nsSelector, eeSelector *metav1.LabelSelector) string {
	groupSelector := antreatypes.NewGroupSelector(namespace, podSelector, nsSelector, eeSelector)
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
	n.groupingInterface.AddGroup(addressGroupType, addressGroup.Name, groupSelector)
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
		allPodsGroupUID := n.createAddressGroup(np.Namespace, matchAllPodsPeer.PodSelector, matchAllPodsPeer.NamespaceSelector, nil)
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
			normalizedUID := n.createAddressGroup(np.Namespace, peer.PodSelector, peer.NamespaceSelector, nil)
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

// deleteDereferencedAddressGroups deletes the AddressGroup keys which are no
// longer referenced by any internal NetworPolicy.
func (n *NetworkPolicyController) deleteDereferencedAddressGroups(internalNP *antreatypes.NetworkPolicy) {
	addressGroupKeys := sets.String{}
	for _, rule := range internalNP.Rules {
		// Populate AddressGroupKeys for ingress rules.
		addressGroupKeys.Insert(rule.From.AddressGroups...)
		// Populate AddressGroupKeys for egress rules.
		addressGroupKeys.Insert(rule.To.AddressGroups...)
	}
	// Delete any AddressGroup key which is no longer referenced by any internal
	// NetworkPolicy.
	for key := range addressGroupKeys {
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
			n.groupingInterface.DeleteGroup(addressGroupType, key)
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
		n.groupingInterface.DeleteGroup(appliedToGroupType, key)
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
	defer n.internalGroupQueue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{n.networkPolicyListerSynced, n.groupingInterfaceSynced}
	// Only wait for cnpListerSynced and anpListerSynced when AntreaPolicy feature gate is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		cacheSyncs = append(cacheSyncs, n.cnpListerSynced, n.anpListerSynced, n.cgListerSynced)
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
		klog.V(2).Infof("AddressGroup %s not found", key)
		return nil
	}
	addressGroup := addressGroupObj.(*antreatypes.AddressGroup)
	// NodeNames set must be considered immutable once generated and updated
	// in the store. If any change is needed, the set must be regenerated with
	// the new NodeNames and the store must be updated.
	addrGroupNodeNames := sets.String{}
	for _, internalNPObj := range nps {
		internalNP := internalNPObj.(*antreatypes.NetworkPolicy)
		utilsets.MergeString(addrGroupNodeNames, internalNP.SpanMeta.NodeNames)
	}
	memberSet := n.getAddressGroupMemberSet(addressGroup)
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

// getAddressGroupMemberSet knows how to construct a GroupMemberSet that contains
// all the entities selected by an AddressGroup.
func (n *NetworkPolicyController) getAddressGroupMemberSet(g *antreatypes.AddressGroup) controlplane.GroupMemberSet {
	// Check if an internal Group object exists corresponding to this AddressGroup.
	groupObj, found, _ := n.internalGroupStore.Get(g.Name)
	if found {
		// This AddressGroup is derived from a ClusterGroup.
		group := groupObj.(*antreatypes.Group)
		return n.getClusterGroupMemberSet(group)
	}
	return n.getMemberSetForGroupType(addressGroupType, g.Name)
}

// getClusterGroupMemberSet knows how to construct a GroupMemberSet that contains
// all the entities selected by a ClusterGroup. For ClusterGroup that has childGroups,
// the members are computed as the union of all its childGroup's members.
func (n *NetworkPolicyController) getClusterGroupMemberSet(group *antreatypes.Group) controlplane.GroupMemberSet {
	if len(group.ChildGroups) == 0 {
		return n.getMemberSetForGroupType(clusterGroupType, group.Name)
	}
	groupMemberSet := controlplane.GroupMemberSet{}
	for _, childName := range group.ChildGroups {
		childGroup, found, _ := n.internalGroupStore.Get(childName)
		if found {
			child := childGroup.(*antreatypes.Group)
			groupMemberSet.Merge(n.getMemberSetForGroupType(clusterGroupType, child.Name))
		}
	}
	return groupMemberSet
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
		groupMemberSet.Insert(externalEntityToGroupMember(ee))
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
	pods, externalEntities := n.getAppliedToWorkloads(appliedToGroup)
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

// getAppliedToWorkloads returns a list of workloads (Pods and ExternalEntities) selected by an AppliedToGroup
// for standalone selectors or corresponding to a ClusterGroup.
func (n *NetworkPolicyController) getAppliedToWorkloads(g *antreatypes.AppliedToGroup) ([]*v1.Pod, []*v1alpha2.ExternalEntity) {
	// Check if an internal Group object exists corresponding to this AppliedToGroup.
	group, found, _ := n.internalGroupStore.Get(g.Name)
	if found {
		// This AppliedToGroup is derived from a ClusterGroup.
		grp := group.(*antreatypes.Group)
		return n.getClusterGroupWorkloads(grp)
	}
	return n.groupingInterface.GetEntities(appliedToGroupType, g.Name)
}

// getClusterGroupWorkloads returns a list of workloads (Pods and ExternalEntities) selected by a ClusterGroup.
// For ClusterGroup that has childGroups, the workloads are computed as the union of all its childGroup's workloads.
func (n *NetworkPolicyController) getClusterGroupWorkloads(group *antreatypes.Group) ([]*v1.Pod, []*v1alpha2.ExternalEntity) {
	if len(group.ChildGroups) == 0 {
		return n.groupingInterface.GetEntities(clusterGroupType, group.Name)
	}
	podNameSet, eeNameSet := sets.String{}, sets.String{}
	var pods []*v1.Pod
	var ees []*v1alpha2.ExternalEntity
	for _, childName := range group.ChildGroups {
		childPods, childEEs := n.groupingInterface.GetEntities(clusterGroupType, childName)
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
	return pods, ees
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
		utilsets.MergeString(nodeNames, appGroup.SpanMeta.NodeNames)
	}
	updatedNetworkPolicy := &antreatypes.NetworkPolicy{
		UID:                   internalNP.UID,
		Name:                  internalNP.Name,
		SourceRef:             internalNP.SourceRef,
		Rules:                 internalNP.Rules,
		AppliedToGroups:       internalNP.AppliedToGroups,
		Priority:              internalNP.Priority,
		TierPriority:          internalNP.TierPriority,
		AppliedToPerRule:      internalNP.AppliedToPerRule,
		PerNamespaceSelectors: internalNP.PerNamespaceSelectors,
		SpanMeta:              antreatypes.SpanMeta{NodeNames: nodeNames},
		Generation:            internalNP.Generation,
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

// internalGroupKeyFunc knows how to generate the key for an internal Group based on the object metadata
// of the corresponding ClusterGroup resource. Currently the Name of the ClusterGroup is used to ensure uniqueness.
func internalGroupKeyFunc(obj metav1.Object) string {
	return obj.GetName()
}

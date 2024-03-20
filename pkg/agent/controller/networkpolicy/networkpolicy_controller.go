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
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"antrea.io/ofnet/ofctrl"
	"github.com/spf13/afero"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/networkpolicy/l7engine"
	"antrea.io/antrea/pkg/agent/flowexporter/connections"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	proxytypes "antrea.io/antrea/pkg/agent/proxy/types"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/controlplane/install"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/channel"
	utilwait "antrea.io/antrea/pkg/util/wait"
)

const (
	// How long to wait before retrying the processing of a network policy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a rule change.
	defaultWorkers = 4
	// Default number of workers for making DNS queries.
	defaultDNSWorkers = 4
	// Reserved OVS rule ID for installing the DNS response intercept rule.
	// It is a special OVS rule which intercepts DNS query responses from DNS
	// services to the workloads that have FQDN policy rules applied.
	dnsInterceptRuleID = uint32(1)
)

const (
	dataPath           = "/var/run/antrea/networkpolicy"
	networkPoliciesDir = "network-policies"
	appliedToGroupsDir = "applied-to-groups"
	addressGroupsDir   = "address-groups"
)

type L7RuleReconciler interface {
	AddRule(ruleID, policyName string, vlanID uint32, l7Protocols []v1beta2.L7Protocol, enableLogging bool) error
	DeleteRule(ruleID string, vlanID uint32) error
}

var emptyWatch = watch.NewEmptyWatch()

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	install.Install(scheme)
}

type packetInAction func(*ofctrl.PacketIn) error

// Controller is responsible for watching Antrea AddressGroups, AppliedToGroups,
// and NetworkPolicies, feeding them to ruleCache, getting dirty rules from
// ruleCache, invoking reconcilers to reconcile them.
//
//	        a.Feed AddressGroups,AppliedToGroups
//	             and NetworkPolicies
//	|-----------|    <--------    |----------- |  c. Reconcile dirty rules |----------- |
//	| ruleCache |                 | Controller |     ------------>         | reconciler |
//	| ----------|    -------->    |----------- |                           |----------- |
//	            b. Notify dirty rules
type Controller struct {
	// antreaPolicyEnabled indicates whether Antrea NetworkPolicy and
	// ClusterNetworkPolicy are enabled.
	antreaPolicyEnabled      bool
	l7NetworkPolicyEnabled   bool
	nodeNetworkPolicyEnabled bool
	// antreaProxyEnabled indicates whether Antrea proxy is enabled.
	antreaProxyEnabled bool
	// statusManagerEnabled indicates whether a statusManager is configured.
	statusManagerEnabled bool
	// multicastEnabled indicates whether multicast is enabled.
	multicastEnabled bool
	// nodeType indicates type of the Node where Antrea Agent is running on.
	nodeType config.NodeType
	// antreaClientProvider provides interfaces to get antreaClient, which can be
	// used to watch Antrea AddressGroups, AppliedToGroups, and NetworkPolicies.
	// We need to get antreaClient dynamically because the apiserver cert can be
	// rotated and we need a new client with the updated CA cert.
	// Verifying server certificate only takes place for new requests and existing
	// watches won't be interrupted by rotating cert. The new client will be used
	// after the existing watches expire.
	antreaClientProvider agent.AntreaClientProvider
	// queue maintains the NetworkPolicy ruleIDs that need to be synced.
	queue workqueue.RateLimitingInterface
	// ruleCache maintains the desired state of NetworkPolicy rules.
	ruleCache *ruleCache
	// podReconciler provides interfaces to reconcile the desired state of
	// NetworkPolicy rules with the actual state of Openflow entries.
	podReconciler Reconciler
	// nodeReconciler provides interfaces to reconcile the desired state of
	// NetworkPolicy rules with the actual state of iptables entries.
	nodeReconciler Reconciler
	// l7RuleReconciler provides interfaces to reconcile the desired state of
	// NetworkPolicy rules which have L7 rules with the actual state of Suricata rules.
	l7RuleReconciler L7RuleReconciler
	// l7VlanIDAllocator allocates a VLAN ID for every L7 rule.
	l7VlanIDAllocator *l7VlanIDAllocator
	// ofClient registers packetin for Antrea Policy logging.
	ofClient    openflow.Client
	auditLogger *AuditLogger
	// statusManager syncs NetworkPolicy statuses with the antrea-controller.
	// It's only for Antrea NetworkPolicies.
	statusManager         StatusManager
	fqdnController        *fqdnController
	networkPolicyWatcher  *watcher
	appliedToGroupWatcher *watcher
	addressGroupWatcher   *watcher
	fullSyncGroup         sync.WaitGroup
	ifaceStore            interfacestore.InterfaceStore
	// denyConnStore is for storing deny connections for flow exporter.
	denyConnStore  *connections.DenyConnectionStore
	gwPort         uint32
	tunPort        uint32
	nodeConfig     *config.NodeConfig
	podNetworkWait *utilwait.Group

	// The fileStores store runtime.Objects in files and use them as the fallback data source when agent can't connect
	// to antrea-controller on startup.
	networkPolicyStore  *fileStore
	appliedToGroupStore *fileStore
	addressGroupStore   *fileStore

	logPacketAction           packetInAction
	rejectRequestAction       packetInAction
	storeDenyConnectionAction packetInAction
}

// NewNetworkPolicyController returns a new *Controller.
func NewNetworkPolicyController(antreaClientGetter agent.AntreaClientProvider,
	ofClient openflow.Client,
	routeClient route.Interface,
	ifaceStore interfacestore.InterfaceStore,
	fs afero.Fs,
	nodeName string,
	podUpdateSubscriber channel.Subscriber,
	externalEntityUpdateSubscriber channel.Subscriber,
	groupCounters []proxytypes.GroupCounter,
	groupIDUpdates <-chan string,
	antreaPolicyEnabled bool,
	l7NetworkPolicyEnabled bool,
	nodeNetworkPolicyEnabled bool,
	antreaProxyEnabled bool,
	statusManagerEnabled bool,
	multicastEnabled bool,
	loggerOptions *AuditLoggerOptions, // use nil to disable logging
	asyncRuleDeleteInterval time.Duration,
	dnsServerOverride string,
	nodeType config.NodeType,
	v4Enabled bool,
	v6Enabled bool,
	gwPort, tunPort uint32,
	nodeConfig *config.NodeConfig,
	podNetworkWait *utilwait.Group,
	l7Reconciler *l7engine.Reconciler) (*Controller, error) {
	idAllocator := newIDAllocator(asyncRuleDeleteInterval, dnsInterceptRuleID)
	c := &Controller{
		antreaClientProvider:     antreaClientGetter,
		queue:                    workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicyrule"),
		ofClient:                 ofClient,
		nodeType:                 nodeType,
		antreaPolicyEnabled:      antreaPolicyEnabled,
		l7NetworkPolicyEnabled:   l7NetworkPolicyEnabled,
		nodeNetworkPolicyEnabled: nodeNetworkPolicyEnabled,
		antreaProxyEnabled:       antreaProxyEnabled,
		statusManagerEnabled:     statusManagerEnabled,
		multicastEnabled:         multicastEnabled,
		gwPort:                   gwPort,
		tunPort:                  tunPort,
		nodeConfig:               nodeConfig,
		podNetworkWait:           podNetworkWait.Increment(),
	}

	if l7NetworkPolicyEnabled {
		c.l7RuleReconciler = l7Reconciler
		c.l7VlanIDAllocator = newL7VlanIDAllocator()
	}

	var err error
	if antreaPolicyEnabled {
		if c.fqdnController, err = newFQDNController(ofClient, idAllocator, dnsServerOverride, c.enqueueRule, v4Enabled, v6Enabled, gwPort); err != nil {
			return nil, err
		}

		if c.ofClient != nil {
			c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryDNS), c.fqdnController)
		}
	}
	c.podReconciler = newPodReconciler(ofClient, ifaceStore, idAllocator, c.fqdnController, groupCounters,
		v4Enabled, v6Enabled, antreaPolicyEnabled, multicastEnabled)

	if c.nodeNetworkPolicyEnabled {
		c.nodeReconciler = newNodeReconciler(routeClient, v4Enabled, v6Enabled)
	}
	c.ruleCache = newRuleCache(c.enqueueRule, podUpdateSubscriber, externalEntityUpdateSubscriber, groupIDUpdates, nodeType)

	serializer := protobuf.NewSerializer(scheme, scheme)
	codec := codecs.CodecForVersions(serializer, serializer, v1beta2.SchemeGroupVersion, v1beta2.SchemeGroupVersion)
	fs = afero.NewBasePathFs(fs, dataPath)
	c.networkPolicyStore, err = newFileStore(fs, networkPoliciesDir, codec)
	if err != nil {
		return nil, fmt.Errorf("error creating file store for NetworkPolicy: %w", err)
	}
	c.appliedToGroupStore, err = newFileStore(fs, appliedToGroupsDir, codec)
	if err != nil {
		return nil, fmt.Errorf("error creating file store for AppliedToGroup: %w", err)
	}
	c.addressGroupStore, err = newFileStore(fs, addressGroupsDir, codec)
	if err != nil {
		return nil, fmt.Errorf("error creating file store for AddressGroup: %w", err)
	}

	if statusManagerEnabled {
		c.statusManager = newStatusController(antreaClientGetter, nodeName, c.ruleCache)
	}
	// Create a WaitGroup that is used to block network policy workers from asynchronously processing
	// NP rules until the events preceding bookmark are synced. It can also be used as part of the
	// solution to a deterministic mechanism for when to cleanup flows from previous round.
	// Wait until appliedToGroupWatcher, addressGroupWatcher and networkPolicyWatcher to receive bookmark event.
	c.fullSyncGroup.Add(3)

	if c.ofClient != nil {
		// Register packetInHandler
		c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInCategoryNP), c)
		if loggerOptions != nil {
			// Initialize logger for Antrea Policy audit logging
			auditLogger, err := newAuditLogger(loggerOptions)
			if err != nil {
				return nil, err
			}
			c.auditLogger = auditLogger
		}
	}

	// Use nodeName to filter resources when watching resources.
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", nodeName).String(),
	}

	c.networkPolicyWatcher = &watcher{
		objectType: "NetworkPolicy",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().NetworkPolicies().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && v1beta2.IsSourceAntreaNativePolicy(policy.SourceRef) {
				klog.InfoS("Ignore Antrea-native policy since AntreaPolicy feature gate is not enabled",
					"policyName", policy.SourceRef.ToString())
				return nil
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if err := c.networkPolicyStore.save(policy); err != nil {
				klog.ErrorS(err, "Failed to store the NetworkPolicy to file", "policyName", policy.SourceRef.ToString())
			}
			c.ruleCache.AddNetworkPolicy(policy)
			klog.InfoS("NetworkPolicy applied to Pods on this Node or the Node itself", "policyName", policy.SourceRef.ToString())
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && v1beta2.IsSourceAntreaNativePolicy(policy.SourceRef) {
				klog.InfoS("Ignore Antrea-native policy since AntreaPolicy feature gate is not enabled",
					"policyName", policy.SourceRef.ToString())
				return nil
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if err := c.networkPolicyStore.save(policy); err != nil {
				klog.ErrorS(err, "Failed to store the NetworkPolicy to file", "policyName", policy.SourceRef.ToString())
			}
			updated := c.ruleCache.UpdateNetworkPolicy(policy)
			// If any rule or the generation changes, we ensure statusManager will resync the policy's status once, in
			// case the changes don't cause any actual rule update but the whole policy's generation is changed.
			if c.statusManagerEnabled && updated && v1beta2.IsSourceAntreaNativePolicy(policy.SourceRef) {
				c.statusManager.Resync(policy.UID)
			}
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && v1beta2.IsSourceAntreaNativePolicy(policy.SourceRef) {
				klog.InfoS("Ignore Antrea-native policy since AntreaPolicy feature gate is not enabled",
					"policyName", policy.SourceRef.ToString())
				return nil
			}
			c.ruleCache.DeleteNetworkPolicy(policy)
			klog.InfoS("NetworkPolicy no longer applied to Pods on this Node", "policyName", policy.SourceRef.ToString())
			if err := c.networkPolicyStore.save(policy); err != nil {
				klog.ErrorS(err, "Failed to delete the NetworkPolicy from file", "policyName", policy.SourceRef.ToString())
			}
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			policies := make([]*v1beta2.NetworkPolicy, len(objs))
			var ok bool
			for i := range objs {
				policies[i], ok = objs[i].(*v1beta2.NetworkPolicy)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", objs[i])
				}
				if !c.antreaPolicyEnabled && v1beta2.IsSourceAntreaNativePolicy(policies[i].SourceRef) {
					klog.InfoS("Ignore Antrea-native policy since AntreaPolicy feature gate is not enabled",
						"policyName", policies[i].SourceRef.ToString())
					return nil
				}
				klog.InfoS("NetworkPolicy applied to Pods on this Node", "policyName", policies[i].SourceRef.ToString())
				// When ReplaceFunc is called, either the controller restarted or this was a regular reconnection.
				// For the former case, agent must resync the statuses as the controller lost the previous statuses.
				// For the latter case, agent doesn't need to do anything. However, we are not able to differentiate the
				// two cases. Anyway there's no harm to do a periodical resync.
				if c.statusManagerEnabled && v1beta2.IsSourceAntreaNativePolicy(policies[i].SourceRef) {
					c.statusManager.Resync(policies[i].UID)
				}
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if err := c.networkPolicyStore.replaceAll(objs); err != nil {
				klog.ErrorS(err, "Failed to store the NetworkPolicies to files")
			}
			c.ruleCache.ReplaceNetworkPolicies(policies)
			return nil
		},
		FallbackFunc:      c.networkPolicyStore.loadAll,
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}

	c.appliedToGroupWatcher = &watcher{
		objectType: "AppliedToGroup",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().AppliedToGroups().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AppliedToGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", obj)
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if err := c.appliedToGroupStore.save(group); err != nil {
				klog.ErrorS(err, "Failed to store the AppliedToGroup to file", "groupName", group.Name)
			}
			c.ruleCache.AddAppliedToGroup(group)
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			patch, ok := obj.(*v1beta2.AppliedToGroupPatch)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroupPatch: %v", obj)
			}
			group, err := c.ruleCache.PatchAppliedToGroup(patch)
			if err != nil {
				return err
			}
			// It's fine to store the object to file after applying the patch to ruleCache because the returned object
			// is newly created, and ruleCache itself doesn't use it.
			if err := c.appliedToGroupStore.save(group); err != nil {
				klog.ErrorS(err, "Failed to store the AppliedToGroup to file", "groupName", group.Name)
			}
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AppliedToGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", obj)
			}
			c.ruleCache.DeleteAppliedToGroup(group)
			if err := c.appliedToGroupStore.delete(group); err != nil {
				klog.ErrorS(err, "Failed to delete the AppliedToGroup from file", "groupName", group.Name)
			}
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			groups := make([]*v1beta2.AppliedToGroup, len(objs))
			var ok bool
			for i := range objs {
				groups[i], ok = objs[i].(*v1beta2.AppliedToGroup)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", objs[i])
				}
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if c.appliedToGroupStore.replaceAll(objs); err != nil {
				klog.ErrorS(err, "Failed to store the AppliedToGroups to files")
			}
			c.ruleCache.ReplaceAppliedToGroups(groups)
			return nil
		},
		FallbackFunc:      c.appliedToGroupStore.loadAll,
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}

	c.addressGroupWatcher = &watcher{
		objectType: "AddressGroup",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().AddressGroups().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AddressGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", obj)
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if err := c.addressGroupStore.save(group); err != nil {
				klog.ErrorS(err, "Failed to store the AddressGroup to file", "groupName", group.Name)
			}
			c.ruleCache.AddAddressGroup(group)
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			patch, ok := obj.(*v1beta2.AddressGroupPatch)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroupPatch: %v", obj)
			}
			group, err := c.ruleCache.PatchAddressGroup(patch)
			if err != nil {
				return err
			}
			// It's fine to store the object to file after applying the patch to ruleCache because the returned object
			// is newly created, and ruleCache itself doesn't use it.
			if err := c.addressGroupStore.save(group); err != nil {
				klog.ErrorS(err, "Failed to store the AddressGroup to file", "groupName", group.Name)
			}
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AddressGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", obj)
			}
			c.ruleCache.DeleteAddressGroup(group)
			if err := c.addressGroupStore.delete(group); err != nil {
				klog.ErrorS(err, "Failed to delete the AddressGroup from file", "groupName", group.Name)
			}
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			groups := make([]*v1beta2.AddressGroup, len(objs))
			var ok bool
			for i := range objs {
				groups[i], ok = objs[i].(*v1beta2.AddressGroup)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", objs[i])
				}
			}
			// Storing the object to file first because its GroupVersionKind can be updated in-place during
			// serialization, which may incur data race if we add it to ruleCache first.
			if c.addressGroupStore.replaceAll(objs); err != nil {
				klog.ErrorS(err, "Failed to store the AddressGroups to files")
			}
			c.ruleCache.ReplaceAddressGroups(groups)
			return nil
		},
		FallbackFunc:      c.addressGroupStore.loadAll,
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}
	c.ifaceStore = ifaceStore
	c.logPacketAction = c.logPacket
	c.rejectRequestAction = c.rejectRequest
	c.storeDenyConnectionAction = c.storeDenyConnection
	return c, nil
}

func (c *Controller) GetNetworkPolicyNum() int {
	return c.ruleCache.GetNetworkPolicyNum()
}

func (c *Controller) GetAddressGroupNum() int {
	return c.ruleCache.GetAddressGroupNum()
}

func (c *Controller) GetAppliedToGroupNum() int {
	return c.ruleCache.GetAppliedToGroupNum()
}

// GetNetworkPolicies returns the requested NetworkPolicies.
// This func will return all NetworkPolicies that can match all provided attributes in NetworkPolicyQueryFilter.
// These not provided attributes in NetworkPolicyQueryFilter means match all.
func (c *Controller) GetNetworkPolicies(npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	return c.ruleCache.getNetworkPolicies(npFilter)
}

// GetAppliedNetworkPolicies returns the NetworkPolicies applied to the Pod and match the filter.
func (c *Controller) GetAppliedNetworkPolicies(pod, namespace string, npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	return c.ruleCache.getAppliedNetworkPolicies(pod, namespace, npFilter)
}

func (c *Controller) GetAddressGroups() []v1beta2.AddressGroup {
	return c.ruleCache.GetAddressGroups()
}

func (c *Controller) GetAppliedToGroups() []v1beta2.AppliedToGroup {
	return c.ruleCache.GetAppliedToGroups()
}

func (c *Controller) GetNetworkPolicyByRuleFlowID(ruleFlowID uint32) *v1beta2.NetworkPolicyReference {
	rule := c.GetRuleByFlowID(ruleFlowID)
	if rule == nil {
		return nil
	}
	return rule.PolicyRef
}

func (c *Controller) GetRuleByFlowID(ruleFlowID uint32) *types.PolicyRule {
	rule, exists, err := c.podReconciler.GetRuleByFlowID(ruleFlowID)
	if err != nil {
		klog.Errorf("Error when getting network policy by rule flow ID: %v", err)
		return nil
	}
	if !exists {
		return nil
	}
	return rule
}

func (c *Controller) GetControllerConnectionStatus() bool {
	// When the watchers are connected, controller connection status is true. Otherwise, it is false.
	return c.addressGroupWatcher.isConnected() && c.appliedToGroupWatcher.isConnected() && c.networkPolicyWatcher.isConnected()
}

func (c *Controller) SetDenyConnStore(denyConnStore *connections.DenyConnectionStore) {
	c.denyConnStore = denyConnStore
}

// Run begins watching and processing Antrea AddressGroups, AppliedToGroups
// and NetworkPolicies, and spawns workers that reconciles NetworkPolicy rules.
// Run will not return until stopCh is closed.
func (c *Controller) Run(stopCh <-chan struct{}) {
	attempts := 0
	if err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		if attempts%10 == 0 {
			klog.Info("Waiting for Antrea client to be ready")
		}
		if _, err := c.antreaClientProvider.GetAntreaClient(); err != nil {
			attempts++
			return false, nil
		}
		return true, nil
	}); err != nil {
		klog.Info("Stopped waiting for Antrea client")
		return
	}
	klog.Info("Antrea client is ready")

	// Use NonSlidingUntil so that normal reconnection (disconnected after
	// running a while) can reconnect immediately while abnormal reconnection
	// won't be too aggressive.
	go wait.NonSlidingUntil(c.appliedToGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.addressGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.networkPolicyWatcher.watch, 5*time.Second, stopCh)

	if c.antreaPolicyEnabled {
		for i := 0; i < defaultDNSWorkers; i++ {
			go wait.Until(c.fqdnController.worker, time.Second, stopCh)
		}
		go c.fqdnController.runRuleSyncTracker(stopCh)
	}
	klog.Infof("Waiting for all watchers to complete full sync")
	c.fullSyncGroup.Wait()
	klog.Infof("All watchers have completed full sync, installing flows for init events")
	// Batch install all rules in queue after fullSync is finished.
	c.processAllItemsInQueue()
	c.podNetworkWait.Done()

	klog.Infof("Starting NetworkPolicy workers now")
	defer c.queue.ShutDown()
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	klog.Infof("Starting IDAllocator worker to maintain the async rule cache")
	go c.podReconciler.RunIDAllocatorWorker(stopCh)

	if c.statusManagerEnabled {
		go c.statusManager.Run(stopCh)
	}

	<-stopCh
}

func (c *Controller) matchIGMPType(r *rule, igmpType uint8, groupAddress string) bool {
	for _, s := range r.Services {
		if (s.IGMPType == nil || uint8(*s.IGMPType) == igmpType) && (s.GroupAddress == "" || s.GroupAddress == groupAddress) {
			return true
		}
	}
	return false
}

// GetIGMPNPRuleInfo looks up the IGMP NetworkPolicy rule that matches the given Pod and groupAddress,
// and returns the rule information if found.
func (c *Controller) GetIGMPNPRuleInfo(podName, podNamespace string, groupAddress net.IP, igmpType uint8) (*types.IGMPNPRuleInfo, error) {
	member := &v1beta2.GroupMember{
		Pod: &v1beta2.PodReference{
			Name:      podName,
			Namespace: podNamespace,
		},
	}

	var ruleInfo *types.IGMPNPRuleInfo
	objects, _ := c.ruleCache.rules.ByIndex(toIGMPReportGroupAddressIndex, groupAddress.String())
	objects2, _ := c.ruleCache.rules.ByIndex(toIGMPReportGroupAddressIndex, "")
	objects = append(objects, objects2...)
	var matchedRule *rule
	for _, obj := range objects {
		rule := obj.(*rule)
		groupMembers, anyExists := c.ruleCache.unionAppliedToGroups(rule.AppliedToGroups)
		if !anyExists {
			continue
		}
		if groupMembers.Has(member) && (matchedRule == nil || matchedRule.Less(rule)) &&
			c.matchIGMPType(rule, igmpType, groupAddress.String()) {
			matchedRule = rule
		}
	}

	if matchedRule != nil {
		ruleInfo = &types.IGMPNPRuleInfo{
			RuleAction: *matchedRule.Action,
			UUID:       matchedRule.PolicyUID,
			NPType:     &matchedRule.SourceRef.Type,
			Name:       matchedRule.Name,
		}
	}
	return ruleInfo, nil
}

func (c *Controller) enqueueRule(ruleID string) {
	c.queue.Add(ruleID)
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same rule at
// the same time.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncRule(key.(string))
	c.handleErr(err, key)

	return true
}

// processAllItemsInQueue pops all rule keys queued at the moment and calls syncRules to
// reconcile those rules in batch.
func (c *Controller) processAllItemsInQueue() {
	numRules := c.queue.Len()
	batchSyncRuleKeys := make([]string, numRules)
	for i := 0; i < numRules; i++ {
		ruleKey, _ := c.queue.Get()
		batchSyncRuleKeys[i] = ruleKey.(string)
		// set key to done to prevent missing watched updates between here and fullSync finish.
		c.queue.Done(ruleKey)
	}
	// Reconcile all rule keys at once.
	if err := c.syncRules(batchSyncRuleKeys); err != nil {
		klog.Errorf("Error occurred when reconciling all rules for init events: %v", err)
		for _, k := range batchSyncRuleKeys {
			c.queue.AddRateLimited(k)
		}
	}
}

func (c *Controller) syncRule(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing rule", "ruleID", key, "duration", time.Since(startTime))
	}()
	rule, effective, realizable := c.ruleCache.GetCompletedRule(key)
	if !effective {
		klog.V(2).InfoS("Rule was not effective, removing it", "ruleID", key)
		// Uncertain whether this rule applies to a Node or Pod, but it's safe to delete it redundantly.
		if err := c.podReconciler.Forget(key); err != nil {
			return err
		}
		if c.nodeNetworkPolicyEnabled {
			if err := c.nodeReconciler.Forget(key); err != nil {
				return err
			}
		}
		if c.statusManagerEnabled {
			// We don't know whether this is a rule owned by Antrea Policy, but
			// harmless to delete it.
			c.statusManager.DeleteRuleRealization(key)
		}
		if c.l7NetworkPolicyEnabled {
			if vlanID := c.l7VlanIDAllocator.query(key); vlanID != 0 {
				if err := c.l7RuleReconciler.DeleteRule(key, vlanID); err != nil {
					return err
				}
				c.l7VlanIDAllocator.release(key)
			}
		}
		return nil
	}
	// If the rule is not realizable, we can simply skip it as it will be marked as dirty
	// and queued again when we receive the missing group it missed.
	if !realizable {
		klog.V(2).InfoS("Rule is not realizable, skipping", "ruleID", key)
		return nil
	}

	isNodeNetworkPolicy := rule.isNodeNetworkPolicyRule()
	if !c.nodeNetworkPolicyEnabled && isNodeNetworkPolicy {
		klog.Warningf("Feature gate NodeNetworkPolicy is not enabled, skipping ruleID %s", key)
		return nil
	}

	if c.l7NetworkPolicyEnabled && len(rule.L7Protocols) != 0 {
		// Allocate VLAN ID for the L7 rule.
		vlanID := c.l7VlanIDAllocator.allocate(key)
		rule.L7RuleVlanID = &vlanID

		if err := c.l7RuleReconciler.AddRule(key, rule.SourceRef.ToString(), vlanID, rule.L7Protocols, rule.EnableLogging); err != nil {
			return err
		}
	}

	var err error
	if isNodeNetworkPolicy {
		err = c.nodeReconciler.Reconcile(rule)
	} else {
		err = c.podReconciler.Reconcile(rule)
		if c.fqdnController != nil {
			// No matter whether the rule reconciliation succeeds or not, fqdnController
			// needs to be notified of the status.
			klog.V(2).InfoS("Rule realization was done", "ruleID", key)
			c.fqdnController.notifyRuleUpdate(key, err)
		}
	}
	if err != nil {
		return err
	}
	if c.statusManagerEnabled && v1beta2.IsSourceAntreaNativePolicy(rule.SourceRef) {
		c.statusManager.SetRuleRealization(key, rule.PolicyUID)
	}
	return nil
}

// syncRules calls the reconciler to sync all the rules after watchers complete full sync.
// After flows for those init events are installed, subsequent rules will be handled asynchronously
// by the syncRule() function.
func (c *Controller) syncRules(keys []string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing all rules before bookmark event (%v)", time.Since(startTime))
	}()

	var allPodRules, allNodeRules []*CompletedRule
	for _, key := range keys {
		rule, effective, realizable := c.ruleCache.GetCompletedRule(key)
		// It's normal that a rule is not effective on this Node but abnormal that it is not realizable after watchers
		// complete full sync.
		if !effective {
			klog.Infof("Rule %s is not effective on this Node", key)
		} else if !realizable {
			klog.Errorf("Rule %s is effective but not realizable", key)
		} else {
			isNodeNetworkPolicy := rule.isNodeNetworkPolicyRule()
			if !c.nodeNetworkPolicyEnabled && isNodeNetworkPolicy {
				klog.Warningf("Feature gate NodeNetworkPolicy is not enabled, skipping ruleID %s", key)
				continue
			}
			if c.l7NetworkPolicyEnabled && len(rule.L7Protocols) != 0 {
				// Allocate VLAN ID for the L7 rule.
				vlanID := c.l7VlanIDAllocator.allocate(key)
				rule.L7RuleVlanID = &vlanID

				if err := c.l7RuleReconciler.AddRule(key, rule.SourceRef.ToString(), vlanID, rule.L7Protocols, rule.EnableLogging); err != nil {
					return err
				}
			}
			if isNodeNetworkPolicy {
				allNodeRules = append(allNodeRules, rule)
			} else {
				allPodRules = append(allPodRules, rule)
			}
		}
	}
	if c.nodeNetworkPolicyEnabled {
		if err := c.nodeReconciler.BatchReconcile(allNodeRules); err != nil {
			return err
		}
	}
	if err := c.podReconciler.BatchReconcile(allPodRules); err != nil {
		return err
	}
	if c.statusManagerEnabled {
		for _, rule := range allPodRules {
			if v1beta2.IsSourceAntreaNativePolicy(rule.SourceRef) {
				c.statusManager.SetRuleRealization(rule.ID, rule.PolicyUID)
			}
		}
		if c.nodeNetworkPolicyEnabled {
			for _, rule := range allNodeRules {
				if v1beta2.IsSourceAntreaNativePolicy(rule.SourceRef) {
					c.statusManager.SetRuleRealization(rule.ID, rule.PolicyUID)
				}
			}
		}
	}
	return nil
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	klog.Errorf("Error syncing rule %q, retrying. Error: %v", key, err)
	c.queue.AddRateLimited(key)
}

// watcher is responsible for watching a given resource with the provided watchFunc
// and calling the eventHandlers when receiving events.
type watcher struct {
	// objectType is the type of objects being watched, used for logging.
	objectType string
	// watchFunc is the function that starts the watch.
	watchFunc func() (watch.Interface, error)
	// AddFunc is the function that handles added event.
	AddFunc func(obj runtime.Object) error
	// UpdateFunc is the function that handles modified event.
	UpdateFunc func(obj runtime.Object) error
	// DeleteFunc is the function that handles deleted event.
	DeleteFunc func(obj runtime.Object) error
	// ReplaceFunc is the function that handles init events.
	ReplaceFunc func(objs []runtime.Object) error
	// FallbackFunc is the function that provides the data when it can't start the watch successfully.
	FallbackFunc func() ([]runtime.Object, error)
	// connected represents whether the watch has connected to apiserver successfully.
	connected bool
	// lock protects connected.
	lock sync.RWMutex
	// group to be notified when each watcher receives bookmark event
	fullSyncWaitGroup *sync.WaitGroup
	// fullSynced indicates if the resource has been synced at least once since agent started.
	fullSynced bool
}

func (w *watcher) isConnected() bool {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return w.connected
}

func (w *watcher) setConnected(connected bool) {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.connected = connected
}

// fallback gets init events from the FallbackFunc if the watcher hasn't been synced once.
func (w *watcher) fallback() {
	// If the watcher has been synced once, the fallback data source doesn't have newer data, do nothing.
	if w.fullSynced {
		return
	}
	klog.InfoS("Getting init events for %s from fallback", w.objectType)
	objects, err := w.FallbackFunc()
	if err != nil {
		klog.ErrorS(err, "Failed to get init events for %s from fallback", w.objectType)
		return
	}
	if err := w.ReplaceFunc(objects); err != nil {
		klog.ErrorS(err, "Failed to handle init events")
		return
	}
	w.onFullSync()
}

func (w *watcher) onFullSync() {
	if !w.fullSynced {
		w.fullSynced = true
		// Notify fullSyncWaitGroup that all events before bookmark is handled
		w.fullSyncWaitGroup.Done()
	}
}

func (w *watcher) watch() {
	klog.Infof("Starting watch for %s", w.objectType)
	watcher, err := w.watchFunc()
	if err != nil {
		klog.Warningf("Failed to start watch for %s: %v", w.objectType, err)
		w.fallback()
		return
	}
	// Watch method doesn't return error but "emptyWatch" in case of some partial data errors,
	// e.g. timeout error. Make sure that watcher is not empty and log warning otherwise.
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.Warningf("Failed to start watch for %s, please ensure antrea service is reachable for the agent", w.objectType)
		w.fallback()
		return
	}

	klog.Infof("Started watch for %s", w.objectType)
	w.setConnected(true)
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watch for %s, total items received: %d", w.objectType, eventCount)
		w.setConnected(false)
		watcher.Stop()
	}()

	// First receive init events from the result channel and buffer them until
	// a Bookmark event is received, indicating that all init events have been
	// received.
	var initObjects []runtime.Object
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for %s was closed", w.objectType)
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added %s (%#v)", w.objectType, event.Object)
				initObjects = append(initObjects, event.Object)
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for %s", len(initObjects), w.objectType)

	eventCount += len(initObjects)
	if err := w.ReplaceFunc(initObjects); err != nil {
		klog.Errorf("Failed to handle init events: %v", err)
		return
	}
	w.onFullSync()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			klog.V(2).InfoS("Received event", "eventType", event.Type, "objectType", w.objectType, "object", event.Object)
			switch event.Type {
			case watch.Added:
				if err := w.AddFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle added event: %v", err)
					return
				}
			case watch.Modified:
				if err := w.UpdateFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle modified event: %v", err)
					return
				}
			case watch.Deleted:
				if err := w.DeleteFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle deleted event: %v", err)
					return
				}
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}

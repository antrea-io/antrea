// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intermediate

import (
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/pkg/flowaggregator/flowrecord"
)

const gatewayIPIndex = "gatewayIPIndex"

var NodeIndexers = cache.Indexers{
	// gatewayIPIndex extracts Gateway IPs from nodes on the cluster.
	gatewayIPIndex: func(obj interface{}) ([]string, error) {
		node, ok := obj.(*v1.Node)
		if !ok {
			return nil, fmt.Errorf("object is not a Node: %T", obj)
		}

		podCIDR := node.Spec.PodCIDR
		if podCIDR == "" {
			return nil, fmt.Errorf("podCIDR is nil")
		}
		prefix, err := netip.ParsePrefix(podCIDR)
		if err != nil {
			return nil, fmt.Errorf("could not parse pod CIDR %s for node %s: %v", podCIDR, node.Name, err)
		}
		return []string{prefix.Addr().Next().String()}, nil
	},
}

// ttl threshold for expiring flows.
var defaultTTL = time.Minute

// defaultCleanUpInterval is the frequency in which we run the cleanup for expiring stale flows.
var defaultCleanUpInterval = time.Second * 5

type fromExternalAggregator struct {
	FromExternalStore map[string]flowItem
	nodeIndexer       cache.Indexer
	stopCh            chan struct{}
	stopOnce          sync.Once
	lock              sync.RWMutex
	ttl               time.Duration
	cleanUpInterval   time.Duration
}

type option func(*fromExternalAggregator)

func newFromExternalAggregator(nodeIndexer cache.Indexer, opts ...option) *fromExternalAggregator {
	stopCh := make(chan struct{})
	a := &fromExternalAggregator{
		FromExternalStore: make(map[string]flowItem),
		nodeIndexer:       nodeIndexer,
		stopCh:            stopCh,
		ttl:               defaultTTL,
		cleanUpInterval:   defaultCleanUpInterval,
	}

	for _, opt := range opts {
		opt(a)
	}

	go a.cleanUpLoop(stopCh)
	return a
}

// correlateOrStore returns the correlated record. If correlation is not needed, the original inputs are returned
// unchanged. If the record needs to be stored for future correlation, nil is returned.
func (a *fromExternalAggregator) correlateOrStore(flowKey *FlowKey, record *flowpb.Flow) (*FlowKey, *flowpb.Flow) {
	if !a.fromExternalCorrelationRequired(record) {
		return flowKey, record
	}
	if a.storeIfNew(record) {
		return nil, nil
	}
	record = a.correlateExternal(record)
	flowKey, _ = getFlowKeyFromRecord(record)

	return flowKey, record
}

// flowItem wraps a zone zero connection along with it's timestamp use for expiring flows.
type flowItem struct {
	flow      *flowpb.Flow
	timestamp time.Time
}

// cleanUpLoop runs in an infinite loop and cleans up the store at the given interval.
func (a *fromExternalAggregator) cleanUpLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(a.cleanUpInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			a.cleanup(a.ttl)
		}
	}
}

// cleanup loops through the entire store and deleting connections that exceed the ttl.
func (a *fromExternalAggregator) cleanup(ttl time.Duration) {
	a.lock.Lock()
	defer a.lock.Unlock()
	now := time.Now()
	for key, record := range a.FromExternalStore {
		if now.Sub(record.timestamp) > ttl {
			delete(a.FromExternalStore, key)
		}
	}
}

// stop kills the goroutine running cleanup of expiring flows.
func (a *fromExternalAggregator) stop() {
	a.stopOnce.Do(func() {
		if a.stopCh != nil {
			close(a.stopCh)
		}
	})
}

// isCorrelationRequired returns true for InterNode flowType when
// either the egressNetworkPolicyRuleAction is not deny (drop/reject) or
// the ingressNetworkPolicyRuleAction is not reject.
func isCorrelationRequired(record *flowpb.Flow) bool {
	flowType := record.K8S.FlowType
	return flowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE &&
		record.K8S.EgressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP &&
		record.K8S.EgressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT &&
		record.K8S.IngressNetworkPolicyRuleAction != flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT
}

// Returns true if the given ip is a Gateway IP from one of the nodes on the cluster.
// If there are errors, they are logged and false is returned.
func (a *fromExternalAggregator) isGateway(ip []byte) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		klog.Errorf("Failed to determine if ip is gateway. IP %v could not be converted to Addr", ip)
		return false
	}

	objs, err := a.nodeIndexer.ByIndex(gatewayIPIndex, addr.String())
	if err != nil {
		klog.Errorf("failed to query Node indexer: %v", err)
		return false
	}

	if len(objs) == 0 {
		return false
	}

	return true
}

// Returns true if record is FromExternal and represents the flow created from
// an external connection where the sourceNode and destinationNode are the same.
// When a flow goes through two distinct nodes, the sourceNode flow has empty destinationNode
// and the destinationNode has the gatewayIP as the sourceAddress. If flow is invalid, false
// is returned
func (a *fromExternalAggregator) fromExternalCorrelationRequired(flow *flowpb.Flow) bool {
	if flow.K8S == nil || flow.K8S.FlowType != flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL {
		return false
	}
	if flow.Ip == nil {
		klog.Errorf("Failed to determine correlation of FromExternal record required. Ip missing from flow %v", flow)
		return false
	}
	// DestinationNode flows have source IP as the gateway
	if a.isGateway(flow.Ip.Source) {
		return true
	}
	// SourceNode flows do not have podName
	if flow.K8S == nil || flow.K8S.DestinationPodName == "" {
		return true
	}
	return false
}

// Return a key unique to the pair of flows that make up a FromExternal flow
func (a *fromExternalAggregator) generateFromExternalStoreKey(record *flowpb.Flow) string {
	var gateway string
	var SNATPort string

	if a.isGateway(record.Ip.Source) {
		// Is Destination Flow
		gateway = flowrecord.IpAddressAsString(record.Ip.Source)
		SNATPort = strconv.FormatUint(uint64(record.Transport.SourcePort), 10)
	} else {
		// Is SourceFlow
		gateway = flowrecord.IpAddressAsString(record.ProxySnatIp)
		SNATPort = strconv.FormatUint(uint64(record.ProxySnatPort), 10)
	}

	destinationAddress := flowrecord.IpAddressAsString(record.Ip.Destination)
	destinationPort := strconv.FormatUint(uint64(record.Transport.DestinationPort), 10)

	return fmt.Sprintf("%s-%s-%s-%s",
		SNATPort,
		gateway,
		destinationAddress,
		destinationPort,
	)
}

// If FromExternal flow is not yet in the store, add it and return true.
// If the flow is in the store, return false
func (a *fromExternalAggregator) storeIfNew(flow *flowpb.Flow) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	key := a.generateFromExternalStoreKey(flow)
	if _, exists := a.FromExternalStore[key]; !exists {
		// TODO ADD method?
		a.FromExternalStore[key] = flowItem{
			flow:      flow,
			timestamp: time.Now(),
		}
		return true
	}
	return false
}

// Return a correlated flow from the given flow and it's matching record from the store. Returns
// nil if there was no matching flow in store. Upon successful correlation, delete the flow from
// the store.
func (a *fromExternalAggregator) correlateExternal(flow *flowpb.Flow) *flowpb.Flow {
	a.lock.Lock()
	defer a.lock.Unlock()
	key := a.generateFromExternalStoreKey(flow)
	storedFlowItem, exists := a.FromExternalStore[key]
	if !exists {
		return nil
	}
	storedFlow := storedFlowItem.flow
	delete(a.FromExternalStore, key)
	if a.isGateway(flow.Ip.Source) {
		flow.Ip.Source = storedFlow.Ip.Source
		if flow.K8S != nil {
			flow.K8S.DestinationServiceIp = storedFlow.K8S.DestinationServiceIp
			flow.K8S.DestinationServicePortName = storedFlow.K8S.DestinationServicePortName
			flow.K8S.DestinationServicePort = storedFlow.K8S.DestinationServicePort
			flow.K8S.DestinationClusterIp = storedFlow.K8S.DestinationClusterIp
		}
		return flow
	} else {
		storedFlow.Ip.Source = flow.Ip.Source
		if storedFlow.K8S != nil {
			storedFlow.K8S.DestinationServiceIp = flow.K8S.DestinationServiceIp
			storedFlow.K8S.DestinationServicePortName = flow.K8S.DestinationServicePortName
			storedFlow.K8S.DestinationServicePort = flow.K8S.DestinationServicePort
			storedFlow.K8S.DestinationClusterIp = flow.K8S.DestinationClusterIp
		}
		return storedFlow
	}
}

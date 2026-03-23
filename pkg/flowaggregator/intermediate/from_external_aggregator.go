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
	// gatewayIPIndex extracts gateway IPs from nodes on the cluster.
	// For each PodCIDR the gateway is assumed to be the first host
	// address (prefix base + 1). An empty slice is returned when no
	// PodCIDR is set yet (e.g. Node just joined the cluster).
	gatewayIPIndex: func(obj interface{}) ([]string, error) {
		node, ok := obj.(*v1.Node)
		if !ok {
			return nil, fmt.Errorf("object is not a Node: %T", obj)
		}
		podCIDRs := node.Spec.PodCIDRs
		if len(podCIDRs) == 0 {
			if node.Spec.PodCIDR != "" {
				podCIDRs = []string{node.Spec.PodCIDR}
			} else {
				return nil, nil
			}
		}
		gatewayIPs := make([]string, 0, len(podCIDRs))
		for _, cidr := range podCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				klog.ErrorS(err, "Could not parse PodCIDR for Node", "node", node.Name, "podCIDR", cidr)
				continue
			}
			gatewayIPs = append(gatewayIPs, prefix.Addr().Next().String())
		}
		return gatewayIPs, nil
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

// correlateOrStore returns the correlated record. If correlation is not
// needed, the original inputs are returned unchanged. If the record needs to
// be stored for future correlation, nil is returned.
func (a *fromExternalAggregator) correlateOrStore(flowKey *FlowKey, record *flowpb.Flow) (*FlowKey, *flowpb.Flow) {
	if !a.fromExternalCorrelationRequired(record) {
		return flowKey, record
	}

	matchedFlow := a.storeIfNew(record)
	if matchedFlow == nil {
		klog.V(4).InfoS("Stored from-external flow for correlation")
		return nil, nil
	}

	klog.V(4).InfoS("Correlating from-external flow")
	record = a.mergeExternalFlows(record, matchedFlow)
	flowKey, _ = getFlowKeyFromRecord(record)
	return flowKey, record
}

// mergeExternalFlows merges the incoming flow with the previously stored
// counterpart. The destination-node flow (whose source is the gateway)
// receives the original external source IP and service metadata from the
// source-node flow.
func (a *fromExternalAggregator) mergeExternalFlows(incoming, stored *flowpb.Flow) *flowpb.Flow {
	if a.isGateway(incoming.Ip.Source) {
		incoming.Ip.Source = stored.Ip.Source
		if incoming.K8S != nil {
			incoming.K8S.DestinationServiceIp = stored.K8S.DestinationServiceIp
			incoming.K8S.DestinationServicePortName = stored.K8S.DestinationServicePortName
			incoming.K8S.DestinationServicePort = stored.K8S.DestinationServicePort
			incoming.K8S.DestinationClusterIp = stored.K8S.DestinationClusterIp
		}
		return incoming
	}
	stored.Ip.Source = incoming.Ip.Source
	if stored.K8S != nil {
		stored.K8S.DestinationServiceIp = incoming.K8S.DestinationServiceIp
		stored.K8S.DestinationServicePortName = incoming.K8S.DestinationServicePortName
		stored.K8S.DestinationServicePort = incoming.K8S.DestinationServicePort
		stored.K8S.DestinationClusterIp = incoming.K8S.DestinationClusterIp
	}
	return stored
}

// flowItem wraps a zone-zero connection along with its timestamp used for expiring flows.
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

// cleanup loops through the entire store and deletes entries that exceed the ttl.
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

// isGateway returns true if the given ip is a gateway IP for one of the
// cluster Nodes. Returns false when the nodeIndexer is nil or on errors.
func (a *fromExternalAggregator) isGateway(ip []byte) bool {
	if a.nodeIndexer == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		klog.ErrorS(nil, "Failed to determine if IP is gateway: could not convert to Addr", "ip", ip)
		return false
	}
	objs, err := a.nodeIndexer.ByIndex(gatewayIPIndex, addr.String())
	if err != nil {
		klog.ErrorS(err, "Failed to query Node indexer")
		return false
	}
	return len(objs) > 0
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
		klog.ErrorS(nil, "Cannot determine FromExternal correlation: IP missing from flow")
		return false
	}
	// DestinationNode flows have source IP as the gateway
	if a.isGateway(flow.Ip.Source) {
		return true
	}
	// SourceNode flows do not have podName
	if flow.K8S.DestinationPodName == "" {
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

// storeIfNew atomically stores the flow when no matching key exists and
// returns nil. When a matching key already exists, it deletes the stored
// entry and returns the previously stored flow. This ensures the
// store-or-correlate decision is race-free under a single lock.
func (a *fromExternalAggregator) storeIfNew(flow *flowpb.Flow) *flowpb.Flow {
	a.lock.Lock()
	defer a.lock.Unlock()

	key := a.generateFromExternalStoreKey(flow)
	existing, exists := a.FromExternalStore[key]
	if !exists {
		a.FromExternalStore[key] = flowItem{
			flow:      flow,
			timestamp: time.Now(),
		}
		return nil
	}
	delete(a.FromExternalStore, key)
	return existing.flow
}

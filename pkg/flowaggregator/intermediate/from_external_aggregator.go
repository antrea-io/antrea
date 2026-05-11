// Copyright 2026 Antrea Authors
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
	"strconv"
	"sync"
	"time"

	"k8s.io/klog/v2"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/flowrecord"
)

const (
	// defaultTTL is the threshold for expiring FROM_EXTERNAL source-node flows that never
	// found their destination-node counterpart.
	defaultTTL = time.Minute
	// defaultCleanUpInterval is how often the background cleanup runs.
	defaultCleanUpInterval = 5 * time.Second
)

// fromExternalAggregator handles correlation of inter-node external-to-Pod connections.
//
// The two flow halves:
//   - Source-node (FlowType=FROM_EXTERNAL): Ip.Source=externalClientIP,
//     ProxySnatIp=sourceNodeGatewayIP, ProxySnatPort=snatPort, DestinationPodName=""
//     (pod is on the remote node).
//   - Destination-node (FlowType=INTER_NODE, agent srcIsGw branch): Ip.Source=gatewayIP,
//     Transport.SourcePort=snatPort, DestinationPodName set, ProxySnatIp unset.
//
// Both halves share the same correlation key:
//   - Source-node  → (ProxySnatIp=gatewayIP, ProxySnatPort=snatPort, dstPodIP, dstPort)
//   - Destination-node → (Ip.Source=gatewayIP, SourcePort=snatPort, dstPodIP, dstPort)
//
// This correlation key is identical to the FlowKey value under which the destination-node
// INTER_NODE flow is stored in flowKeyRecordMap.
//
// # Correlation strategy:
// Destination-node INTER_NODE arrives first:
//  1. correlateOrStore passes it through unchanged.
//  2. addOrUpdateRecordInMap inserts it into flowKeyRecordMap using the correlation key
//     described above.
//  3. addOrUpdateRecordInMap immediately probes fromExternalStore with the same correlation
//     key. Nothing there yet → record stays pending (ReadyToSend=false).
//
// Source-node FROM_EXTERNAL arrives (before or after the destination node flow):
//  1. correlateOrStore stores it in fromExternalStore and returns (nil,nil).
//  2. addOrUpdateRecordInMap (seeing nil flowKey) then looks up flowKeyRecordMap using the
//     correlation key derived from the source-node flow's ProxySnatIp/Port.
//     - If the destination-node INTER_NODE entry exists: mergeExternalFlows is called in-place,
//     the entry is re-keyed from (gatewayIP,...) to (externalIP,clientPort,...), and
//     ReadyToSend is set to true → exported immediately.
//     - If not: the source-node flow stays in fromExternalStore. When the destination-node flow
//     arrives later (case above), step 3 picks it up and merges, exported immediately.
//
// In both orderings the merge is instant — no polling, no retries, no agent-timer dependency.
type fromExternalAggregator struct {
	lock              sync.Mutex
	fromExternalStore map[string]flowItem
	ttl               time.Duration
	cleanUpInterval   time.Duration
}

// flowItem stores a FROM_EXTERNAL source-node flow together with its insertion timestamp.
type flowItem struct {
	flow      *flowpb.Flow
	timestamp time.Time
}

func newFromExternalAggregator() *fromExternalAggregator {
	return &fromExternalAggregator{
		fromExternalStore: make(map[string]flowItem),
		ttl:               defaultTTL,
		cleanUpInterval:   defaultCleanUpInterval,
	}
}

func (a *fromExternalAggregator) Run(stopCh <-chan struct{}) {
	a.cleanUpLoop(stopCh)
}

// correlateOrStore is called for every incoming record before flowKeyRecordMap is consulted.
//
// For all flows that are NOT a FROM_EXTERNAL source-node flow, it returns the record unchanged so
// it enters flowKeyRecordMap directly (including destination-node INTER_NODE flows, which will be
// probed for a matching source-node flow by addOrUpdateRecordInMap immediately after insertion).
//
// For FROM_EXTERNAL source-node flows, it stores the flow in fromExternalStore and returns
// (nil, nil). addOrUpdateRecordInMap interprets a nil flowKey as a signal to attempt a cross-key
// merge against flowKeyRecordMap.
func (a *fromExternalAggregator) correlateOrStore(flowKey *FlowKey, record *flowpb.Flow) (*FlowKey, *flowpb.Flow) {
	if !isSourceNodeFromExternalFlow(record) {
		return flowKey, record
	}
	if record.Ip == nil {
		klog.ErrorS(nil, "Cannot handle FROM_EXTERNAL source-node flow: IP field is nil")
		return flowKey, record
	}
	key := generateFromExternalStoreKey(record)
	a.lock.Lock()
	defer a.lock.Unlock()

	a.fromExternalStore[key] = flowItem{flow: record, timestamp: time.Now()}
	klog.V(4).InfoS("Stored FROM_EXTERNAL source-node flow pending cross-key merge")
	return nil, nil
}

// popSourceNodeFlow removes and returns the stored FROM_EXTERNAL source-node flow for the given
// cross-key, or returns nil if none exists. Called by addOrUpdateRecordInMap.
func (a *fromExternalAggregator) popSourceNodeFlow(key string) *flowpb.Flow {
	a.lock.Lock()
	defer a.lock.Unlock()

	item, exists := a.fromExternalStore[key]
	if !exists {
		return nil
	}
	delete(a.fromExternalStore, key)
	return item.flow
}

// isSourceNodeFromExternalFlow returns true for the source-node half of an inter-node
// FROM_EXTERNAL connection: FlowType=FROM_EXTERNAL and DestinationPodName is empty (the pod is
// on the remote destination node, so the agent could not resolve it).
func isSourceNodeFromExternalFlow(record *flowpb.Flow) bool {
	return record.K8S != nil &&
		record.K8S.FlowType == flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL &&
		record.K8S.DestinationPodName == ""
}

// isDestinationNodeFromExternalFlow returns true for the destination-node half of an inter-node
// FROM_EXTERNAL connection: FlowType=INTER_NODE (exported from the agent's srcIsGw branch),
// DestinationPodName set (pod is local), SourcePodName empty (source is the remote gateway, not
// a Pod), ProxySnatIp unset (conntrack is symmetric at this hop).
func isDestinationNodeFromExternalFlow(record *flowpb.Flow) bool {
	return record.K8S != nil &&
		record.K8S.FlowType == flowpb.FlowType_FLOW_TYPE_INTER_NODE &&
		record.K8S.DestinationPodName != "" &&
		record.K8S.SourcePodName == "" &&
		len(record.ProxySnatIp) == 0
}

// mergeExternalFlows merges the source-node FROM_EXTERNAL record into the destination-node
// INTER_NODE record. The destination-node record is mutated in-place with the real external
// client IP, original source port, service metadata, and FlowType=FROM_EXTERNAL. ProxySnatIp/Port
// are cleared. The merged destination-node record is returned.
func mergeExternalFlows(sourceNodeFlow, destinationNodeFlow *flowpb.Flow) *flowpb.Flow {
	destinationNodeFlow.Ip.Source = sourceNodeFlow.Ip.Source
	destinationNodeFlow.Transport.SourcePort = sourceNodeFlow.Transport.SourcePort
	if destinationNodeFlow.K8S != nil && sourceNodeFlow.K8S != nil {
		destinationNodeFlow.K8S.DestinationServiceIp = sourceNodeFlow.K8S.DestinationServiceIp
		destinationNodeFlow.K8S.DestinationServicePortName = sourceNodeFlow.K8S.DestinationServicePortName
		destinationNodeFlow.K8S.DestinationServicePort = sourceNodeFlow.K8S.DestinationServicePort
		destinationNodeFlow.K8S.DestinationClusterIp = sourceNodeFlow.K8S.DestinationClusterIp
		destinationNodeFlow.K8S.FlowType = flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL
	}
	destinationNodeFlow.ProxySnatIp = nil
	destinationNodeFlow.ProxySnatPort = 0
	return destinationNodeFlow
}

// generateFromExternalStoreKey returns a string key that is equal for both halves of an
// inter-node FROM_EXTERNAL connection.
//   - Source-node (FROM_EXTERNAL): (ProxySnatIp=gatewayIP, ProxySnatPort, dstIP, dstPort)
//   - Destination-node (INTER_NODE): (Ip.Source=gatewayIP, SourcePort, dstIP, dstPort)
//
// Because ProxySnatIp==Ip.Source and ProxySnatPort==SourcePort, both sides produce the same key.
// It is also identical to the FlowKey stored in flowKeyRecordMap for the destination-node flow.
func generateFromExternalStoreKey(record *flowpb.Flow) string {
	var snatIP, snatPort string
	if len(record.ProxySnatIp) > 0 {
		snatIP = flowrecord.IpAddressAsString(record.ProxySnatIp)
		snatPort = strconv.FormatUint(uint64(record.ProxySnatPort), 10)
	} else {
		snatIP = flowrecord.IpAddressAsString(record.Ip.Source)
		snatPort = strconv.FormatUint(uint64(record.Transport.SourcePort), 10)
	}
	return fmt.Sprintf("%s-%s-%s-%s",
		snatPort,
		snatIP,
		flowrecord.IpAddressAsString(record.Ip.Destination),
		strconv.FormatUint(uint64(record.Transport.DestinationPort), 10),
	)
}

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

func (a *fromExternalAggregator) cleanup(ttl time.Duration) {
	a.lock.Lock()
	defer a.lock.Unlock()

	now := time.Now()
	for key, item := range a.fromExternalStore {
		if now.Sub(item.timestamp) > ttl {
			delete(a.fromExternalStore, key)
		}
	}
}

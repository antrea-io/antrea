// Copyright 2020 Antrea Authors
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

package stats

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent"
	"antrea.io/antrea/pkg/agent/multicast"
	"antrea.io/antrea/pkg/agent/openflow"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	// Period for performing stats collection and report.
	collectPeriod = 60 * time.Second
)

// statsCollection is a collection of stats.
type statsCollection struct {
	// networkPolicyStats is a mapping from K8s NetworkPolicy UIDs to their traffic stats.
	networkPolicyStats map[types.UID]*statsv1alpha1.TrafficStats
	// antreaClusterNetworkPolicyStats is a mapping from Antrea ClusterNetworkPolicy UIDs to their traffic stats.
	antreaClusterNetworkPolicyStats map[types.UID]map[string]*statsv1alpha1.TrafficStats
	// antreaNetworkPolicyStats is a mapping from Antrea NetworkPolicy UIDs to their traffic stats.
	antreaNetworkPolicyStats map[types.UID]map[string]*statsv1alpha1.TrafficStats
	// multicastGroups is a map that encodes the list of Pods that has joined the multicast group.
	multicastGroups map[string][]cpv1beta.PodReference
}

// Collector is responsible for collecting stats from the Openflow client, calculating the delta compared with the last
// reported stats, and reporting it to the antrea-controller summary API.
type Collector struct {
	nodeName string
	// antreaClientProvider provides interfaces to get antreaClient, which will be used to report the statistics to the
	// antrea-controller.
	antreaClientProvider agent.AntreaClientProvider
	// ofClient is the Openflow interface that can fetch the statistic of the Openflow entries.
	ofClient             openflow.Client
	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	multicastQuerier     querier.AgentMulticastInfoQuerier
	// lastStatsCollection is the last statistics that has been reported to antrea-controller successfully.
	// It is used to calculate the delta of the statistics that will be reported.
	lastStatsCollection *statsCollection
	multicastEnabled    bool
}

func NewCollector(antreaClientProvider agent.AntreaClientProvider, ofClient openflow.Client, npQuerier querier.AgentNetworkPolicyInfoQuerier, mcQuerier *multicast.Controller) *Collector {
	nodeName, _ := env.GetNodeName()
	manager := &Collector{
		nodeName:             nodeName,
		antreaClientProvider: antreaClientProvider,
		ofClient:             ofClient,
		networkPolicyQuerier: npQuerier,
		multicastQuerier:     mcQuerier,
		multicastEnabled:     mcQuerier != nil,
	}
	return manager
}

// Run runs a loop that collects statistics and reports them until the provided channel is closed.
func (m *Collector) Run(stopCh <-chan struct{}) {
	klog.Info("Start collecting metrics")
	ticker := time.NewTicker(collectPeriod)
	defer ticker.Stop()

	// Record the initial statistics as the base that will be used to calculate the delta.
	// If the counters increase during antrea-agent's downtime, the delta will not be reported to the antrea-controller,
	// it's however better than reporting the full statistics twice which could introduce greater deviations.
	m.lastStatsCollection = m.collect()

	for {
		select {
		case <-ticker.C:
			curStatsCollection := m.collect()
			// Do not update m.lastStatsMap if the report fails so that the next report attempt can add up the
			// statistics produced in this duration.
			if err := m.report(curStatsCollection); err != nil {
				klog.Errorf("Failed to report stats: %v", err)
			} else {
				m.lastStatsCollection = curStatsCollection
			}
		case <-stopCh:
			return
		}
	}
}

// collect collects the stats of Openflow rules, maps them to the stats of NetworkPolicies.
// It returns a map from NetworkPolicyReferences to their stats.
func (m *Collector) collect() *statsCollection {
	ruleStatsMap := m.ofClient.NetworkPolicyMetrics()
	npStatsMap := map[types.UID]*statsv1alpha1.TrafficStats{}
	acnpStatsMap := map[types.UID]map[string]*statsv1alpha1.TrafficStats{}
	annpStatsMap := map[types.UID]map[string]*statsv1alpha1.TrafficStats{}

	for ofID, ruleStats := range ruleStatsMap {
		rule := m.networkPolicyQuerier.GetRuleByFlowID(ofID)
		if rule == nil {
			// This should not happen because the rule flow ID to rule mapping is
			// preserved for at least 5 seconds even after the rule deletion.
			klog.Warningf("Cannot find NetworkPolicy Rule that has ofID %v", ofID)
			continue
		}

		klog.V(4).Infof("Converting ofID %v to policy %s", ofID, rule.PolicyRef.ToString())
		switch rule.PolicyRef.Type {
		case cpv1beta.K8sNetworkPolicy:
			addPolicyStatsUp(npStatsMap, ruleStats, rule)
		case cpv1beta.AntreaClusterNetworkPolicy:
			addRuleStatsUp(acnpStatsMap, ruleStats, rule)
		case cpv1beta.AntreaNetworkPolicy:
			addRuleStatsUp(annpStatsMap, ruleStats, rule)
		}
	}
	var multicastGroupMap map[string][]cpv1beta.PodReference
	if m.multicastEnabled {
		multicastGroupMap = m.multicastQuerier.GetGroupPods()
	}
	return &statsCollection{
		networkPolicyStats:              npStatsMap,
		antreaClusterNetworkPolicyStats: acnpStatsMap,
		antreaNetworkPolicyStats:        annpStatsMap,
		multicastGroups:                 multicastGroupMap,
	}
}

func addPolicyStatsUp(statsMap map[types.UID]*statsv1alpha1.TrafficStats, ruleStats *agenttypes.RuleMetric, rule *agenttypes.PolicyRule) {
	policyStats, exists := statsMap[rule.PolicyRef.UID]
	if !exists {
		policyStats = new(statsv1alpha1.TrafficStats)
		statsMap[rule.PolicyRef.UID] = policyStats
	}
	addUp(policyStats, ruleStats)
}

func addRuleStatsUp(ruleStatsMap map[types.UID]map[string]*statsv1alpha1.TrafficStats, ruleStats *agenttypes.RuleMetric, rule *agenttypes.PolicyRule) {
	lastRuleStats, exists := ruleStatsMap[rule.PolicyRef.UID]
	if !exists {
		lastRuleStats = make(map[string]*statsv1alpha1.TrafficStats)
		ruleStatsMap[rule.PolicyRef.UID] = lastRuleStats
	}
	trafficStats, trafficStatsExists := lastRuleStats[rule.Name]
	if !trafficStatsExists {
		trafficStats = new(statsv1alpha1.TrafficStats)
		lastRuleStats[rule.Name] = trafficStats
	}
	addUp(trafficStats, ruleStats)
}

func addUp(stats *statsv1alpha1.TrafficStats, inc *agenttypes.RuleMetric) {
	stats.Sessions += int64(inc.Sessions)
	stats.Packets += int64(inc.Packets)
	stats.Bytes += int64(inc.Bytes)
}

func isIdenticalMulticastGroupMap(a, b map[string][]cpv1beta.PodReference) bool {
	if len(a) != len(b) {
		return false
	}
	for aKey, aValue := range a {
		bValue, exist := b[aKey]
		if !exist {
			return false
		}
		if len(aValue) != len(bValue) {
			return false
		}
		aValueSet := sets.New[string]()
		for _, av := range aValue {
			aValueSet.Insert(k8s.NamespacedName(av.Namespace, av.Name))
		}
		bValueSet := sets.New[string]()
		for _, bv := range bValue {
			bValueSet.Insert(k8s.NamespacedName(bv.Namespace, bv.Name))
		}
		if !aValueSet.Equal(bValueSet) {
			return false
		}
	}
	return true
}

func (m *Collector) calculateNPStats(curStatsCollection *statsCollection) (npStats, acnpStats, annpStats []cpv1beta.NetworkPolicyStats) {
	npStats = calculateDiff(curStatsCollection.networkPolicyStats, m.lastStatsCollection.networkPolicyStats)
	acnpStats = calculateRuleDiff(curStatsCollection.antreaClusterNetworkPolicyStats, m.lastStatsCollection.antreaClusterNetworkPolicyStats)
	annpStats = calculateRuleDiff(curStatsCollection.antreaNetworkPolicyStats, m.lastStatsCollection.antreaNetworkPolicyStats)
	return npStats, acnpStats, annpStats
}

func (m *Collector) calculateNodeStatsSummary(curStatsCollection *statsCollection) *cpv1beta.NodeStatsSummary {
	var multicastGroups []cpv1beta.MulticastGroupInfo
	multicastGroupsUpdated := false
	npStats, acnpStats, annpStats := m.calculateNPStats(curStatsCollection)
	if m.multicastEnabled {
		multicastGroupsUpdated = !isIdenticalMulticastGroupMap(curStatsCollection.multicastGroups, m.lastStatsCollection.multicastGroups)
		acnpStats, annpStats = m.mergeStatsWithIGMPReports(acnpStats, annpStats)
		multicastGroups = m.convertMulticastGroups(curStatsCollection.multicastGroups)
	}
	// Semantically, reporting networkpolicy statistics with zero length is equal to reporting the same multicastGroupInfo.
	if len(npStats) == 0 && len(acnpStats) == 0 && len(annpStats) == 0 && !multicastGroupsUpdated {
		return nil
	}
	return &cpv1beta.NodeStatsSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name: m.nodeName,
		},
		NetworkPolicies:              npStats,
		AntreaClusterNetworkPolicies: acnpStats,
		AntreaNetworkPolicies:        annpStats,
		Multicast:                    multicastGroups,
	}
}

// mergeStatsWithIGMPReports merges acnpStats or annpStats with IGMP report statistics.
// Unlike other networkpolicystats collection process, IGMP report statistics is not collected from OVS flows. It was collected during IGMP packetIn process by a local cache.
// IGMP report statistics collected for a rule should be merged into already defined networkpolicy statistics before reporting.
func (m *Collector) mergeStatsWithIGMPReports(acnpStats, annpStats []cpv1beta.NetworkPolicyStats) ([]cpv1beta.NetworkPolicyStats, []cpv1beta.NetworkPolicyStats) {
	multicastANNPStatsMap, multicastACNPStatsMap := m.multicastQuerier.CollectIGMPReportNPStats()
	mergeReportStats := func(igmpReportStatsMap map[types.UID]map[string]*agenttypes.RuleMetric, originalStatsList []cpv1beta.NetworkPolicyStats) []cpv1beta.NetworkPolicyStats {
		uidIndexMap := make(map[types.UID]int)
		for i, stats := range originalStatsList {
			uidIndexMap[stats.NetworkPolicy.UID] = i
		}
		for uid, npStats := range igmpReportStatsMap {
			ruleStatsList := make([]statsv1alpha1.RuleTrafficStats, 0, len(npStats))
			for ruleName, ruleStats := range npStats {
				ruleStatsList = append(ruleStatsList, statsv1alpha1.RuleTrafficStats{Name: ruleName, TrafficStats: statsv1alpha1.TrafficStats{Packets: int64(ruleStats.Packets), Bytes: int64(ruleStats.Bytes)}})
			}
			index, exist := uidIndexMap[uid]
			if !exist {
				originalStatsList = append(originalStatsList, cpv1beta.NetworkPolicyStats{NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: uid}, RuleTrafficStats: ruleStatsList})
			} else {
				originalStatsList[index].RuleTrafficStats = append(originalStatsList[index].RuleTrafficStats, ruleStatsList...)
			}
		}
		return originalStatsList
	}

	return mergeReportStats(multicastACNPStatsMap, acnpStats), mergeReportStats(multicastANNPStatsMap, annpStats)
}

// convertMulticastGroups converts multicastGroupMap into a slice of multicastGroups.
// Calculating diff is not needed because we report full multicast group of the local node.
func (m *Collector) convertMulticastGroups(multicastGroupMap map[string][]cpv1beta.PodReference) []cpv1beta.MulticastGroupInfo {
	multicastGroups := make([]cpv1beta.MulticastGroupInfo, 0, len(multicastGroupMap))
	for group, pods := range multicastGroupMap {
		multicastGroups = append(multicastGroups, cpv1beta.MulticastGroupInfo{Group: group, Pods: pods})
	}
	return multicastGroups
}

// report calculates the delta of the stats and pushes it to the antrea-controller summary API.
// If multicast feature gate is enabled, it also sends the full multicast group and IGMP report stats to the antrea-controller.
func (m *Collector) report(curStatsCollection *statsCollection) error {
	summary := m.calculateNodeStatsSummary(curStatsCollection)
	if summary == nil {
		klog.V(4).Info("No stats to report, skip reporting")
		return nil
	}
	klog.V(4).InfoS("Reporting NodeStatsSummary", "NodeStatsSummary", summary)
	antreaClient, err := m.antreaClientProvider.GetAntreaClient()
	if err != nil {
		return err
	}
	_, err = antreaClient.ControlplaneV1beta2().NodeStatsSummaries().Create(context.TODO(), summary, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func calculateRuleDiff(curStatsMap, lastStatsMap map[types.UID]map[string]*statsv1alpha1.TrafficStats) []cpv1beta.NetworkPolicyStats {
	if len(curStatsMap) == 0 {
		return nil
	}
	statsList := make([]cpv1beta.NetworkPolicyStats, 0, len(curStatsMap))
	for uid, curStats := range curStatsMap {
		lastStats, exists := lastStatsMap[uid]
		stats := make([]statsv1alpha1.RuleTrafficStats, 0, len(curStats))
		if !exists {
			for name, curRuleStats := range curStats {
				if curRuleStats.Bytes != 0 {
					ruleTrafficStats := statsv1alpha1.RuleTrafficStats{
						Name:         name,
						TrafficStats: *curRuleStats,
					}
					stats = append(stats, ruleTrafficStats)
				}
			}
		} else {
			for name, curRuleStats := range curStats {
				lastRuleStats, lastRuleStatsExists := lastStats[name]
				// curRuleStats.Bytes < lastRuleStats.Bytes could happen
				// as rules with same name can be deleted and recreated later.
				if !lastRuleStatsExists || curRuleStats.Bytes < lastRuleStats.Bytes {
					if curRuleStats.Bytes != 0 {
						ruleTrafficStats := statsv1alpha1.RuleTrafficStats{
							Name:         name,
							TrafficStats: *curRuleStats,
						}
						stats = append(stats, ruleTrafficStats)
					}
				} else if curRuleStats.Bytes > lastRuleStats.Bytes {
					ruleTrafficStats := statsv1alpha1.RuleTrafficStats{
						Name: name,
						TrafficStats: statsv1alpha1.TrafficStats{
							Bytes:    curRuleStats.Bytes - lastRuleStats.Bytes,
							Sessions: curRuleStats.Sessions - lastRuleStats.Sessions,
							Packets:  curRuleStats.Packets - lastRuleStats.Packets,
						},
					}
					stats = append(stats, ruleTrafficStats)
				}
			}
		}
		if len(stats) != 0 {
			policyStats := cpv1beta.NetworkPolicyStats{
				NetworkPolicy:    cpv1beta.NetworkPolicyReference{UID: uid},
				RuleTrafficStats: stats,
			}
			statsList = append(statsList, policyStats)
		}
	}
	return statsList
}

func calculateDiff(curStatsMap, lastStatsMap map[types.UID]*statsv1alpha1.TrafficStats) []cpv1beta.NetworkPolicyStats {
	if len(curStatsMap) == 0 {
		return nil
	}
	statsList := make([]cpv1beta.NetworkPolicyStats, 0, len(curStatsMap))
	for uid, curStats := range curStatsMap {
		var stats *statsv1alpha1.TrafficStats
		lastStats, exists := lastStatsMap[uid]
		// curStats.Bytes < lastStats.Bytes could happen if one of the following conditions happens:
		// 1. OVS is restarted and Openflow entries are reinstalled.
		// 2. The NetworkPolicy is removed and recreated in-between two collection.
		// In these cases, curStats is the delta it should report.
		if !exists || curStats.Bytes < lastStats.Bytes {
			stats = curStats
		} else {
			stats = &statsv1alpha1.TrafficStats{
				Packets:  curStats.Packets - lastStats.Packets,
				Sessions: curStats.Sessions - lastStats.Sessions,
				Bytes:    curStats.Bytes - lastStats.Bytes,
			}
		}
		// If the statistics of the NetworkPolicy remain unchanged, no need to report it.
		if stats.Bytes == 0 {
			continue
		}
		policyStats := cpv1beta.NetworkPolicyStats{
			NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: uid},
			TrafficStats:  *stats,
		}
		statsList = append(statsList, policyStats)
	}
	return statsList
}

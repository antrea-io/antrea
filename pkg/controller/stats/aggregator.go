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
	"fmt"
	"sync"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	uidIndex           = "uid"
	GroupNameIndexName = "groupName"
)

// Aggregator collects the stats from the antrea-agents, aggregates them, caches the result, and provides interfaces
// for Stats API handlers to query them. It implements the following interfaces:
// - pkg/apiserver/registry/controlplane/nodestatssummary.statsCollector
// - pkg/apiserver/registry/stats/networkpolicystats.statsProvider
// - pkg/apiserver/registry/stats/antreaclusternetworkpolicystats.statsProvider
// - pkg/apiserver/registry/stats/antreanetworkpolicystats.statsProvider
// - pkg/apiserver/registry/stats/multicastgroup.statsProvider
type Aggregator struct {
	// networkPolicyStats caches the statistics of K8s NetworkPolicies collected from the antrea-agents.
	networkPolicyStats cache.Indexer
	// antreaClusterNetworkPolicyStats caches the statistics of Antrea ClusterNetworkPolicies collected from the antrea-agents.
	antreaClusterNetworkPolicyStats cache.Indexer
	// antreaNetworkPolicyStats caches the statistics of Antrea NetworkPolicies collected from the antrea-agents.
	antreaNetworkPolicyStats cache.Indexer
	// groupNodePodsMap caches the information of Pods in a Node that have joined multicast groups collected from the antrea-agents.
	// The map can be interpreted as
	// map[IP of multicast group]map[name of node]list of PodReference.
	groupNodePodsMap      map[string]map[string][]statsv1alpha1.PodReference
	groupNodePodsMapMutex sync.RWMutex
	// dataCh is the channel that buffers the NodeSummaries sent by antrea-agents.
	dataCh chan *controlplane.NodeStatsSummary
	// npListerSynced is a function which returns true if the K8s NetworkPolicy shared informer has been synced at least once.
	npListerSynced cache.InformerSynced
	// acnpListerSynced is a function which returns true if the Antrea ClusterNetworkPolicy shared informer has been synced at least once.
	acnpListerSynced cache.InformerSynced
	// annpListerSynced is a function which returns true if the Antrea NetworkPolicy shared informer has been synced at least once.
	annpListerSynced cache.InformerSynced
}

// uidIndexFunc is an index function that indexes based on an object's UID.
func uidIndexFunc(obj interface{}) ([]string, error) {
	meta, err := meta.Accessor(obj)
	if err != nil {
		return []string{""}, fmt.Errorf("object has no meta: %v", err)
	}
	return []string{string(meta.GetUID())}, nil
}

func NewAggregator(networkPolicyInformer networkinginformers.NetworkPolicyInformer, acnpInformer crdinformers.ClusterNetworkPolicyInformer, annpInformer crdinformers.NetworkPolicyInformer) *Aggregator {
	aggregator := &Aggregator{
		networkPolicyStats: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc, uidIndex: uidIndexFunc}),
		dataCh:             make(chan *controlplane.NodeStatsSummary, 1000),
		npListerSynced:     networkPolicyInformer.Informer().HasSynced,
	}
	// Add handlers for NetworkPolicy events.
	// They are the source of truth of the NetworkPolicyStats, i.e., a NetworkPolicyStats is present only if the
	// corresponding NetworkPolicy is present.
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    aggregator.addNetworkPolicy,
			DeleteFunc: aggregator.deleteNetworkPolicy,
		},
		// Set resyncPeriod to 0 to disable resyncing.
		0,
	)
	// Register Informer and add handlers for AntreaPolicy events only if the feature is enabled.
	// They are the source of truth of the ClusterNetworkPolicyStats, i.e., a ClusterNetworkPolicyStats is present
	// only if the corresponding ClusterNetworkPolicy is present.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		aggregator.antreaClusterNetworkPolicyStats = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{uidIndex: uidIndexFunc})
		aggregator.acnpListerSynced = acnpInformer.Informer().HasSynced
		acnpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    aggregator.addACNP,
				DeleteFunc: aggregator.deleteACNP,
			},
			// Set resyncPeriod to 0 to disable resyncing.
			0,
		)

		aggregator.antreaNetworkPolicyStats = cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc, uidIndex: uidIndexFunc})
		aggregator.annpListerSynced = annpInformer.Informer().HasSynced
		annpInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    aggregator.addANNP,
				DeleteFunc: aggregator.deleteANNP,
			},
			// Set resyncPeriod to 0 to disable resyncing.
			0,
		)
	}
	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		aggregator.groupNodePodsMap = make(map[string]map[string][]statsv1alpha1.PodReference)
	}
	return aggregator
}

// addNetworkPolicy handles NetworkPolicy ADD events and creates corresponding NetworkPolicyStats objects.
func (a *Aggregator) addNetworkPolicy(obj interface{}) {
	np := obj.(*networkingv1.NetworkPolicy)
	stats := &statsv1alpha1.NetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
			UID:       np.UID,
			// To indicate the duration that the stats cover, the CreationTimestamp is set to the time that the stats
			// start, instead of the CreationTimestamp of the NetworkPolicy.
			CreationTimestamp: metav1.Time{Time: time.Now()},
		},
	}
	a.networkPolicyStats.Add(stats)
}

// deleteNetworkPolicy handles NetworkPolicy DELETE events and deletes corresponding NetworkPolicyStats objects.
func (a *Aggregator) deleteNetworkPolicy(obj interface{}) {
	np, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting NetworkPolicy, invalid type: %v", obj)
			return
		}
		np, ok = tombstone.Obj.(*networkingv1.NetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting NetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	stats := &statsv1alpha1.NetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: np.Namespace,
			UID:       np.UID,
		},
	}
	a.networkPolicyStats.Delete(stats)
}

// addACNP handles ClusterNetworkPolicy ADD events and creates corresponding ClusterNetworkPolicyStats objects.
func (a *Aggregator) addACNP(obj interface{}) {
	acnp := obj.(*crdv1beta1.ClusterNetworkPolicy)
	stats := &statsv1alpha1.AntreaClusterNetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnp.Name,
			UID:  acnp.UID,
			// To indicate the duration that the stats covers, the CreationTimestamp is set to the time that the stats
			// start, instead of the CreationTimestamp of the ClusterNetworkPolicy.
			CreationTimestamp: metav1.Time{Time: time.Now()},
		},
	}
	a.antreaClusterNetworkPolicyStats.Add(stats)
}

// deleteACNP handles ClusterNetworkPolicy DELETE events and deletes corresponding ClusterNetworkPolicyStats objects.
func (a *Aggregator) deleteACNP(obj interface{}) {
	acnp, ok := obj.(*crdv1beta1.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Antrea ClusterNetworkPolicy, invalid type: %v", obj)
			return
		}
		acnp, ok = tombstone.Obj.(*crdv1beta1.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Antrea ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	stats := &statsv1alpha1.AntreaClusterNetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnp.Name,
			UID:  acnp.UID,
		},
	}
	a.antreaClusterNetworkPolicyStats.Delete(stats)
}

// addANNP handles Antrea NetworkPolicy ADD events and creates corresponding AntreaNetworkPolicyStats objects.
func (a *Aggregator) addANNP(obj interface{}) {
	annp := obj.(*crdv1beta1.NetworkPolicy)
	stats := &statsv1alpha1.AntreaNetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: annp.Namespace,
			Name:      annp.Name,
			UID:       annp.UID,
			// To indicate the duration that the stats covers, the CreationTimestamp is set to the time that the stats
			// start, instead of the CreationTimestamp of the Antrea NetworkPolicy.
			CreationTimestamp: metav1.Time{Time: time.Now()},
		},
	}
	a.antreaNetworkPolicyStats.Add(stats)
}

// deleteANNP handles Antrea NetworkPolicy DELETE events and deletes corresponding AntreaNetworkPolicyStats objects.
func (a *Aggregator) deleteANNP(obj interface{}) {
	annp, ok := obj.(*crdv1beta1.NetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Antrea NetworkPolicy, invalid type: %v", obj)
			return
		}
		annp, ok = tombstone.Obj.(*crdv1beta1.NetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Antrea NetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	stats := &statsv1alpha1.AntreaNetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: annp.Namespace,
			Name:      annp.Name,
			UID:       annp.UID,
		},
	}
	a.antreaNetworkPolicyStats.Delete(stats)
}

func (a *Aggregator) ListAntreaClusterNetworkPolicyStats() []statsv1alpha1.AntreaClusterNetworkPolicyStats {
	objs := a.antreaClusterNetworkPolicyStats.List()
	stats := make([]statsv1alpha1.AntreaClusterNetworkPolicyStats, len(objs))
	for i, obj := range objs {
		stats[i] = *(obj.(*statsv1alpha1.AntreaClusterNetworkPolicyStats))
	}
	return stats
}

func (a *Aggregator) ListMulticastGroups() []statsv1alpha1.MulticastGroup {
	stats := make([]statsv1alpha1.MulticastGroup, 0, len(a.groupNodePodsMap))
	a.groupNodePodsMapMutex.RLock()
	defer a.groupNodePodsMapMutex.RUnlock()
	for group, nodePods := range a.groupNodePodsMap {
		allPods := make([]statsv1alpha1.PodReference, 0)
		for _, pods := range nodePods {
			allPods = append(allPods, pods...)
		}
		stats = append(stats, statsv1alpha1.MulticastGroup{ObjectMeta: metav1.ObjectMeta{Name: group}, Group: group, Pods: allPods})
	}
	return stats
}

func (a *Aggregator) GetMulticastGroup(group string) (*statsv1alpha1.MulticastGroup, bool) {
	a.groupNodePodsMapMutex.RLock()
	defer a.groupNodePodsMapMutex.RUnlock()
	nodePods, exist := a.groupNodePodsMap[group]
	if !exist {
		return nil, false
	}
	allPods := make([]statsv1alpha1.PodReference, 0)
	for _, pods := range nodePods {
		allPods = append(allPods, pods...)
	}

	return &statsv1alpha1.MulticastGroup{ObjectMeta: metav1.ObjectMeta{Name: group}, Group: group, Pods: allPods}, true
}

func (a *Aggregator) GetAntreaClusterNetworkPolicyStats(name string) (*statsv1alpha1.AntreaClusterNetworkPolicyStats, bool) {
	obj, exists, _ := a.antreaClusterNetworkPolicyStats.GetByKey(name)
	if !exists {
		return nil, false
	}
	return obj.(*statsv1alpha1.AntreaClusterNetworkPolicyStats), true
}

func (a *Aggregator) ListAntreaNetworkPolicyStats(namespace string) []statsv1alpha1.AntreaNetworkPolicyStats {
	var objs []interface{}
	if namespace == "" {
		objs = a.antreaNetworkPolicyStats.List()
	} else {
		objs, _ = a.antreaNetworkPolicyStats.ByIndex(cache.NamespaceIndex, namespace)
	}

	stats := make([]statsv1alpha1.AntreaNetworkPolicyStats, len(objs))
	for i, obj := range objs {
		stats[i] = *(obj.(*statsv1alpha1.AntreaNetworkPolicyStats))
	}
	return stats
}

func (a *Aggregator) GetAntreaNetworkPolicyStats(namespace, name string) (*statsv1alpha1.AntreaNetworkPolicyStats, bool) {
	obj, exists, _ := a.antreaNetworkPolicyStats.GetByKey(k8s.NamespacedName(namespace, name))
	if !exists {
		return nil, false
	}
	return obj.(*statsv1alpha1.AntreaNetworkPolicyStats), true
}

func (a *Aggregator) ListNetworkPolicyStats(namespace string) []statsv1alpha1.NetworkPolicyStats {
	var objs []interface{}
	if namespace == "" {
		objs = a.networkPolicyStats.List()
	} else {
		objs, _ = a.networkPolicyStats.ByIndex(cache.NamespaceIndex, namespace)
	}

	stats := make([]statsv1alpha1.NetworkPolicyStats, len(objs))
	for i, obj := range objs {
		stats[i] = *(obj.(*statsv1alpha1.NetworkPolicyStats))
	}
	return stats
}

func (a *Aggregator) GetNetworkPolicyStats(namespace, name string) (*statsv1alpha1.NetworkPolicyStats, bool) {
	obj, exists, _ := a.networkPolicyStats.GetByKey(k8s.NamespacedName(namespace, name))
	if !exists {
		return nil, false
	}
	return obj.(*statsv1alpha1.NetworkPolicyStats), true
}

// Collect collects the node summary asynchronously to avoid the competition for the statsLock and to save clients
// from pending on it.
func (a *Aggregator) Collect(summary *controlplane.NodeStatsSummary) {
	a.dataCh <- summary
}

// Run runs a loop that keeps taking stats summary from the data channel and actually collecting them until the
// provided stop channel is closed.
func (a *Aggregator) Run(stopCh <-chan struct{}) {
	klog.Info("Starting stats aggregator")
	defer klog.Info("Shutting down stats aggregator")

	cacheSyncs := []cache.InformerSynced{a.npListerSynced}
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		cacheSyncs = append(cacheSyncs, a.acnpListerSynced, a.annpListerSynced)
	}
	if !cache.WaitForNamedCacheSync("stats aggregator", stopCh, cacheSyncs...) {
		return
	}

	for {
		select {
		case summary := <-a.dataCh:
			a.doCollect(summary)
		case <-stopCh:
			return
		}
	}
}

func (a *Aggregator) doCollect(summary *controlplane.NodeStatsSummary) {
	for _, stats := range summary.NetworkPolicies {
		// The policy might have been removed, skip processing it if missing.
		objs, _ := a.networkPolicyStats.ByIndex(uidIndex, string(stats.NetworkPolicy.UID))
		if len(objs) > 0 {
			// The object returned by cache is supposed to be read only, create a new object and update it.
			curStats := objs[0].(*statsv1alpha1.NetworkPolicyStats).DeepCopy()
			addUp(&curStats.TrafficStats, &stats.TrafficStats)
			a.networkPolicyStats.Update(curStats)
		}
	}
	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		reportedGroups := sets.New[string]()
		a.groupNodePodsMapMutex.Lock()
		for _, mcastGroupInfo := range summary.Multicast {
			group := mcastGroupInfo.Group
			reportedGroups.Insert(group)
			_, exist := a.groupNodePodsMap[group]
			if !exist {
				a.groupNodePodsMap[group] = make(map[string][]statsv1alpha1.PodReference)
			}
			statsv1alpha1Pods := make([]statsv1alpha1.PodReference, 0, len(mcastGroupInfo.Pods))
			for _, pod := range mcastGroupInfo.Pods {
				statsv1alpha1Pods = append(statsv1alpha1Pods, statsv1alpha1.PodReference{Name: pod.Name, Namespace: pod.Namespace})
			}
			a.groupNodePodsMap[group][summary.ObjectMeta.Name] = statsv1alpha1Pods
		}
		for group := range a.groupNodePodsMap {
			// The antrea-agent reports full mcastGroupInfo to the controller, if the group is unreported,
			// then this group has no Pod joined in this Node.
			if !reportedGroups.Has(group) {
				delete(a.groupNodePodsMap[group], summary.ObjectMeta.Name)
				if len(a.groupNodePodsMap[group]) == 0 {
					delete(a.groupNodePodsMap, group)
				}
			}
		}
		a.groupNodePodsMapMutex.Unlock()
	}
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		for _, stats := range summary.AntreaClusterNetworkPolicies {
			// The policy have might been removed, skip processing it if missing.
			objs, _ := a.antreaClusterNetworkPolicyStats.ByIndex(uidIndex, string(stats.NetworkPolicy.UID))
			if len(objs) > 0 {
				// The object returned by cache is supposed to be read only, create a new object and update it.
				curStats := objs[0].(*statsv1alpha1.AntreaClusterNetworkPolicyStats).DeepCopy()
				// antrea agents may not be updated and still use TrafficStats to collect overall networkpolicy
				if stats.TrafficStats.Bytes > 0 {
					addUp(&curStats.TrafficStats, &stats.TrafficStats)
				} else {
					addRulesUp(&curStats.RuleTrafficStats, &curStats.TrafficStats, stats.RuleTrafficStats)
				}
				a.antreaClusterNetworkPolicyStats.Update(curStats)
			}
		}

		for _, stats := range summary.AntreaNetworkPolicies {
			// The policy have might been removed, skip processing it if missing.
			objs, _ := a.antreaNetworkPolicyStats.ByIndex(uidIndex, string(stats.NetworkPolicy.UID))

			if len(objs) > 0 {
				// The object returned by cache is supposed to be read only, create a new object and update it.
				curStats := objs[0].(*statsv1alpha1.AntreaNetworkPolicyStats).DeepCopy()
				// antrea agents may not be updated and still use TrafficStats to collect overall networkpolicy
				if stats.TrafficStats.Bytes > 0 {
					addUp(&curStats.TrafficStats, &stats.TrafficStats)
				} else {
					addRulesUp(&curStats.RuleTrafficStats, &curStats.TrafficStats, stats.RuleTrafficStats)
				}
				a.antreaNetworkPolicyStats.Update(curStats)
			}
		}
	}
}

func addUp(stats *statsv1alpha1.TrafficStats, inc *statsv1alpha1.TrafficStats) {
	stats.Sessions += inc.Sessions
	stats.Packets += inc.Packets
	stats.Bytes += inc.Bytes
}

func addRulesUp(ruleStats *[]statsv1alpha1.RuleTrafficStats, ruleSumStats *statsv1alpha1.TrafficStats, inc []statsv1alpha1.RuleTrafficStats) {
	incMap := make(map[string]*statsv1alpha1.TrafficStats)
	for i, v := range inc {
		incMap[v.Name] = &inc[i].TrafficStats
	}
	// accumulate incMap traffics stats to the current traffic stats
	for _, v := range incMap {
		addUp(ruleSumStats, v)
	}
	// accumulate the rule traffic stats as the rule has already 'existed' in the ruleStats
	for i, v := range *ruleStats {
		stats, exist := incMap[v.Name]
		if exist {
			(*ruleStats)[i].TrafficStats = statsv1alpha1.TrafficStats{
				Packets:  v.TrafficStats.Packets + stats.Packets,
				Bytes:    v.TrafficStats.Bytes + stats.Bytes,
				Sessions: v.TrafficStats.Sessions + stats.Sessions,
			}
		}
		delete(incMap, v.Name)
	}
	// convert remaining incs to RuleTrafficStats and add it to current traffic stats
	for k, v := range incMap {
		rs := statsv1alpha1.RuleTrafficStats{
			Name:         k,
			TrafficStats: *v,
		}
		*ruleStats = append(*ruleStats, rs)
	}
}

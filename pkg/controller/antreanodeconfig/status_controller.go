// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
	infoinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1alpha1"
	infolisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const (
	agentReportTimeout   = 3 * time.Minute
	statusResyncInterval = 30 * time.Second
	maxNodeMessageLength = 512
)

// StatusController aggregates Agent reports into AntreaNodeConfig status.
type StatusController struct {
	client           clientset.Interface
	ancLister        crdlisters.AntreaNodeConfigLister
	infoLister       infolisters.AntreaAgentInfoLister
	nodeLister       corelisters.NodeLister
	synced           []cache.InformerSynced
	queue            workqueue.TypedRateLimitingInterface[string]
	selectionVersion atomic.Uint64
	// The selection cache is accessed only by the status worker. Heartbeat updates
	// do not invalidate it, as they cannot change configuration precedence.
	cachedVersion uint64
	selected      map[types.UID]*crdv1alpha1.AntreaNodeConfig
}

// NewStatusController registers configuration, Node, and Agent report event handlers.
func NewStatusController(client clientset.Interface, ancInformer crdinformers.AntreaNodeConfigInformer,
	infoInformer infoinformers.AntreaAgentInfoInformer, nodeInformer coreinformers.NodeInformer) *StatusController {
	c := &StatusController{
		client: client, ancLister: ancInformer.Lister(), infoLister: infoInformer.Lister(), nodeLister: nodeInformer.Lister(),
		synced: []cache.InformerSynced{ancInformer.Informer().HasSynced, infoInformer.Informer().HasSynced, nodeInformer.Informer().HasSynced},
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Second, 30*time.Second),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "antreanodeconfigstatus"}),
	}
	ancInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { c.selectionVersion.Add(1); c.enqueueAll() },
		DeleteFunc: func(interface{}) { c.selectionVersion.Add(1); c.enqueueAll() },
		UpdateFunc: func(old, current interface{}) {
			before, after := old.(*crdv1alpha1.AntreaNodeConfig), current.(*crdv1alpha1.AntreaNodeConfig)
			if before.Generation != after.Generation || !reflect.DeepEqual(before.Spec, after.Spec) || !reflect.DeepEqual(before.DeletionTimestamp, after.DeletionTimestamp) {
				c.selectionVersion.Add(1)
				c.enqueueAll()
			}
		},
	})
	infoInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { c.enqueueReport(obj.(*crdv1beta1.AntreaAgentInfo)) },
		DeleteFunc: func(obj interface{}) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if info, ok := obj.(*crdv1beta1.AntreaAgentInfo); ok {
				c.enqueueReport(info)
			}
		},
		UpdateFunc: func(old, current interface{}) {
			before, after := old.(*crdv1beta1.AntreaAgentInfo), current.(*crdv1beta1.AntreaAgentInfo)
			if reportNeedsSync(before.NodeConfigStatus, after.NodeConfigStatus, time.Now()) {
				c.enqueueReport(before)
				c.enqueueReport(after)
			}
		},
	})
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { c.selectionVersion.Add(1); c.enqueueAll() },
		DeleteFunc: func(interface{}) { c.selectionVersion.Add(1); c.enqueueAll() },
		UpdateFunc: func(old, current interface{}) {
			before, after := old.(*corev1.Node), current.(*corev1.Node)
			if before.UID != after.UID || !reflect.DeepEqual(before.Labels, after.Labels) {
				c.selectionVersion.Add(1)
				c.enqueueAll()
			} else if nodeReadiness(before) != nodeReadiness(after) {
				c.enqueueNode(after)
			}
		},
	})
	return c
}

func reportNeedsSync(before, after *crdv1beta1.AntreaNodeConfigAgentStatus, now time.Time) bool {
	if before == nil || after == nil {
		return before != after
	}
	// Heartbeats only extend the expiry deadline. Periodic reconciliation reads
	// that deadline; stable reports must not cause a cluster-wide scan per Agent.
	if now.Sub(before.LastHeartbeatTime.Time) > agentReportTimeout {
		return true
	}
	oldReport, newReport := before.DeepCopy(), after.DeepCopy()
	oldReport.LastHeartbeatTime, newReport.LastHeartbeatTime = metav1.Time{}, metav1.Time{}
	return !reflect.DeepEqual(oldReport, newReport)
}

func nodeReadiness(node *corev1.Node) corev1.ConditionStatus {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status
		}
	}
	return corev1.ConditionUnknown
}

func (c *StatusController) enqueueAll() {
	configs, err := c.ancLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Failed to list AntreaNodeConfigs for status updates")
		return
	}
	for _, cfg := range configs {
		c.queue.Add(cfg.Name)
	}
}

func (c *StatusController) enqueueNode(node *corev1.Node) {
	configs, err := c.ancLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Failed to list AntreaNodeConfigs for Node status update")
		return
	}
	for _, cfg := range k8s.MatchingAntreaNodeConfigs(node, configs) {
		c.queue.Add(cfg.Name)
	}
}

func (c *StatusController) enqueueReport(info *crdv1beta1.AntreaAgentInfo) {
	if report := info.NodeConfigStatus; report != nil && report.ConfigName != "" {
		c.queue.Add(report.ConfigName)
	}
	// AgentInfo is named after its Node. A missing or obsolete report still
	// invalidates the configuration currently selecting that Node.
	node, err := c.nodeLister.Get(info.Name)
	if err != nil {
		if !errors.IsNotFound(err) {
			klog.ErrorS(err, "Failed to get Node for Agent configuration report", "node", info.Name)
		}
		return
	}
	c.enqueueNode(node)
}

// Run updates configuration status on relevant events and expires stale reports.
func (c *StatusController) Run(stopCh <-chan struct{}) {
	ctx := wait.ContextForChannel(stopCh)
	defer c.queue.ShutDown()
	if !cache.WaitForNamedCacheSync("AntreaNodeConfigStatus", stopCh, c.synced...) {
		return
	}
	c.enqueueAll()
	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		for c.processNextItem(ctx) {
		}
	}, time.Second)
	<-stopCh
}

func (c *StatusController) processNextItem(ctx context.Context) bool {
	key, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	defer c.queue.Done(key)
	if ctx.Err() != nil {
		c.queue.Forget(key)
		return false
	}
	err := c.syncStatus(ctx, key)
	if ctx.Err() != nil {
		c.queue.Forget(key)
		return false
	}
	if err != nil {
		if errors.IsNotFound(err) {
			c.queue.Forget(key)
			return true
		}
		klog.ErrorS(err, "Failed to aggregate AntreaNodeConfig status", "antreaNodeConfig", key)
		c.queue.AddRateLimited(key)
	} else {
		c.queue.Forget(key)
		c.queue.AddAfter(key, statusResyncInterval)
	}
	return true
}

func (c *StatusController) syncStatus(ctx context.Context, name string) error {
	version := c.selectionVersion.Load()
	cfg, err := c.ancLister.Get(name)
	if err != nil {
		return err
	}
	configs, err := c.ancLister.List(labels.Everything())
	if err != nil {
		return err
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	infos, err := c.infoLister.List(labels.Everything())
	if err != nil {
		return err
	}
	reports := make(map[string]*crdv1beta1.AntreaNodeConfigAgentStatus, len(infos))
	for _, info := range infos {
		reports[info.Name] = info.NodeConfigStatus
	}
	if c.selected == nil || c.cachedVersion != version {
		c.selected, c.cachedVersion = k8s.SelectAntreaNodeConfigs(nodes, configs), version
	}
	status := calculateStatus(cfg, c.selected, nodes, reports, time.Now())
	if reflect.DeepEqual(cfg.Status, status) {
		return nil
	}
	updated := cfg.DeepCopy()
	updated.Status = status
	_, err = c.client.CrdV1alpha1().AntreaNodeConfigs().UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}

func freshReport(node *corev1.Node, report *crdv1beta1.AntreaNodeConfigAgentStatus, now time.Time) bool {
	if report == nil || report.NodeUID != node.UID || report.LastHeartbeatTime.IsZero() ||
		now.Sub(report.LastHeartbeatTime.Time) > agentReportTimeout || report.LastHeartbeatTime.After(now.Add(time.Minute)) {
		return false
	}
	return nodeReadiness(node) == corev1.ConditionTrue
}

func calculateStatus(cfg *crdv1alpha1.AntreaNodeConfig, selectedConfigs map[types.UID]*crdv1alpha1.AntreaNodeConfig,
	nodes []*corev1.Node, reports map[string]*crdv1beta1.AntreaNodeConfigAgentStatus, now time.Time) crdv1alpha1.AntreaNodeConfigStatus {
	status := crdv1alpha1.AntreaNodeConfigStatus{ObservedGeneration: cfg.Generation}
	aggregate := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, ObservedGeneration: cfg.Generation,
		Reason: "Reconciled", Message: "Configuration has been realized on all selected Nodes", LastTransitionTime: metav1.NewTime(now)}
	selector, selectorErr := metav1.LabelSelectorAsSelector(&cfg.Spec.NodeSelector)
	shadowed := 0
	var representative string
	for _, node := range nodes {
		effective := selectedConfigs[node.UID]
		if effective == nil || effective.UID != cfg.UID {
			if cfg.DeletionTimestamp == nil && selectorErr == nil && selector.Matches(labels.Set(node.Labels)) {
				shadowed++
			}
			continue
		}
		status.DesiredNodes++
		condition := selectedNodeCondition(cfg, node, reports[node.Name], now)
		if condition.Status == metav1.ConditionTrue {
			status.RealizedNodes++
			continue
		}
		// A failure takes precedence over an unavailable report. Within either
		// class, the first Node by name supplies a stable, useful reason.
		if aggregate.Status == metav1.ConditionTrue ||
			(condition.Status == metav1.ConditionFalse && aggregate.Status != metav1.ConditionFalse) ||
			(condition.Status == aggregate.Status && node.Name < representative) {
			aggregate.Status, aggregate.Reason = condition.Status, condition.Reason
			aggregate.Message = fmt.Sprintf("Node %s: %s", node.Name, condition.Message)
			representative = node.Name
		}
	}
	if selectorErr != nil {
		aggregate.Status, aggregate.Reason, aggregate.Message = metav1.ConditionFalse, "InvalidNodeSelector", selectorErr.Error()
	} else if status.DesiredNodes == 0 {
		aggregate.Status, aggregate.Reason, aggregate.Message = metav1.ConditionFalse, "NoMatchingNodes", "No Nodes currently select this configuration"
		if shadowed > 0 {
			aggregate.Reason, aggregate.Message = "ConfigurationNotSelected", "All matching Nodes select an older AntreaNodeConfig"
		}
	}
	if len(aggregate.Message) > maxNodeMessageLength {
		aggregate.Message = aggregate.Message[:maxNodeMessageLength-3] + "..."
	}
	for _, conditionType := range []string{"Ready", "ConflictFree"} {
		if previous := meta.FindStatusCondition(cfg.Status.Conditions, conditionType); previous != nil {
			status.Conditions = append(status.Conditions, *previous)
		}
	}
	meta.SetStatusCondition(&status.Conditions, aggregate)
	conflict := metav1.Condition{Type: "ConflictFree", Status: metav1.ConditionTrue, ObservedGeneration: cfg.Generation,
		Reason: "NoConflicts", Message: "No matching Nodes select another AntreaNodeConfig", LastTransitionTime: metav1.NewTime(now)}
	if selectorErr != nil {
		conflict.Status, conflict.Reason, conflict.Message = metav1.ConditionUnknown, "InvalidNodeSelector", "Cannot evaluate conflicts with an invalid Node selector"
	} else if shadowed > 0 {
		conflict.Status, conflict.Reason, conflict.Message = metav1.ConditionFalse, "OverriddenNodes", fmt.Sprintf("%d matching Nodes select an older AntreaNodeConfig; Ready covers effective selected Nodes", shadowed)
	}
	meta.SetStatusCondition(&status.Conditions, conflict)
	return status
}

func selectedNodeCondition(cfg *crdv1alpha1.AntreaNodeConfig, node *corev1.Node,
	report *crdv1beta1.AntreaNodeConfigAgentStatus, now time.Time) metav1.Condition {
	condition := metav1.Condition{Status: metav1.ConditionUnknown,
		Reason: "AgentUnavailable", Message: "Waiting for a fresh Agent configuration report"}
	if !freshReport(node, report, now) {
		return condition
	}
	condition.Reason, condition.Message = "ConfigurationUnavailable", "Waiting for secondary network configuration status"
	if report.SecondaryNetwork == nil {
		return condition
	}
	ready := meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready")
	if ready == nil {
		return condition
	}
	identityFree := report.ConfigUID == "" && report.ConfigName == "" && ready.ObservedGeneration == 0
	switch {
	case identityFree && ready.Status == metav1.ConditionFalse &&
		(ready.Reason == "FeatureDisabled" || ready.Reason == "UnsupportedNode"):
		condition.Status, condition.Reason, condition.Message = ready.Status, ready.Reason, ready.Message
	case (identityFree || report.ConfigUID == cfg.UID) && ready.ObservedGeneration == 0 &&
		ready.Status == metav1.ConditionUnknown && ready.Reason == "ConfigurationUnavailable":
		condition.Reason, condition.Message = ready.Reason, ready.Message
	case report.ConfigUID != cfg.UID || ready.ObservedGeneration <= 0 || ready.ObservedGeneration != cfg.Generation:
		condition.Status, condition.Reason, condition.Message = metav1.ConditionFalse, "GenerationNotObserved", "Agent has not reconciled the selected configuration generation"
	default:
		condition.Status, condition.Reason, condition.Message = ready.Status, ready.Reason, ready.Message
	}
	return condition
}

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

package monitor

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	externalnodeinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	externalnodelisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	controllerquerier "antrea.io/antrea/pkg/controller/querier"
)

const (
	controllerName = "AntreaControllerMonitor"
	// How long to wait before retrying the processing of a Node/ExternalNode change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a Node/ExternalNode change.
	defaultWorkers        = 4
	agentInfoResourceKind = "AntreaAgentInfo"
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
)

type controllerMonitor struct {
	client       clientset.Interface
	nodeInformer coreinformers.NodeInformer
	nodeLister   corelisters.NodeLister
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced

	externalNodeInformer     externalnodeinformers.ExternalNodeInformer
	externalNodeLister       externalnodelisters.ExternalNodeLister
	externalNodeListerSynced cache.InformerSynced

	externalNodeEnabled bool

	nodeQueue         workqueue.RateLimitingInterface
	externalNodeQueue workqueue.RateLimitingInterface

	querier controllerquerier.ControllerQuerier
	// controllerCRD is the desired state of controller monitoring CRD which controllerMonitor expects.
	controllerCRD *v1beta1.AntreaControllerInfo
}

// NewControllerMonitor creates a new controller monitor.
func NewControllerMonitor(
	client clientset.Interface,
	nodeInformer coreinformers.NodeInformer,
	externalNodeInformer externalnodeinformers.ExternalNodeInformer,
	querier controllerquerier.ControllerQuerier,
	externalNodeEnabled bool,
) *controllerMonitor {
	m := &controllerMonitor{
		client:              client,
		nodeInformer:        nodeInformer,
		nodeLister:          nodeInformer.Lister(),
		nodeListerSynced:    nodeInformer.Informer().HasSynced,
		nodeQueue:           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "node"),
		querier:             querier,
		controllerCRD:       nil,
		externalNodeEnabled: externalNodeEnabled,
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.enqueueNode,
		UpdateFunc: nil,
		DeleteFunc: m.enqueueNode,
	})
	// Register Informer and add handlers for ExternalNode events only if the feature is enabled.
	if externalNodeEnabled {
		m.externalNodeInformer = externalNodeInformer
		m.externalNodeLister = externalNodeInformer.Lister()
		m.externalNodeListerSynced = externalNodeInformer.Informer().HasSynced
		m.externalNodeQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalNode")
		externalNodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    m.enqueueExternalNode,
			UpdateFunc: nil,
			DeleteFunc: m.enqueueExternalNode,
		})
	}

	return m
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *controllerMonitor) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	cacheSyncs := []cache.InformerSynced{monitor.nodeListerSynced}
	// Only wait for externalNodeListerSynced when ExternalNode feature is enabled.
	if monitor.externalNodeEnabled {
		cacheSyncs = append(cacheSyncs, monitor.externalNodeListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	// Sync controller monitoring CRD every minute util stopCh is closed.
	go wait.Until(monitor.syncControllerCRD, time.Minute, stopCh)

	if !monitor.antreaAgentInfoAPIAvailable(stopCh) {
		klog.InfoS("The AntreaAgentInfo API is unavailable, will not run node workers")
		return
	}
	monitor.deleteStaleAgentCRDs()
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(monitor.nodeWorker, time.Second, stopCh)
		if monitor.externalNodeEnabled {
			go wait.Until(monitor.externalNodeWorker, time.Second, stopCh)
		}
	}
}

func (monitor *controllerMonitor) syncControllerCRD() {
	var err error
	if monitor.controllerCRD != nil {
		if monitor.controllerCRD, err = monitor.updateControllerCRD(true); err == nil {
			return
		}
		klog.ErrorS(err, "Failed to partially update controller monitoring CRD")
		monitor.controllerCRD = nil
	}

	monitor.controllerCRD, err = monitor.getControllerCRD(v1beta1.AntreaControllerInfoResourceName)

	if errors.IsNotFound(err) {
		monitor.controllerCRD, err = monitor.createControllerCRD(v1beta1.AntreaControllerInfoResourceName)
		if err != nil {
			klog.ErrorS(err, "Failed to create controller monitoring CRD")
			monitor.controllerCRD = nil
		}
		return
	}

	if err != nil {
		klog.ErrorS(err, "Failed to get controller monitoring CRD")
		monitor.controllerCRD = nil
		return
	}

	monitor.controllerCRD, err = monitor.updateControllerCRD(false)
	if err != nil {
		klog.ErrorS(err, "Failed to entirely update controller monitoring CRD")
		monitor.controllerCRD = nil
	}
}

// getControllerCRD is used to check the existence of controller monitoring CRD.
// So when the Pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *controllerMonitor) getControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

func (monitor *controllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := new(v1beta1.AntreaControllerInfo)
	controllerCRD.Name = crdName
	monitor.querier.GetControllerInfo(controllerCRD, false)
	klog.V(2).Infof("Creating controller monitoring CRD %+v", controllerCRD)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Create(context.TODO(), controllerCRD, metav1.CreateOptions{})
}

// updateControllerCRD updates the monitoring CRD.
func (monitor *controllerMonitor) updateControllerCRD(partial bool) (*v1beta1.AntreaControllerInfo, error) {
	monitor.querier.GetControllerInfo(monitor.controllerCRD, partial)
	klog.V(2).Infof("Updating controller monitoring CRD %+v, partial: %t", monitor.controllerCRD, partial)
	return monitor.client.CrdV1beta1().AntreaControllerInfos().Update(context.TODO(), monitor.controllerCRD, metav1.UpdateOptions{})
}

func (monitor *controllerMonitor) deleteStaleAgentCRDs() {
	crds, err := monitor.client.CrdV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{
		ResourceVersion: "0",
	})
	if err != nil {
		klog.ErrorS(err, "Failed to list agent monitoring CRDs")
		return
	}
	existingNames := sets.New[string]()
	for _, crd := range crds.Items {
		existingNames.Insert(crd.Name)
	}
	// Delete stale agent monitoring CRD based on existing Nodes and ExternalNodes.
	expectedNames := sets.New[string]()
	nodes, err := monitor.nodeLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Failed to list nodes")
		return
	}
	for _, node := range nodes {
		expectedNames.Insert(node.Name)
	}
	if monitor.externalNodeEnabled {
		externalNodes, err := monitor.externalNodeLister.List(labels.Everything())
		if err != nil {
			klog.ErrorS(err, "Failed to list ExternalNode CRDs")
			return
		}
		for _, en := range externalNodes {
			expectedNames.Insert(en.Name)
		}
	}
	staleSet := existingNames.Difference(expectedNames)
	for _, name := range sets.List(staleSet) {
		monitor.deleteAgentCRD(name)
	}
}

func (monitor *controllerMonitor) enqueueNode(obj interface{}) {
	node := obj.(*corev1.Node)
	key, _ := keyFunc(node)
	monitor.nodeQueue.Add(key)
}

func (monitor *controllerMonitor) enqueueExternalNode(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	monitor.externalNodeQueue.Add(key)
}

func (n *controllerMonitor) nodeWorker() {
	for n.processNextNodeWorkItem() {
	}
}

func (n *controllerMonitor) externalNodeWorker() {
	for n.processNextExternalNodeWorkItem() {
	}
}

func (c *controllerMonitor) processNextNodeWorkItem() bool {
	obj, quit := c.nodeQueue.Get()
	if quit {
		return false
	}
	defer c.nodeQueue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.nodeQueue.Forget(obj)
		klog.Errorf("Expected string in Node work queue but got %#v", obj)
		return true
	} else if err := c.syncNode(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.nodeQueue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.nodeQueue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing Node", "Node", key)
	}
	return true
}

func (c *controllerMonitor) processNextExternalNodeWorkItem() bool {
	obj, quit := c.externalNodeQueue.Get()
	if quit {
		return false
	}
	defer c.externalNodeQueue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.externalNodeQueue.Forget(obj)
		klog.Errorf("Expected string in ExternalNode work queue but got %#v", obj)
		return true
	} else if err := c.syncExternalNode(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.externalNodeQueue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.externalNodeQueue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing ExternalNode", "ExternalNode", key)
	}
	return true
}

func (c *controllerMonitor) syncNode(key string) error {
	_, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	_, err = c.nodeLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return c.deleteAgentCRD(name)
		} else {
			return err
		}
	}
	return c.createAgentCRD(name)

}

func (c *controllerMonitor) syncExternalNode(key string) error {
	namespace, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	_, err = c.externalNodeLister.ExternalNodes(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return c.deleteAgentCRD(name)
		} else {
			return err
		}
	}
	return c.createAgentCRD(name)

}

func (monitor *controllerMonitor) createAgentCRD(name string) error {
	klog.InfoS("Creating agent monitoring CRD", "name", name)
	agentCRD := new(v1beta1.AntreaAgentInfo)
	agentCRD.Name = name
	_, err := monitor.client.CrdV1beta1().AntreaAgentInfos().Create(context.TODO(), agentCRD, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			klog.InfoS("Skipping creating agent monitoring CRD as it already exists", "name", name)
		} else {
			return err
		}
	}
	return nil
}

func (monitor *controllerMonitor) deleteAgentCRD(name string) error {
	klog.InfoS("Deleting agent monitoring CRD", "name", name)
	err := monitor.client.CrdV1beta1().AntreaAgentInfos().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			klog.InfoS("Skipping deleting agent monitoring CRD as it is not found", "name", name)
		} else {
			return err
		}
	}
	return nil
}

func (monitor *controllerMonitor) antreaAgentInfoAPIAvailable(stopCh <-chan struct{}) bool {
	groupVersion := v1beta1.SchemeGroupVersion.String()
	checkFunc := func() (done bool, err error) {
		resources, err := monitor.client.Discovery().ServerResourcesForGroupVersion(groupVersion)
		if err != nil {
			if !errors.IsNotFound(err) {
				return false, err
			}
			klog.InfoS("No server resources found for GroupVersion", "groupVersion", groupVersion)
			return false, nil
		}
		for _, resource := range resources.APIResources {
			if resource.Kind == agentInfoResourceKind {
				return true, nil
			}
		}
		return false, nil
	}

	found := false
	if err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), time.Second*10, true, func(ctx context.Context) (done bool, err error) {
		var checkErr error
		found, checkErr = checkFunc()
		if checkErr != nil {
			klog.ErrorS(err, "Error getting server resources for GroupVersion, will retry after 10s", "groupVersion", groupVersion)
			return false, nil
		}
		return true, nil
	}); err != nil {
		klog.ErrorS(err, "Failed to get server resources for GroupVersion", "groupVersion", groupVersion)
		found = false
	}
	return found
}

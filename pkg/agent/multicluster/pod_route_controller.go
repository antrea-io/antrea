// Copyright 2023 Antrea Authors
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

package multicluster

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/pkg/client/informers/externalversions/multicluster/v1alpha1"
	mclisters "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
)

const (
	// The number of workers processing a Pod change
	podWorkerNum = 5

	dummyKey               = "key"
	podIndexKey            = "podIP"
	podRouteControllerName = "MCPodRouteController"
)

// MCPodRouteController generates L3 forwarding flows to forward cross-cluster
// traffic from MC Gateway to Pods on other Nodes inside a member cluster. It is
// required when networkPolicyOnly, noEncap or hybrid mode are configured, to forward
// the traffic through tunnels between Gateway and other Nodes, as otherwise the
// traffic will not go through tunnels in those modes.
type MCPodRouteController struct {
	k8sClient   kubernetes.Interface
	ofClient    openflow.Client
	nodeConfig  *config.NodeConfig
	podQueue    workqueue.RateLimitingInterface
	gwQueue     workqueue.RateLimitingInterface
	podInformer cache.SharedIndexInformer
	podLister   corelisters.PodLister
	gwInformer  cache.SharedIndexInformer
	gwLister    mclisters.GatewayLister
	// podWorkersStarted is a boolean which tracks if the Pod flow controller has been started.
	podWorkersStarted      bool
	podWorkersStartedMutex sync.RWMutex
	podWorkerStopCh        chan struct{}
}

func NewMCPodRouteController(
	k8sClient kubernetes.Interface,
	gwInformer v1alpha1.GatewayInformer,
	client openflow.Client,
	nodeConfig *config.NodeConfig,
) *MCPodRouteController {
	controller := &MCPodRouteController{
		k8sClient:       k8sClient,
		ofClient:        client,
		nodeConfig:      nodeConfig,
		podQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "MCPodRouteControllerForPod"),
		gwQueue:         workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "MCPodRouteControllerForGateway"),
		gwInformer:      gwInformer.Informer(),
		gwLister:        gwInformer.Lister(),
		podWorkerStopCh: make(chan struct{}),
	}

	controller.gwInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				controller.enqueueGateway(cur)
			},
			// Gateway UPDATE event doesn't impact Pod flows, so ignore it.
			DeleteFunc: func(old interface{}) {
				controller.enqueueGateway(old)
			},
		},
		resyncPeriod,
	)
	return controller
}

func podIPIndexFunc(obj interface{}) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("obj is not Pod: %+v", obj)
	}
	if isValidPod(pod) {
		return []string{pod.Status.PodIP}, nil
	}
	return []string{}, nil
}

func (c *MCPodRouteController) createPodInformer() {
	listOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = fields.OneTermNotEqualSelector("spec.nodeName", c.nodeConfig.Name).String()
	}
	c.podInformer = coreinformers.NewFilteredPodInformer(
		c.k8sClient,
		metav1.NamespaceAll,
		0,
		cache.Indexers{podIndexKey: podIPIndexFunc},
		listOptions,
	)
	c.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				c.createPod(cur)
			},
			UpdateFunc: func(old, cur interface{}) {
				c.updatePod(old, cur)
			},
			DeleteFunc: func(old interface{}) {
				c.deletePod(old)
			},
		},
		resyncPeriod,
	)
	c.podLister = corelisters.NewPodLister(c.podInformer.GetIndexer())
}

func (c *MCPodRouteController) enqueueGateway(obj interface{}) {
	_, isGW := obj.(*mcv1alpha1.Gateway)
	if !isGW {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "object", obj)
			return
		}
		_, ok = deletedState.Obj.(*mcv1alpha1.Gateway)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Gateway object", "object", deletedState.Obj)
			return
		}
	}
	c.gwQueue.Add(dummyKey)
}

func (c *MCPodRouteController) createPod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	if !isValidPod(pod) {
		return
	}
	c.podQueue.Add(pod.Status.PodIP)
}

func (c *MCPodRouteController) updatePod(old, cur interface{}) {
	oldPod := old.(*corev1.Pod)
	curPod := cur.(*corev1.Pod)

	isOldPodValid := isValidPod(oldPod)
	isCurPodValid := isValidPod(curPod)
	if !isCurPodValid && !isOldPodValid {
		return
	}

	if !isOldPodValid {
		c.podQueue.Add(curPod.Status.PodIP)
		return
	}

	if !isCurPodValid {
		c.podQueue.Add(oldPod.Status.PodIP)
		return
	}

	if oldPod.Status.PodIP != curPod.Status.PodIP {
		c.podQueue.Add(oldPod.Status.PodIP)
		c.podQueue.Add(curPod.Status.PodIP)
		return
	}

	if oldPod.Status.HostIP != curPod.Status.HostIP {
		c.podQueue.Add(curPod.Status.PodIP)
	}
}

func (c *MCPodRouteController) deletePod(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Received unexpected object", "object", obj)
			return
		}
		pod, ok = deletedState.Obj.(*corev1.Pod)
		if !ok {
			klog.ErrorS(nil, "DeletedFinalStateUnknown contains non-Pod object", "object", deletedState.Obj)
			return
		}
	}

	if isValidPod(pod) {
		c.podQueue.Add(pod.Status.PodIP)
	}
}

func isValidPod(pod *corev1.Pod) bool {
	if pod.Status.PodIP != "" && pod.Status.HostIP != "" && !pod.Spec.HostNetwork {
		return true
	}
	return false
}

func (c *MCPodRouteController) Run(stopCh <-chan struct{}) {
	defer c.gwQueue.ShutDown()
	defer c.podQueue.ShutDown()

	klog.InfoS("Starting controller", "controller", podRouteControllerName)
	defer klog.InfoS("Shutting down controller", "controller", podRouteControllerName)
	if !cache.WaitForNamedCacheSync(podRouteControllerName, stopCh, c.gwInformer.HasSynced) {
		return
	}
	// Run a single routine to handle Gateway events.
	go wait.Until(c.gatewayWorker, time.Second, stopCh)
	<-stopCh
}

func (c *MCPodRouteController) gatewayWorker() {
	for c.processGatewayNextWorkItem() {
	}
}

func (c *MCPodRouteController) processGatewayNextWorkItem() bool {
	key, quit := c.gwQueue.Get()
	if quit {
		return false
	}
	defer c.gwQueue.Done(key)

	if k, ok := key.(string); !ok {
		c.gwQueue.Forget(k)
		klog.InfoS("Expected string in work queue but got %#v", "object", k)
		return true
	} else if err := c.syncGateway(); err == nil {
		c.gwQueue.Forget(key)
	} else {
		c.gwQueue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing Gateway, requeuing", "key", key)
	}
	return true
}

func (c *MCPodRouteController) syncGateway() error {
	activeGW, err := getActiveGateway(c.gwLister)
	if err != nil {
		klog.ErrorS(err, "Failed to get an active Gateway")
		return err
	}

	c.podWorkersStartedMutex.Lock()
	defer c.podWorkersStartedMutex.Unlock()

	amIGateway := activeGW != nil && c.nodeConfig.Name == activeGW.Name
	// Stop Pod flow controller and clean up all installed Multi-cluster Pod flows,
	// if the Node was a Gateway before.
	if !amIGateway {
		if c.podWorkersStarted {
			klog.InfoS("Shutting down Multi-cluster PodFlowController")
			close(c.podWorkerStopCh)
			c.podWorkerStopCh = nil
			c.podInformer = nil
			c.podLister = nil
			c.podWorkersStarted = false
		}
	}

	if !amIGateway || (amIGateway && !c.podWorkersStarted) {
		err := c.ofClient.UninstallMulticlusterPodFlows("")
		if err != nil {
			return err
		}
	}

	if amIGateway {
		if !c.podWorkersStarted {
			klog.InfoS("Starting Multi-cluster PodFlowController")
			c.podWorkerStopCh = make(chan struct{})
			c.createPodInformer()
			go c.podInformer.Run(c.podWorkerStopCh)
			if !cache.WaitForNamedCacheSync(podRouteControllerName, c.podWorkerStopCh, c.podInformer.HasSynced) {
				c.podWorkerStopCh = nil
				c.podInformer = nil
				c.podLister = nil
				return errors.New("failed to sync Pod cache")
			}

			for i := 0; i < podWorkerNum; i++ {
				go wait.Until(c.podWorker, time.Second, c.podWorkerStopCh)
			}
			c.podWorkersStarted = true
			return nil
		}
		// Do nothing when the Pod flow controller is already started since
		// Pod flow controller will be responsible for handling Pod events to install flows.
	}
	return nil
}

func (c *MCPodRouteController) podWorker() {
	for c.processPodNextWorkItem() {
	}
}

func (c *MCPodRouteController) processPodNextWorkItem() bool {
	obj, quit := c.podQueue.Get()
	if quit {
		return false
	}
	defer c.podQueue.Done(obj)

	if k, ok := obj.(string); !ok {
		c.podQueue.Forget(obj)
		klog.InfoS("Expected string in work queue but got %#v", "object", obj)
		return true
	} else if err := c.syncPod(k); err == nil {
		c.podQueue.Forget(k)
	} else {
		c.podQueue.AddRateLimited(k)
		klog.ErrorS(err, "Error syncing key, requeuing", "key", k)
	}
	return true
}

func (c *MCPodRouteController) syncPod(podIP string) error {
	c.podWorkersStartedMutex.RLock()
	defer c.podWorkersStartedMutex.RUnlock()
	if !c.podWorkersStarted {
		return nil
	}

	pods, _ := c.podInformer.GetIndexer().ByIndex(podIndexKey, podIP)
	if len(pods) == 0 {
		klog.V(2).InfoS("Deleting Multi-cluster flows for Pod", "podIP", podIP)
		if err := c.ofClient.UninstallMulticlusterPodFlows(podIP); err != nil {
			klog.ErrorS(err, "Failed to uninstall Multi-cluster flows for Pod", "podIP", podIP)
			return err
		}
		return nil
	}

	latestPod := c.getLatestPod(pods)
	nodeIP := latestPod.Status.HostIP
	klog.V(2).InfoS("Adding Multi-cluster flows for Pod", "podIP", podIP, "nodeIP", nodeIP)
	if err := c.ofClient.InstallMulticlusterPodFlows(net.ParseIP(podIP), net.ParseIP(nodeIP)); err != nil {
		klog.ErrorS(err, "Failed to install Multi-cluster flows for Pod", "podIP", podIP, "nodeIP", nodeIP)
		return err
	}
	return nil
}

func (c *MCPodRouteController) getLatestPod(pods []interface{}) *corev1.Pod {
	lastCreatedPod := pods[0].(*corev1.Pod)
	for _, podObj := range pods {
		pod := podObj.(*corev1.Pod)
		if lastCreatedPod.CreationTimestamp.Before(&pod.CreationTimestamp) {
			lastCreatedPod = pod
		}
	}
	return lastCreatedPod
}

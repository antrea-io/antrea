/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
// Copyright 2021 Antrea Authors
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

Modifies:
- Replace k8s.io/kubernetes/pkg/controller/nodeipam/ipam import with
  antrea.io/antrea/third_party/ipam/nodeipam/ipam
- Remove recorder from rangeAllocator type, NewCIDRRangeAllocator(), RecordNodeStatusChange() calls
- Run() takes stopCh <-chan struct{} instead of context.Context
*/

package ipam

import (
	"fmt"
	"net"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	nodeutil "antrea.io/antrea/third_party/ipam/controller_util_node"
	"antrea.io/antrea/third_party/ipam/nodeipam/ipam/cidrset"
	utilnode "antrea.io/antrea/third_party/ipam/util_node"
)

type rangeAllocator struct {
	client clientset.Interface
	// cluster cidrs as passed in during controller creation
	clusterCIDRs []*net.IPNet
	// for each entry in clusterCIDRs we maintain a list of what is used and what is not
	cidrSets []*cidrset.CidrSet
	// nodeLister is able to list/get nodes and is populated by the shared informer passed to controller
	nodeLister corelisters.NodeLister
	// nodesSynced returns true if the node shared informer has been synced at least once.
	nodesSynced cache.InformerSynced

	// queues are where incoming work is placed to de-dup and to allow "easy"
	// rate limited requeues on errors
	queue workqueue.RateLimitingInterface
}

// NewCIDRRangeAllocator returns a CIDRAllocator to allocate CIDRs for node (one from each of clusterCIDRs)
// Caller must ensure subNetMaskSize is not less than cluster CIDR mask size.
// Caller must always pass in a list of existing nodes so the new allocator.
// Caller must ensure that ClusterCIDRs are semantically correct e.g (1 for non DualStack, 2 for DualStack etc..)
// can initialize its CIDR map. NodeList is only nil in testing.
func NewCIDRRangeAllocator(client clientset.Interface, nodeInformer informers.NodeInformer, allocatorParams CIDRAllocatorParams, nodeList *v1.NodeList) (CIDRAllocator, error) {
	if client == nil {
		klog.Fatal("kubeClient is nil when starting NodeController")
	}

	klog.InfoS("Sending events to api server")

	// create a cidrSet for each cidr we operate on
	// cidrSet are mapped to clusterCIDR by index
	cidrSets := make([]*cidrset.CidrSet, len(allocatorParams.ClusterCIDRs))
	for idx, cidr := range allocatorParams.ClusterCIDRs {
		cidrSet, err := cidrset.NewCIDRSet(cidr, allocatorParams.NodeCIDRMaskSizes[idx])
		if err != nil {
			return nil, err
		}
		cidrSets[idx] = cidrSet
	}

	ra := &rangeAllocator{
		client:       client,
		clusterCIDRs: allocatorParams.ClusterCIDRs,
		cidrSets:     cidrSets,
		nodeLister:   nodeInformer.Lister(),
		nodesSynced:  nodeInformer.Informer().HasSynced,
		queue:        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cidrallocator_node"),
	}

	if allocatorParams.ServiceCIDR != nil {
		ra.filterOutServiceRange(allocatorParams.ServiceCIDR)
	} else {
		klog.InfoS("No Service CIDR provided. Skipping filtering out service addresses")
	}

	if allocatorParams.SecondaryServiceCIDR != nil {
		ra.filterOutServiceRange(allocatorParams.SecondaryServiceCIDR)
	} else {
		klog.InfoS("No Secondary Service CIDR provided. Skipping filtering out secondary service addresses")
	}

	if nodeList != nil {
		for _, node := range nodeList.Items {
			if len(node.Spec.PodCIDRs) == 0 {
				klog.V(4).InfoS("Node has no CIDR, ignoring", "node", node.Name)
				continue
			}
			klog.V(4).InfoS("Node has CIDR, occupying it in CIDR map", "node", node.Name, "podCIDR", node.Spec.PodCIDR)
			if err := ra.occupyCIDRs(&node); err != nil {
				// This will happen if:
				// 1. We find garbage in the podCIDRs field. Retrying is useless.
				// 2. CIDR out of range: This means a node CIDR has changed.
				// This error will keep crashing controller-manager.
				return nil, err
			}
		}
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				ra.queue.Add(key)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				ra.queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// The informer cache no longer has the object, and since Node doesn't have a finalizer,
			// we don't see the Update with DeletionTimestamp != 0.
			node, ok := obj.(*v1.Node)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
					return
				}
				node, ok = tombstone.Obj.(*v1.Node)
				if !ok {
					utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
					return
				}
			}
			if err := ra.ReleaseCIDR(node); err != nil {
				utilruntime.HandleError(fmt.Errorf("error while processing CIDR Release: %w", err))
			}
		},
	})

	return ra, nil
}

func (r *rangeAllocator) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer r.queue.ShutDown()

	klog.InfoS("Starting range CIDR allocator")
	defer klog.InfoS("Shutting down range CIDR allocator")

	if !cache.WaitForNamedCacheSync("cidrallocator", stopCh, r.nodesSynced) {
		return
	}

	for i := 0; i < cidrUpdateWorkers; i++ {
		go wait.Until(r.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

// runWorker is a long-running function that will continually call the
// processNextNodeWorkItem function in order to read and process a message on the
// queue.
func (r *rangeAllocator) runWorker() {
	for r.processNextNodeWorkItem() {
	}
}

// processNextNodeWorkItem will read a single work item off the queue and
// attempt to process it, by calling the syncHandler.
func (r *rangeAllocator) processNextNodeWorkItem() bool {
	obj, shutdown := r.queue.Get()
	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer r.queue.Done(obj)
		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			r.queue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in work queue but got %#v", obj))
			return nil
		}
		if err := r.syncNode(key); err != nil {
			r.queue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		r.queue.Forget(obj)
		klog.V(4).InfoS("Successfully synced", "key", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

func (r *rangeAllocator) syncNode(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing Node request", "node", key, "elapsed", time.Since(startTime))
	}()

	node, err := r.nodeLister.Get(key)
	if apierrors.IsNotFound(err) {
		klog.V(3).InfoS("Node has been deleted", "node", key)
		return nil
	}
	if err != nil {
		return err
	}
	// Check the DeletionTimestamp to determine if object is under deletion.
	if !node.DeletionTimestamp.IsZero() {
		klog.V(3).InfoS("Node is being deleted", "node", key)
		return nil
	}
	return r.AllocateOrOccupyCIDR(node)
}

// marks node.PodCIDRs[...] as used in allocator's tracked cidrSet
func (r *rangeAllocator) occupyCIDRs(node *v1.Node) error {
	if len(node.Spec.PodCIDRs) == 0 {
		return nil
	}
	for idx, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse node %s, CIDR %s", node.Name, node.Spec.PodCIDR)
		}
		// If node has a pre allocate cidr that does not exist in our cidrs.
		// This will happen if cluster went from dualstack(multi cidrs) to non-dualstack
		// then we have now way of locking it
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}

		if err := r.cidrSets[idx].Occupy(podCIDR); err != nil {
			return fmt.Errorf("failed to mark cidr[%v] at idx [%v] as occupied for node: %v: %v", podCIDR, idx, node.Name, err)
		}
	}
	return nil
}

func (r *rangeAllocator) AllocateOrOccupyCIDR(node *v1.Node) error {
	if node == nil {
		return nil
	}

	if len(node.Spec.PodCIDRs) > 0 {
		return r.occupyCIDRs(node)
	}

	allocatedCIDRs := make([]*net.IPNet, len(r.cidrSets))

	for idx := range r.cidrSets {
		podCIDR, err := r.cidrSets[idx].AllocateNext()
		if err != nil {
			nodeutil.RecordNodeStatusChange(node, "CIDRNotAvailable")
			return fmt.Errorf("failed to allocate cidr from cluster cidr at idx:%v: %v", idx, err)
		}
		allocatedCIDRs[idx] = podCIDR
	}

	//queue the assignment
	klog.V(4).InfoS("Putting node with CIDR into the work queue", "node", node.Name, "CIDRs", allocatedCIDRs)
	return r.updateCIDRsAllocation(node.Name, allocatedCIDRs)
}

// ReleaseCIDR marks node.podCIDRs[...] as unused in our tracked cidrSets
func (r *rangeAllocator) ReleaseCIDR(node *v1.Node) error {
	if node == nil || len(node.Spec.PodCIDRs) == 0 {
		return nil
	}

	for idx, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR %s on Node %v: %v", cidr, node.Name, err)
		}

		// If node has a pre allocate cidr that does not exist in our cidrs.
		// This will happen if cluster went from dualstack(multi cidrs) to non-dualstack
		// then we have now way of locking it
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}

		klog.V(4).InfoS("Release CIDR for node", "CIDR", cidr, "node", node.Name)
		if err = r.cidrSets[idx].Release(podCIDR); err != nil {
			return fmt.Errorf("error when releasing CIDR %v: %v", cidr, err)
		}
	}
	return nil
}

// Marks all CIDRs with subNetMaskSize that belongs to serviceCIDR as used across all cidrs
// so that they won't be assignable.
func (r *rangeAllocator) filterOutServiceRange(serviceCIDR *net.IPNet) {
	// Checks if service CIDR has a nonempty intersection with cluster
	// CIDR. It is the case if either clusterCIDR contains serviceCIDR with
	// clusterCIDR's Mask applied (this means that clusterCIDR contains
	// serviceCIDR) or vice versa (which means that serviceCIDR contains
	// clusterCIDR).
	for idx, cidr := range r.clusterCIDRs {
		// if they don't overlap then ignore the filtering
		if !cidr.Contains(serviceCIDR.IP.Mask(cidr.Mask)) && !serviceCIDR.Contains(cidr.IP.Mask(serviceCIDR.Mask)) {
			continue
		}

		// at this point, len(cidrSet) == len(clusterCidr)
		if err := r.cidrSets[idx].Occupy(serviceCIDR); err != nil {
			klog.ErrorS(err, "Error filtering out service CIDR from cluster CIDR", "clusterCIDR", cidr, "index", idx, "serviceCIDR", serviceCIDR)
		}
	}
}

// updateCIDRsAllocation assigns CIDR to Node and sends an update to the API server.
func (r *rangeAllocator) updateCIDRsAllocation(nodeName string, allocatedCIDRs []*net.IPNet) error {
	var err error
	var node *v1.Node
	cidrsString := cidrsAsString(allocatedCIDRs)
	node, err = r.nodeLister.Get(nodeName)
	if err != nil {
		klog.ErrorS(err, "Failed while getting node for updating Node.Spec.PodCIDRs", "node", nodeName)
		return err
	}

	// if cidr list matches the proposed.
	// then we possibly updated this node
	// and just failed to ack the success.
	if len(node.Spec.PodCIDRs) == len(allocatedCIDRs) {
		match := true
		for idx, cidr := range cidrsString {
			if node.Spec.PodCIDRs[idx] != cidr {
				match = false
				break
			}
		}
		if match {
			klog.V(4).InfoS("Node already has allocated CIDR. It matches the proposed one", "node", node.Name, "CIDRs", allocatedCIDRs)
			return nil
		}
	}

	// node has cidrs, release the reserved
	if len(node.Spec.PodCIDRs) != 0 {
		klog.ErrorS(nil, "Node already has a CIDR allocated. Releasing the new one", "node", node.Name, "podCIDRs", node.Spec.PodCIDRs)
		for idx, cidr := range allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				klog.ErrorS(releaseErr, "Error when releasing CIDR", "index", idx, "CIDR", cidr)
			}
		}
		return nil
	}

	// If we reached here, it means that the node has no CIDR currently assigned. So we set it.
	for i := 0; i < cidrUpdateRetries; i++ {
		if err = utilnode.PatchNodeCIDRs(r.client, types.NodeName(node.Name), cidrsString); err == nil {
			klog.InfoS("Set node PodCIDR", "node", node.Name, "podCIDRs", cidrsString)
			return nil
		}
	}
	// failed release back to the pool
	klog.ErrorS(err, "Failed to update node PodCIDR after multiple attempts", "node", node.Name, "podCIDRs", cidrsString)
	nodeutil.RecordNodeStatusChange(node, "CIDRAssignmentFailed")
	// We accept the fact that we may leak CIDRs here. This is safer than releasing
	// them in case when we don't know if request went through.
	// NodeController restart will return all falsely allocated CIDRs to the pool.
	if !apierrors.IsServerTimeout(err) {
		klog.ErrorS(err, "CIDR assignment for node failed. Releasing allocated CIDR", "node", node.Name)
		for idx, cidr := range allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				klog.ErrorS(releaseErr, "Error releasing allocated CIDR for node", "node", node.Name)
			}
		}
	}
	return err
}

// converts a slice of cidrs into <c-1>,<c-2>,<c-n>
func cidrsAsString(inCIDRs []*net.IPNet) []string {
	outCIDRs := make([]string, len(inCIDRs))
	for idx, inCIDR := range inCIDRs {
		outCIDRs[idx] = inCIDR.String()
	}
	return outCIDRs
}

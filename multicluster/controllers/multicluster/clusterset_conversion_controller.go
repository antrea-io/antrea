/*
Copyright 2023 Antrea Authors.

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

package multicluster

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	mcsv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

// In Antrea 1.13, ClusterClaim CRD will be removed from Antrea Multi-cluster API.
// ClusterSetConversionController is responsible to convert fetch clusterID and clusterSetID
// from existing ClusterClaims into the clusterID field of ClusterSet for smooth upgrade
// without manual intervention.
type ClusterSetConversionController struct {
	client.Client
	Scheme    *runtime.Scheme
	namespace string
	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
	// existingClusterSet saves the existing ClusterSet in case it's deleted successfully but
	// the new one is not created yet due to creation error. ClusterSetConversionController
	// should retry with this existingClusterSet.
	existingClusterSet *v1alpha2.ClusterSet
}

func NewClusterSetConversionController(
	Client client.Client,
	Scheme *runtime.Scheme,
	namespace string,
) *ClusterSetConversionController {
	controller := &ClusterSetConversionController{
		Client:    Client,
		Scheme:    Scheme,
		namespace: namespace,
		queue:     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "ClusterSetConversionController"),
	}
	return controller
}

// Enqueue will be called after ClusterSetConversionController is initialized.
func (c *ClusterSetConversionController) Enqueue() {
	// The key can be anything as we only have single item.
	c.queue.Add("key")
}

// Run starts the ClusterSetConversionController and blocks until stopCh is closed.
// it will run only once if no error happens.
func (c *ClusterSetConversionController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting ClusterSetConversionController")
	defer klog.InfoS("Shutting down ClusterSetConversionController")

	if err := c.RunOnce(); err != nil {
		c.Enqueue()
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *ClusterSetConversionController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *ClusterSetConversionController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.conversion()
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.ErrorS(err, "Error converting ClusterSet, re-queuing it")
	c.queue.AddRateLimited(key)
	return true
}

func (c *ClusterSetConversionController) RunOnce() error {
	err := c.conversion()
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterSetConversionController) conversion() error {
	clusterSets := &mcsv1alpha2.ClusterSetList{}
	ctx := context.Background()
	err := c.Client.List(ctx, clusterSets, &client.ListOptions{Namespace: c.namespace})
	if err != nil {
		return err
	}
	clusterSetsSize := len(clusterSets.Items)
	if clusterSetsSize == 0 && c.existingClusterSet == nil {
		return nil
	}
	var clusterSet v1alpha2.ClusterSet
	if clusterSetsSize > 0 {
		clusterSet = clusterSets.Items[0]
	} else {
		klog.InfoS("using pre-existing ClusterSet to convert", klog.KObj(c.existingClusterSet), "spec", c.existingClusterSet.Spec)
		clusterSet = *c.existingClusterSet
	}
	// Do nothing if the existing ClusterSet already contains ClusterID.
	if clusterSet.Spec.ClusterID != "" {
		return nil
	}

	clusterClaims := &mcsv1alpha2.ClusterClaimList{}
	err = c.Client.List(ctx, clusterClaims, &client.ListOptions{Namespace: c.namespace})
	if err != nil {
		return err
	}

	var clusterID, clusterSetID string
	if len(clusterClaims.Items) == 0 {
		return nil
	}
	for _, cc := range clusterClaims.Items {
		if cc.Name == mcsv1alpha2.WellKnownClusterClaimID {
			clusterID = cc.Value
		}
		if cc.Name == mcsv1alpha2.WellKnownClusterClaimClusterSet {
			clusterSetID = cc.Value
		}
	}

	if clusterID != "" && clusterSetID != "" {
		oldClusterSet := clusterSet
		if c.existingClusterSet == nil {
			c.existingClusterSet = &oldClusterSet
		}
		clusterSet.Spec.ClusterID = clusterID
		if clusterSetID != clusterSet.Name {
			clusterSet.Name = clusterSetID
			clusterSet.ResourceVersion = ""
			err = c.Client.Delete(ctx, &oldClusterSet)
			if err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			klog.InfoS("The old ClusterSet is deleted", "clusterset", klog.KObj(&oldClusterSet), "spec", oldClusterSet.Spec)
			err := c.Client.Create(ctx, &clusterSet)
			if err != nil {
				return err
			}
		} else {
			err := c.Client.Update(ctx, &clusterSet)
			if err != nil {
				return client.IgnoreNotFound(err)
			}
		}
		klog.InfoS("ClusterSet converted successfully", "clusterID", clusterID, "clusterSetID", clusterSetID)
	}
	return nil
}

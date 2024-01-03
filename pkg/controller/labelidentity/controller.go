// Copyright 2022 Antrea Authors
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

package labelidentity

import (
	"context"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcinformers "antrea.io/antrea/multicluster/pkg/client/informers/externalversions/multicluster/v1alpha1"
)

const (
	controllerName = "LabelIdentityController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
)

// eventsCounter is used to keep track of the number of occurrences of an event type. It uses the
// low-level atomic memory primitives from the sync/atomic package to provide atomic operations
// (Increment and Load).
// There is a known-bug on 32-bit architectures for sync/atomic:
// On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange for 64-bit alignment
// of 64-bit words accessed atomically. The first word in a variable or in an allocated struct,
// array, or slice can be relied upon to be 64-bit aligned.
// As a result, instances of eventsCounter should be allocated when using them in structs; they
// should not be embedded directly.
type eventsCounter struct {
	count uint64
}

func (c *eventsCounter) Increment() {
	atomic.AddUint64(&c.count, 1)
}

func (c *eventsCounter) Load() uint64 {
	return atomic.LoadUint64(&c.count)
}

type Controller struct {
	labelInformer mcinformers.LabelIdentityInformer
	// labelListerSynced is a function which returns true if the LabelIdentity shared informer
	// has been synced at least once
	labelListerSynced cache.InformerSynced
	// labelAddEvents tracks the number of LabelIdentity Add events that have been processed.
	labelAddEvents *eventsCounter
	// labelIdentityIndex is the stores the current state of the LabelIdentities and any selector
	// that matches these LabelIdentities.
	labelIdentityIndex *LabelIdentityIndex
}

func NewLabelIdentityController(index *LabelIdentityIndex,
	labelInformer mcinformers.LabelIdentityInformer) *Controller {
	c := &Controller{
		labelIdentityIndex: index,
		labelInformer:      labelInformer,
		labelListerSynced:  labelInformer.Informer().HasSynced,
		labelAddEvents:     new(eventsCounter),
	}
	labelInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.addLabelIdentity,
			// LabelIdentities are not expected to have update events after they are created.
			// Update will be done by deleting existing one and recreate a new LabelIdentity with new ID.
			UpdateFunc: nil,
			DeleteFunc: c.deleteLabelIdentity,
		},
		resyncPeriod,
	)
	return c
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting controller", "controller", controllerName)
	defer klog.InfoS("Shutting down controller", "controller", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.labelListerSynced) {
		klog.Error("Failed to wait for label lister sync")
		return
	}
	initialLabelCount := len(c.labelInformer.Informer().GetStore().List())
	// Wait until initial label identities are processed before setting labelIdentityIndex as synced.
	if err := wait.PollUntilContextCancel(wait.ContextForChannel(stopCh), 100*time.Millisecond, true, func(ctx context.Context) (done bool, err error) {
		if uint64(initialLabelCount) > c.labelAddEvents.Load() {
			return false, nil
		}
		return true, nil
	}); err == nil {
		c.labelIdentityIndex.setSynced(true)
	}
	<-stopCh
}

func (c *Controller) addLabelIdentity(obj interface{}) {
	labelIdentity := obj.(*mcv1alpha1.LabelIdentity)
	klog.InfoS("Processing LabelIdentity ADD event", "label", labelIdentity.Spec.Label, "id", labelIdentity.Spec.ID)
	c.labelIdentityIndex.AddLabelIdentity(labelIdentity.Spec.Label, labelIdentity.Spec.ID)
	c.labelAddEvents.Increment()
}

func (c *Controller) deleteLabelIdentity(obj interface{}) {
	labelIdentity := obj.(*mcv1alpha1.LabelIdentity)
	klog.InfoS("Processing LabelIdentity DELETE event", "label", labelIdentity.Spec.Label)
	c.labelIdentityIndex.DeleteLabelIdentity(labelIdentity.Spec.Label)
}

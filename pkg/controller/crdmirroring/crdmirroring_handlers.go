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

package crdmirroring

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/controller/crdmirroring/types"
)

func (c *Controller) onNewCRDAdd(obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s ADD event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onNewCRDUpdate(prevObj, obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s UPDATE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onNewCRDDelete(obj interface{}) {
	crd := getCRDFromDeleteAction(obj)
	if crd == nil {
		return
	}

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s DELETE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDAdd(obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s ADD event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDUpdate(prevObj, obj interface{}) {
	prevCrd := prevObj.(metav1.Object)

	_, exist := prevCrd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s UPDATE event", c.crdName, prevCrd.GetNamespace(), prevCrd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDDelete(obj interface{}) {
	crd := getCRDFromDeleteAction(obj)
	if crd == nil {
		return
	}

	_, exist := crd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s DELETE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func getCRDFromDeleteAction(obj interface{}) metav1.Object {
	_, ok := obj.(metav1.Object)
	if ok {
		return obj.(metav1.Object)
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
		return nil
	}

	_, ok = tombstone.Obj.(metav1.Object)
	if ok {
		return tombstone.Obj.(metav1.Object)
	}
	utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a object resource: %#v", obj))
	return nil
}

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

package crdhandler

import (
	"context"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crd "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	crdlister "github.com/vmware-tanzu/antrea/pkg/client/listers/crd/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/controller/crdmirroring/types"
	legacyops "github.com/vmware-tanzu/antrea/pkg/legacyapis/ops/v1alpha1"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacyopslister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/ops/v1alpha1"
)

type TraceflowHandler struct {
	lister       crdlister.TraceflowLister
	legacyLister legacyopslister.TraceflowLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
}

func NewTraceflowHandler(lister crdlister.TraceflowLister,
	legacyLister legacyopslister.TraceflowLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) types.MirroringHandler {
	mc := &TraceflowHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new Traceflow struct.
func (c *TraceflowHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.Get(name)
}

// AddNewObject creates the mirrored new Traceflow.
func (c *TraceflowHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacyops.Traceflow)
	n := c.buildNewObject(l)
	client := c.client.CrdV1alpha1().Traceflows()
	_, err := client.Create(context.TODO(), n, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// SyncObject updates the mirrored new Traceflow.
func (c *TraceflowHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		newClient := c.client.CrdV1alpha1().Traceflows()
		_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	if !c.deepEqualStatus(legacyObj, newObj) {
		l := c.syncLegacyObject(legacyObj, newObj)
		legacyClient := c.legacyClient.OpsV1alpha1().Traceflows()
		_, err := legacyClient.UpdateStatus(context.TODO(), l, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

//DeleteNewObject deletes the mirrored new Traceflow.
func (c *TraceflowHandler) DeleteNewObject(namespace, name string) error {
	client := c.client.CrdV1alpha1().Traceflows()
	return client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// LiberateNewObject updates the mirrored new ClusterGroup by deleting "crd.antrea.io/managed-by" annotation, then it
// will not be managed by mirroring controller anymore.
func (c *TraceflowHandler) LiberateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.Traceflow).DeepCopy()
	delete(n.Annotations, types.ManagedBy)
	newClient := c.client.CrdV1alpha1().Traceflows()
	_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy Traceflow struct.
func (c *TraceflowHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.Get(name)
}

// buildNewObject returns a new Traceflow struct.
func (c *TraceflowHandler) buildNewObject(obj metav1.Object) *crd.Traceflow {
	l := obj.(*legacyops.Traceflow)
	n := &crd.Traceflow{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy Traceflow's Spec and Labels to the new Traceflow.
func (c *TraceflowHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.Traceflow {
	l := legacyObj.(*legacyops.Traceflow)
	n := newObj.(*crd.Traceflow).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

// syncLegacyObject syncs new Traceflow's Status to the legacy Traceflow.
func (c *TraceflowHandler) syncLegacyObject(legacyObj, newObj metav1.Object) *legacyops.Traceflow {
	l := legacyObj.(*legacyops.Traceflow).DeepCopy()
	n := newObj.(*crd.Traceflow)
	l.Status = *n.Status.DeepCopy()
	return l
}

func (c *TraceflowHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacyops.Traceflow)
	n := newObj.(*crd.Traceflow)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

func (c *TraceflowHandler) deepEqualStatus(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacyops.Traceflow)
	n := newObj.(*crd.Traceflow)
	return reflect.DeepEqual(l.Status, n.Status)
}

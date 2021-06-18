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

	crd "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdclient "antrea.io/antrea/pkg/client/clientset/versioned/typed/crd/v1alpha2"
	crdlister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/crdmirroring/types"
	legacycore "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
	legacycoreclient "antrea.io/antrea/pkg/legacyclient/clientset/versioned/typed/core/v1alpha2"
	legacycorelister "antrea.io/antrea/pkg/legacyclient/listers/core/v1alpha2"
)

type ClusterGroupHandler struct {
	lister       crdlister.ClusterGroupLister
	legacyLister legacycorelister.ClusterGroupLister
	client       crdclient.ClusterGroupInterface
	legacyClient legacycoreclient.ClusterGroupInterface
}

func NewClusterGroupHandler(lister crdlister.ClusterGroupLister,
	legacyLister legacycorelister.ClusterGroupLister,
	client crdclient.ClusterGroupInterface,
	legacyClient legacycoreclient.ClusterGroupInterface) types.MirroringHandler {
	mc := &ClusterGroupHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new ClusterGroup struct.
func (c *ClusterGroupHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.Get(name)
}

// AddNewObject creates the mirrored new ClusterGroup.
func (c *ClusterGroupHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacycore.ClusterGroup)
	n := c.buildNewObject(l)
	_, err := c.client.Create(context.TODO(), n, metav1.CreateOptions{})
	return err
}

// SyncObject updates the mirrored new ClusterGroup.
func (c *ClusterGroupHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		_, err := c.client.Update(context.TODO(), n, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	if !c.deepEqualStatus(legacyObj, newObj) {
		l := c.syncLegacyObject(legacyObj, newObj)
		_, err := c.legacyClient.UpdateStatus(context.TODO(), l, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteNewObject deletes the mirrored new ClusterGroup.
func (c *ClusterGroupHandler) DeleteNewObject(namespace, name string) error {
	return c.client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterGroup.
func (c *ClusterGroupHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.ClusterGroup)
	_, err := c.client.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy ClusterGroup struct.
func (c *ClusterGroupHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.Get(name)
}

// buildNewObject returns a new ClusterGroup struct.
func (c *ClusterGroupHandler) buildNewObject(obj metav1.Object) *crd.ClusterGroup {
	l := obj.(*legacycore.ClusterGroup)
	n := &crd.ClusterGroup{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy ClusterGroup's Spec and Labels to the new ClusterGroup.
func (c *ClusterGroupHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.ClusterGroup {
	l := legacyObj.(*legacycore.ClusterGroup)
	n := newObj.(*crd.ClusterGroup).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

// syncLegacyObject syncs new ClusterGroup's Status to the legacy ClusterGroup.
func (c *ClusterGroupHandler) syncLegacyObject(legacyObj, newObj metav1.Object) *legacycore.ClusterGroup {
	l := legacyObj.(*legacycore.ClusterGroup).DeepCopy()
	n := newObj.(*crd.ClusterGroup)
	l.Status = *n.Status.DeepCopy()
	return l
}

func (c *ClusterGroupHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacycore.ClusterGroup)
	n := newObj.(*crd.ClusterGroup)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

func (c *ClusterGroupHandler) deepEqualStatus(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacycore.ClusterGroup)
	n := newObj.(*crd.ClusterGroup)
	return reflect.DeepEqual(l.Status, n.Status)
}

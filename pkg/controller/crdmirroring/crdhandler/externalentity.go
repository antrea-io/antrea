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

	crd "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	crdlister "github.com/vmware-tanzu/antrea/pkg/client/listers/crd/v1alpha2"
	"github.com/vmware-tanzu/antrea/pkg/controller/crdmirroring/types"
	legacycore "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacycorelister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/core/v1alpha2"
)

type ExternalEntityHandler struct {
	lister       crdlister.ExternalEntityLister
	legacyLister legacycorelister.ExternalEntityLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
}

func NewExternalEntityHandler(lister crdlister.ExternalEntityLister,
	legacyLister legacycorelister.ExternalEntityLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) types.MirroringHandler {
	mc := &ExternalEntityHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new ExternalEntity struct.
func (c *ExternalEntityHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.ExternalEntities(namespace).Get(name)
}

// AddNewObject creates the mirrored new ExternalEntity.
func (c *ExternalEntityHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacycore.ExternalEntity)
	n := c.buildNewObject(l)
	client := c.client.CrdV1alpha2().ExternalEntities(obj.GetNamespace())
	_, err := client.Create(context.TODO(), n, metav1.CreateOptions{})
	return err
}

// SyncObject updates the mirrored new ExternalEntity.
func (c *ExternalEntityHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		newClient := c.client.CrdV1alpha2().ExternalEntities(legacyObj.GetNamespace())
		_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
		return err
	}
	return nil
}

// DeleteNewObject deletes the mirrored new ExternalEntity.
func (c *ExternalEntityHandler) DeleteNewObject(namespace, name string) error {
	client := c.client.CrdV1alpha2().ExternalEntities(namespace)
	return client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterGroup.
func (c *ExternalEntityHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.ExternalEntity)
	newClient := c.client.CrdV1alpha2().ExternalEntities(newObj.GetNamespace())
	_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy ExternalEntity struct.
func (c *ExternalEntityHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.ExternalEntities(namespace).Get(name)
}

// buildNewObject returns a new ExternalEntity struct.
func (c *ExternalEntityHandler) buildNewObject(obj metav1.Object) *crd.ExternalEntity {
	l := obj.(*legacycore.ExternalEntity)
	n := &crd.ExternalEntity{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy ExternalEntity' Spec and Labels to the new ExternalEntity.
func (c *ExternalEntityHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.ExternalEntity {
	l := legacyObj.(*legacycore.ExternalEntity)
	n := newObj.(*crd.ExternalEntity).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

func (c *ExternalEntityHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacycore.ExternalEntity)
	n := newObj.(*crd.ExternalEntity)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

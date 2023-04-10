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

package crdhandler

import (
	"context"
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crd "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	legacycrd "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/crdmirroring/types"
	crdclient "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/typed/multicluster/v1alpha1"
	legacycoreclient "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/typed/multicluster/v1alpha2"
	v1alpha1lister "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha1"
	v1alpha2lister "antrea.io/antrea/multicluster/pkg/client/listers/multicluster/v1alpha2"
)

type ClusterClaimHandler struct {
	lister       v1alpha1lister.ClusterPropertyLister
	legacyLister v1alpha2lister.ClusterClaimLister
	client       crdclient.ClusterPropertyInterface
	legacyClient legacycoreclient.ClusterClaimInterface
}

func NewClusterClaimHandler(lister v1alpha1lister.ClusterPropertyLister,
	legacyLister v1alpha2lister.ClusterClaimLister,
	client crdclient.ClusterPropertyInterface,
	legacyClient legacycoreclient.ClusterClaimInterface) types.MirroringHandler {
	mc := &ClusterClaimHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new ClusterProperty struct.
func (c *ClusterClaimHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.ClusterProperties(namespace).Get(name)
}

// AddNewObject creates the mirrored new ClusterProperty.
func (c *ClusterClaimHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacycrd.ClusterClaim)
	n := c.buildNewObject(l)
	_, err := c.client.Create(context.TODO(), n, metav1.CreateOptions{})
	return err
}

// SyncObject updates the mirrored new ClusterProperty.
func (c *ClusterClaimHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		_, err := c.client.Update(context.TODO(), n, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteNewObject deletes the mirrored new ClusterProperty.
func (c *ClusterClaimHandler) DeleteNewObject(namespace, name string) error {
	return c.client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterProperty.
func (c *ClusterClaimHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.ClusterProperty)
	_, err := c.client.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy ClusterClaim struct.
func (c *ClusterClaimHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.ClusterClaims(namespace).Get(name)
}

// buildNewObject returns a new ClusterProperty struct.
func (c *ClusterClaimHandler) buildNewObject(obj metav1.Object) *crd.ClusterProperty {
	l := obj.(*legacycrd.ClusterClaim)
	n := &crd.ClusterProperty{}
	n.Value = l.Value
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy ClusterClaim's Spec and Labels to the new ClusterProperty.
func (c *ClusterClaimHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.ClusterProperty {
	l := legacyObj.(*legacycrd.ClusterClaim)
	n := newObj.(*crd.ClusterProperty).DeepCopy()
	if n.Name == legacycrd.WellKnownClusterClaimID {
		n.Name = crd.WellKnownClusterPropertyID
	}
	n.Value = l.Value
	n.Labels = labelsDeepCopy(l)
	return n
}

func (c *ClusterClaimHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacycrd.ClusterClaim)
	n := newObj.(*crd.ClusterProperty)
	if !reflect.DeepEqual(l.Value, n.Value) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

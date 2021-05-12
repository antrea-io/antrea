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

	crd "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdclient "antrea.io/antrea/pkg/client/clientset/versioned/typed/crd/v1alpha1"
	crdlister "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/crdmirroring/types"
	legacysecurity "antrea.io/antrea/pkg/legacyapis/security/v1alpha1"
	legacysecurityclient "antrea.io/antrea/pkg/legacyclient/clientset/versioned/typed/security/v1alpha1"
	legacysecuritylister "antrea.io/antrea/pkg/legacyclient/listers/security/v1alpha1"
)

type ClusterNetworkPolicyHandler struct {
	lister       crdlister.ClusterNetworkPolicyLister
	legacyLister legacysecuritylister.ClusterNetworkPolicyLister
	client       crdclient.ClusterNetworkPolicyInterface
	legacyClient legacysecurityclient.ClusterNetworkPolicyInterface
}

func NewClusterNetworkPolicyHandler(lister crdlister.ClusterNetworkPolicyLister,
	legacyLister legacysecuritylister.ClusterNetworkPolicyLister,
	client crdclient.ClusterNetworkPolicyInterface,
	legacyClient legacysecurityclient.ClusterNetworkPolicyInterface) types.MirroringHandler {
	mc := &ClusterNetworkPolicyHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new ClusterNetworkPolicy struct.
func (c *ClusterNetworkPolicyHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.Get(name)
}

// AddNewObject creates the mirrored new ClusterNetworkPolicy.
func (c *ClusterNetworkPolicyHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacysecurity.ClusterNetworkPolicy)
	n := c.buildNewObject(l)
	_, err := c.client.Create(context.TODO(), n, metav1.CreateOptions{})
	return err
}

// SyncObject updates the mirrored new ClusterNetworkPolicy.
func (c *ClusterNetworkPolicyHandler) SyncObject(legacyObj, newObj metav1.Object) error {
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

// DeleteNewObject deletes the mirrored new ClusterNetworkPolicy.
func (c *ClusterNetworkPolicyHandler) DeleteNewObject(namespace, name string) error {
	return c.client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterGroup.
func (c *ClusterNetworkPolicyHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.ClusterNetworkPolicy)
	_, err := c.client.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy ClusterNetworkPolicy struct.
func (c *ClusterNetworkPolicyHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.Get(name)
}

// buildNewObject returns a new ClusterNetworkPolicy struct.
func (c *ClusterNetworkPolicyHandler) buildNewObject(obj metav1.Object) *crd.ClusterNetworkPolicy {
	l := obj.(*legacysecurity.ClusterNetworkPolicy)
	n := &crd.ClusterNetworkPolicy{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy ClusterNetworkPolicy' Spec and Labels to the new ClusterNetworkPolicy.
func (c *ClusterNetworkPolicyHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.ClusterNetworkPolicy {
	l := legacyObj.(*legacysecurity.ClusterNetworkPolicy)
	n := newObj.(*crd.ClusterNetworkPolicy).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

// syncLegacyObject syncs new ClusterNetworkPolicy's Status to the legacy ClusterNetworkPolicy.
func (c *ClusterNetworkPolicyHandler) syncLegacyObject(legacyObj, newObj metav1.Object) *legacysecurity.ClusterNetworkPolicy {
	l := legacyObj.(*legacysecurity.ClusterNetworkPolicy).DeepCopy()
	n := newObj.(*crd.ClusterNetworkPolicy)
	l.Status = *n.Status.DeepCopy()
	return l
}

func (c *ClusterNetworkPolicyHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacysecurity.ClusterNetworkPolicy)
	n := newObj.(*crd.ClusterNetworkPolicy)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

func (c *ClusterNetworkPolicyHandler) deepEqualStatus(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacysecurity.ClusterNetworkPolicy)
	n := newObj.(*crd.ClusterNetworkPolicy)
	return reflect.DeepEqual(l.Status, n.Status)
}

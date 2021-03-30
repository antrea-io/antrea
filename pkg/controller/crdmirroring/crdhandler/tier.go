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
	legacysecurity "github.com/vmware-tanzu/antrea/pkg/legacyapis/security/v1alpha1"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
	legacysecuritylister "github.com/vmware-tanzu/antrea/pkg/legacyclient/listers/security/v1alpha1"
)

type TierHandler struct {
	lister       crdlister.TierLister
	legacyLister legacysecuritylister.TierLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
}

func NewTierHandler(lister crdlister.TierLister,
	legacyLister legacysecuritylister.TierLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) types.MirroringHandler {
	mc := &TierHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new Tier struct.
func (c *TierHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	lister := c.lister
	return lister.Get(name)
}

// AddNewObject creates the mirrored new Tier.
func (c *TierHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacysecurity.Tier)
	n := c.buildNewObject(l)
	client := c.client.CrdV1alpha1().Tiers()
	_, err := client.Create(context.TODO(), n, metav1.CreateOptions{})
	return err
}

// SyncObject updates the mirrored new Tier.
func (c *TierHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		newClient := c.client.CrdV1alpha1().Tiers()
		_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
		return err
	}
	return nil
}

// DeleteNewObject deletes the mirrored new Tier.
func (c *TierHandler) DeleteNewObject(namespace, name string) error {
	client := c.client.CrdV1alpha1().Tiers()
	return client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterGroup.
func (c *TierHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.Tier)
	newClient := c.client.CrdV1alpha1().Tiers()
	_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy Tier struct.
func (c *TierHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.Get(name)
}

// buildNewObject returns a new Tier struct.
func (c *TierHandler) buildNewObject(obj metav1.Object) *crd.Tier {
	l := obj.(*legacysecurity.Tier)
	n := &crd.Tier{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy Tier's Spec and Labels to the new Tier.
func (c *TierHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.Tier {
	l := legacyObj.(*legacysecurity.Tier)
	n := newObj.(*crd.Tier).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

func (c *TierHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacysecurity.Tier)
	n := newObj.(*crd.Tier)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

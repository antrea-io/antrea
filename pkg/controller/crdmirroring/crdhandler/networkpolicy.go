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

type NetworkPolicyHandler struct {
	lister       crdlister.NetworkPolicyLister
	legacyLister legacysecuritylister.NetworkPolicyLister
	client       crdclientset.Interface
	legacyClient legacycrdclientset.Interface
}

func NewNetworkPolicyHandler(lister crdlister.NetworkPolicyLister,
	legacyLister legacysecuritylister.NetworkPolicyLister,
	client crdclientset.Interface,
	legacyClient legacycrdclientset.Interface) types.MirroringHandler {
	mc := &NetworkPolicyHandler{
		lister:       lister,
		legacyLister: legacyLister,
		client:       client,
		legacyClient: legacyClient,
	}
	return mc
}

// GetNewObject gets the mirrored new NetworkPolicy struct.
func (c *NetworkPolicyHandler) GetNewObject(namespace, name string) (metav1.Object, error) {
	return c.lister.NetworkPolicies(namespace).Get(name)
}

// AddNewObject creates the mirrored new NetworkPolicy.
func (c *NetworkPolicyHandler) AddNewObject(obj metav1.Object) error {
	l := obj.(*legacysecurity.NetworkPolicy)
	n := c.buildNewObject(l)
	client := c.client.CrdV1alpha1().NetworkPolicies(obj.GetNamespace())
	_, err := client.Create(context.TODO(), n, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

// SyncObject updates the mirrored new NetworkPolicy.
func (c *NetworkPolicyHandler) SyncObject(legacyObj, newObj metav1.Object) error {
	if !c.deepEqualSpecAndLabels(legacyObj, newObj) {
		n := c.syncNewObject(legacyObj, newObj)
		newClient := c.client.CrdV1alpha1().NetworkPolicies(legacyObj.GetNamespace())
		_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	if !c.deepEqualStatus(legacyObj, newObj) {
		l := c.syncLegacyObject(legacyObj, newObj)
		legacyClient := c.legacyClient.SecurityV1alpha1().NetworkPolicies(legacyObj.GetNamespace())
		_, err := legacyClient.UpdateStatus(context.TODO(), l, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteNewObject deletes the mirrored new NetworkPolicy.
func (c *NetworkPolicyHandler) DeleteNewObject(namespace, name string) error {
	client := c.client.CrdV1alpha1().NetworkPolicies(namespace)
	return client.Delete(context.TODO(), name, metav1.DeleteOptions{})
}

// UpdateNewObject updates the mirrored new ClusterGroup.
func (c *NetworkPolicyHandler) UpdateNewObject(newObj metav1.Object) error {
	n := newObj.(*crd.NetworkPolicy)
	newClient := c.client.CrdV1alpha1().NetworkPolicies(newObj.GetNamespace())
	_, err := newClient.Update(context.TODO(), n, metav1.UpdateOptions{})
	return err
}

// GetLegacyObject gets the legacy NetworkPolicy struct.
func (c *NetworkPolicyHandler) GetLegacyObject(namespace, name string) (metav1.Object, error) {
	return c.legacyLister.NetworkPolicies(namespace).Get(name)
}

// buildNewObject returns a new NetworkPolicy struct.
func (c *NetworkPolicyHandler) buildNewObject(obj metav1.Object) *crd.NetworkPolicy {
	l := obj.(*legacysecurity.NetworkPolicy)
	n := &crd.NetworkPolicy{}
	n.Spec = *l.Spec.DeepCopy()
	setMetaData(l, n)
	return n
}

// syncNewObject syncs legacy NetworkPolicy's Spec and Labels to the new NetworkPolicy
func (c *NetworkPolicyHandler) syncNewObject(legacyObj, newObj metav1.Object) *crd.NetworkPolicy {
	l := legacyObj.(*legacysecurity.NetworkPolicy)
	n := newObj.(*crd.NetworkPolicy).DeepCopy()
	n.Spec = *l.Spec.DeepCopy()
	n.Labels = labelsDeepCopy(l)
	return n
}

// syncLegacyObject syncs new NetworkPolicy's Status to the legacy NetworkPolicy
func (c *NetworkPolicyHandler) syncLegacyObject(legacyObj, newObj metav1.Object) *legacysecurity.NetworkPolicy {
	l := legacyObj.(*legacysecurity.NetworkPolicy).DeepCopy()
	n := newObj.(*crd.NetworkPolicy)
	l.Status = *n.Status.DeepCopy()
	return l
}

func (c *NetworkPolicyHandler) deepEqualSpecAndLabels(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacysecurity.NetworkPolicy)
	n := newObj.(*crd.NetworkPolicy)
	if !reflect.DeepEqual(l.Spec, n.Spec) {
		return false
	}
	if !reflect.DeepEqual(l.Labels, n.Labels) {
		return false
	}
	return true
}

func (c *NetworkPolicyHandler) deepEqualStatus(legacyObj, newObj metav1.Object) bool {
	l := legacyObj.(*legacysecurity.NetworkPolicy)
	n := newObj.(*crd.NetworkPolicy)
	return reflect.DeepEqual(l.Status, n.Status)
}

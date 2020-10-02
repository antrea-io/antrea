// Copyright 2020 Antrea Authors
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

// Package networkpolicy provides NetworkPolicyController implementation to manage
// and synchronize the Pods and Namespaces affected by Network Policies and enforce
// their rules.

package networkpolicy

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
)

func externalEntityV1Alpha1ToAlpha2(ee *v1alpha1.ExternalEntity) *v1alpha2.ExternalEntity {
	var ports []v1alpha2.NamedPort
	var endpoints []v1alpha2.Endpoint
	for i, ep := range ee.Spec.Endpoints {
		if i == 0 {
			for _, p := range ep.Ports {
				ports = append(ports, v1alpha2.NamedPort{
					Protocol: p.Protocol, Port: p.Port, Name: p.Name,
				})
			}
		}
		endpoints = append(endpoints, v1alpha2.Endpoint{
			IP: ep.IP, Name: ep.Name,
		})
	}
	return &v1alpha2.ExternalEntity{
		TypeMeta:   ee.TypeMeta,
		ObjectMeta: ee.ObjectMeta,
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints:    endpoints,
			Ports:        ports,
			ExternalNode: ee.Spec.ExternalNode,
		},
	}
}

// addExternalEntity retrieves all AddressGroups and AppliedToGroups which match the ExternalEnitty's
// labels and enqueues the groups key for further processing.
func (n *NetworkPolicyController) addExternalEntity(obj interface{}) {
	defer n.heartbeat("addExternalEntity")
	ee := obj.(metav1.Object)
	klog.V(2).Infof("Processing ExternalEntity %s/%s ADD event, labels: %v", ee.GetNamespace(), ee.GetName(), ee.GetLabels())
	// Find all AppliedToGroup keys which match the ExternalEntity's labels.
	appliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(ee)
	// Find all AddressGroup keys which match the ExternalEntity's labels.
	addressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(ee)
	// Enqueue groups to their respective queues for group processing.
	for group := range appliedToGroupKeySet {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeySet {
		n.enqueueAddressGroup(group)
	}
}

// updateExternalEntity retrieves all AddressGroups and AppliedToGroups which match the
// updated and old ExternalEntity's labels and enqueues the group keys for further
// processing.
func (n *NetworkPolicyController) updateExternalEntity(oldObj, curObj interface{}) {
	defer n.heartbeat("updateExternalEntity")
	oldEE := oldObj.(metav1.Object)
	curEE := curObj.(metav1.Object)
	klog.V(2).Infof("Processing ExternalEntity %s/%s UPDATE event, labels: %v", curEE.GetNamespace(), curEE.GetName(), curEE.GetLabels())
	// No need to trigger processing of groups if there is no change in the
	// ExternalEntity labels or ExternalEntity's Endpoints.
	labelsEqual := labels.Equals(labels.Set(oldEE.GetLabels()), labels.Set(curEE.GetLabels()))
	var specEqual bool
	if oldEEObj, ok := oldEE.(*v1alpha2.ExternalEntity); ok {
		curEEObj := curEE.(*v1alpha2.ExternalEntity)
		specEqual = reflect.DeepEqual(oldEEObj.Spec, curEEObj.Spec)
	} else {
		oldEEObj := oldEE.(*v1alpha1.ExternalEntity)
		curEEObj := curEE.(*v1alpha1.ExternalEntity)
		specEqual = reflect.DeepEqual(oldEEObj.Spec, curEEObj.Spec)
	}
	// TODO: Right now two ExternalEntities are only considered equal if the list of Endpoints and
	//  all NamedPorts in each Endpoint are of the exact order. Considering implementing custom compare
	//  method for the ExternalEntity spec to solve this and improve performance.
	if labelsEqual && specEqual {
		klog.V(4).Infof("No change in ExternalEntity %s/%s. Skipping NetworkPolicy evaluation.", curEE.GetNamespace(), curEE.GetName())
		return
	}
	// Find groups matching the old ExternalEntity's labels.
	oldAppliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(oldEE)
	oldAddressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(oldEE)
	// Find groups matching the new ExternalEntity's labels.
	curAppliedToGroupKeySet := n.filterAppliedToGroupsForPodOrExternalEntity(curEE)
	curAddressGroupKeySet := n.filterAddressGroupsForPodOrExternalEntity(curEE)
	// Create set to hold the group keys to enqueue.
	var appliedToGroupKeys sets.String
	var addressGroupKeys sets.String
	// AppliedToGroup keys must be enqueued only if the ExternalEntity's spec has changed or
	// if ExternalEntity's label change causes it to match new Groups.
	if !specEqual {
		appliedToGroupKeys = oldAppliedToGroupKeySet.Union(curAppliedToGroupKeySet)
	} else if !labelsEqual {
		// No need to enqueue common AppliedToGroups as they already have latest Pod
		// information.
		appliedToGroupKeys = oldAppliedToGroupKeySet.Difference(curAppliedToGroupKeySet).Union(curAppliedToGroupKeySet.Difference(oldAppliedToGroupKeySet))
	}
	// AddressGroup keys must be enqueued only if the ExternalEntity's spec has changed or
	// if ExternalEntity's label change causes it to match new Groups.
	if !specEqual {
		addressGroupKeys = oldAddressGroupKeySet.Union(curAddressGroupKeySet)
	} else if !labelsEqual {
		// No need to enqueue common AddressGroups as they already have latest Pod
		// information.
		addressGroupKeys = oldAddressGroupKeySet.Difference(curAddressGroupKeySet).Union(curAddressGroupKeySet.Difference(oldAddressGroupKeySet))
	}
	for group := range appliedToGroupKeys {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

// deleteExternalEntity retrieves all AddressGroups and AppliedToGroups which match the ExternalEntity's
// labels and enqueues the groups key for further processing.
func (n *NetworkPolicyController) deleteExternalEntity(old interface{}) {
	ee, ok := old.(metav1.Object)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ExternalEntity, invalid type: %v", old)
			return
		}
		ee, ok = tombstone.Obj.(*v1alpha2.ExternalEntity)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ExternalEntity, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteExternalEntity")

	klog.V(2).Infof("Processing ExternalEntity %s/%s DELETE event, labels: %v", ee.GetNamespace(), ee.GetName(), ee.GetLabels())
	// Find all AppliedToGroup keys which match the Pod's labels.
	appliedToGroupKeys := n.filterAppliedToGroupsForPodOrExternalEntity(ee)
	// Find all AddressGroup keys which match the Pod's labels.
	addressGroupKeys := n.filterAddressGroupsForPodOrExternalEntity(ee)
	// Enqueue groups to their respective queues for group processing.
	for group := range appliedToGroupKeys {
		n.enqueueAppliedToGroup(group)
	}
	for group := range addressGroupKeys {
		n.enqueueAddressGroup(group)
	}
}

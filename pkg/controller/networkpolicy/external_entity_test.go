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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestExternalEntityToGroupMember(t *testing.T) {
	testEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeA",
			Namespace: "nsA",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{
					IP:   "22.33.44.55",
					Name: "vm1",
				},
			},
			Ports: []v1alpha2.NamedPort{
				{
					Port:     80,
					Name:     "http",
					Protocol: "tcp",
				},
			},
			ExternalNode: "cloud-node-1",
		},
	}
	tests := []struct {
		name        string
		inputEE     *v1alpha2.ExternalEntity
		expMemberEE controlplane.GroupMember
	}{
		{
			name:    "ee-with-ip",
			inputEE: testEntity,
			expMemberEE: controlplane.GroupMember{
				ExternalEntity: &controlplane.ExternalEntityReference{
					Name:      testEntity.Name,
					Namespace: testEntity.Namespace,
				},
				IPs: []controlplane.IPAddress{ipStrToIPAddress(testEntity.Spec.Endpoints[0].IP)},
				Ports: []controlplane.NamedPort{
					{
						Port:     80,
						Name:     "http",
						Protocol: "tcp",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMemberEE := externalEntityToGroupMember(tt.inputEE)
			if !reflect.DeepEqual(*(*actualMemberEE).ExternalEntity, *(tt.expMemberEE).ExternalEntity) {
				t.Errorf("externalEntityToGroupMember() got unexpected EEReference %v, want %v", *(*actualMemberEE).ExternalEntity, *(tt.expMemberEE).ExternalEntity)
			}
			if !comparePodIPs(actualMemberEE.IPs, tt.expMemberEE.IPs) {
				t.Errorf("externalEntityToGroupMember() got unexpected IP %v, want %v", actualMemberEE.IPs, tt.expMemberEE.IPs)
			}
		})
	}
}

func TestAddExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"group": "appliedTo"},
	}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	appliedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podA",
			Namespace: "nsA",
			Labels: map[string]string{
				"group": "appliedTo",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "container-1",
			}},
			NodeName: "nodeA",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIP: "1.2.3.4",
		},
	}
	testANPObj := getEETestANP(selectorSpec, selectorIn, selectorOut)
	tests := []struct {
		name                 string
		addedExternalEntity  interface{}
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			"no-match-ee",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "none"},
				},
			},
			false,
			false,
		},
		{
			"ee-match-ingress",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeB",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
			},
			true,
			false,
		},
		{
			"ee-match-ingress-egress",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeC",
					Namespace: "nsA",
					Labels: map[string]string{
						"inGroup":  "inAddress",
						"outGroup": "outAddress",
					},
				},
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addANP(testANPObj)
			npc.podStore.Add(appliedPod)
			if ee, ok := tt.addedExternalEntity.(*v1alpha2.ExternalEntity); ok {
				npc.externalEntityStore.Add(ee)
			}
			appGroupID := getNormalizedUID(toGroupSelector("nsA", &selectorSpec, nil, nil).NormalizedName)
			inGroupID := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorIn).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorOut).NormalizedName)

			npc.addPod(appliedPod)
			npc.addExternalEntity(tt.addedExternalEntity)
			atGroups, addrGroups := getQueuedGroups(npc)
			assert.Equal(t, true, atGroups.Has(appGroupID))
			assert.Equal(t, tt.inAddressGroupMatch, addrGroups.Has(inGroupID))
			assert.Equal(t, tt.outAddressGroupMatch, addrGroups.Has(outGroupID))

			npc.syncAppliedToGroup(appGroupID)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			var member *controlplane.GroupMember
			if ee, ok := tt.addedExternalEntity.(*v1alpha2.ExternalEntity); ok {
				member = externalEntityToGroupMember(ee)
			}
			assert.Equal(t, tt.inAddressGroupMatch, updatedInAddrGroup.GroupMembers.Has(member))
			assert.Equal(t, tt.outAddressGroupMatch, updatedOutAddrGroup.GroupMembers.Has(member))
		})
	}
}

func TestUpdateExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"group": "appliedTo"},
	}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	selectorOut2 := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress2"},
	}
	testANPObj := getEETestANP(selectorSpec, selectorIn, selectorOut)
	testANPObj2 := getEETestANP(selectorSpec, selectorIn, selectorOut2)
	ee1 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeC",
			Namespace: "nsA",
			Labels: map[string]string{
				"outGroup": "outAddress",
			},
		},
	}
	ee2 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeC",
			Namespace: "nsA",
			Labels: map[string]string{
				"outGroup": "outAddress2",
			},
		},
	}
	ee3 := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeC",
			Namespace: "nsA",
			Labels: map[string]string{
				"outGroup": "outAddress3",
			},
		},
	}
	outGroupID := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorOut).NormalizedName)
	outGroupID2 := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorOut2).NormalizedName)
	_, npc := newController()
	npc.addANP(testANPObj)
	npc.addANP(testANPObj2)
	npc.updateExternalEntity(ee3, ee1)
	_, addrGroups := getQueuedGroups(npc)
	assert.Equal(t, true, addrGroups.Has(outGroupID))
	assert.Equal(t, false, addrGroups.Has(outGroupID2))
	// outGroupID and outGroupID2 should both be queued (EE removed and EE added)
	npc.updateExternalEntity(ee1, ee2)
	_, addrGroups = getQueuedGroups(npc)
	assert.Equal(t, true, addrGroups.Has(outGroupID))
	assert.Equal(t, true, addrGroups.Has(outGroupID2))
	// only outGroupID2 should be queued (EE removed)
	npc.updateExternalEntity(ee2, ee3)
	_, addrGroups = getQueuedGroups(npc)
	assert.Equal(t, false, addrGroups.Has(outGroupID))
	assert.Equal(t, true, addrGroups.Has(outGroupID2))
}

func TestDeleteExternalEntity(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"group": "appliedTo"},
	}
	selectorIn := metav1.LabelSelector{
		MatchLabels: map[string]string{"inGroup": "inAddress"},
	}
	selectorOut := metav1.LabelSelector{
		MatchLabels: map[string]string{"outGroup": "outAddress"},
	}
	testANPObj := getEETestANP(selectorSpec, selectorIn, selectorOut)
	tests := []struct {
		name                 string
		addedExternalEntity  interface{}
		inAddressGroupMatch  bool
		outAddressGroupMatch bool
	}{
		{
			"no-match-ee",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeA",
					Namespace: "nsA",
					Labels:    map[string]string{"group": "none"},
				},
			},
			false,
			false,
		},
		{
			"ee-match-ingress",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeB",
					Namespace: "nsA",
					Labels:    map[string]string{"inGroup": "inAddress"},
				},
			},
			true,
			false,
		},
		{
			"ee-match-ingress-egress",
			&v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eeC",
					Namespace: "nsA",
					Labels: map[string]string{
						"inGroup":  "inAddress",
						"outGroup": "outAddress",
					},
				},
			},
			true,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addANP(testANPObj)
			if ee, ok := tt.addedExternalEntity.(*v1alpha2.ExternalEntity); ok {
				npc.externalEntityStore.Add(ee)
			}
			npc.addExternalEntity(tt.addedExternalEntity)
			inGroupID := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorIn).NormalizedName)
			outGroupID := getNormalizedUID(toGroupSelector("nsA", nil, nil, &selectorOut).NormalizedName)
			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)

			if ee, ok := tt.addedExternalEntity.(*v1alpha2.ExternalEntity); ok {
				npc.externalEntityStore.Delete(ee)
			}
			npc.deleteExternalEntity(tt.addedExternalEntity)
			_, addrGroups := getQueuedGroups(npc)
			if tt.inAddressGroupMatch {
				assert.Equal(t, true, addrGroups.Has(inGroupID))
			}
			if tt.outAddressGroupMatch {
				assert.Equal(t, true, addrGroups.Has(outGroupID))
			}

			npc.syncAddressGroup(inGroupID)
			npc.syncAddressGroup(outGroupID)
			updatedInAddrGroupObj, _, _ := npc.addressGroupStore.Get(inGroupID)
			updatedInAddrGroup := updatedInAddrGroupObj.(*antreatypes.AddressGroup)
			updatedOutAddrGroupObj, _, _ := npc.addressGroupStore.Get(outGroupID)
			updatedOutAddrGroup := updatedOutAddrGroupObj.(*antreatypes.AddressGroup)
			var member *controlplane.GroupMember
			if ee, ok := tt.addedExternalEntity.(*v1alpha2.ExternalEntity); ok {
				member = externalEntityToGroupMember(ee)
			}

			if tt.inAddressGroupMatch {
				assert.Equal(t, false, updatedInAddrGroup.GroupMembers.Has(member))
			}
			if tt.outAddressGroupMatch {
				assert.Equal(t, false, updatedOutAddrGroup.GroupMembers.Has(member))
			}
		})
	}
}

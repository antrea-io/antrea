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

package networkpolicy

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

func TestProcessGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	cidr := "10.0.0.0/24"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1alpha3.Group
		expectedGroup *antreatypes.Group
	}{
		{
			name: "g-with-ns-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				Selector: antreatypes.NewGroupSelector("nsA", nil, &selectorA, nil, nil),
			},
		},
		{
			name: "g-with-pod-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsB", Name: "gB", UID: "uidB"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidB",
				SourceReference: &controlplane.GroupReference{
					Name:      "gB",
					Namespace: "nsB",
					UID:       "uidB",
				},
				Selector: antreatypes.NewGroupSelector("nsB", &selectorB, nil, nil, nil),
			},
		},
		{
			name: "g-with-pod-ns-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsC", Name: "gC", UID: "uidC"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidC",
				SourceReference: &controlplane.GroupReference{
					Name:      "gC",
					Namespace: "nsC",
					UID:       "uidC",
				},
				Selector: antreatypes.NewGroupSelector("nsC", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "g-with-ip-block",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsD", Name: "gD", UID: "uidD"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidD",
				SourceReference: &controlplane.GroupReference{
					Name:      "gD",
					Namespace: "nsD",
					UID:       "uidD",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{},
					},
				},
				IPNets: []net.IPNet{*ipNet},
			},
		},
		{
			name: "g-with-svc-reference",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsE", Name: "gE", UID: "uidE"},
				Spec: crdv1alpha3.GroupSpec{
					ServiceReference: &crdv1alpha1.NamespacedName{
						Name:      "test-svc",
						Namespace: "nsE",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidE",
				SourceReference: &controlplane.GroupReference{
					Name:      "gE",
					Namespace: "nsE",
					UID:       "uidE",
				},
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "nsE",
				},
			},
		},
		{
			name: "g-with-child-groups",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsF", Name: "gF", UID: "uidF"},
				Spec: crdv1alpha3.GroupSpec{
					ChildGroups: []crdv1alpha3.ClusterGroupReference{"gA", "gB"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidF",
				SourceReference: &controlplane.GroupReference{
					Name:      "gF",
					Namespace: "nsF",
					UID:       "uidF",
				},
				ChildGroups: []string{"gA", "gB"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
			actualGroup := c.processGroup(tt.inputGroup)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestAddGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	cidr := "10.0.0.0/24"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1alpha3.Group
		expectedGroup *antreatypes.Group
	}{
		{
			name: "g-with-ns-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				Selector: antreatypes.NewGroupSelector("nsA", nil, &selectorA, nil, nil),
			},
		},
		{
			name: "g-with-pod-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsB", Name: "gB", UID: "uidB"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidB",
				SourceReference: &controlplane.GroupReference{
					Name:      "gB",
					Namespace: "nsB",
					UID:       "uidB",
				},
				Selector: antreatypes.NewGroupSelector("nsB", &selectorB, nil, nil, nil),
			},
		},
		{
			name: "g-with-pod-ns-selector",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsC", Name: "gC", UID: "uidC"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidC",
				SourceReference: &controlplane.GroupReference{
					Name:      "gC",
					Namespace: "nsC",
					UID:       "uidC",
				},
				Selector: antreatypes.NewGroupSelector("nsC", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "g-with-ip-block",
			inputGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsD", Name: "gD", UID: "uidD"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidD",
				SourceReference: &controlplane.GroupReference{
					Name:      "gD",
					Namespace: "nsD",
					UID:       "uidD",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{},
					},
				},
				IPNets: []net.IPNet{*ipNet},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
			npc.addGroup(tt.inputGroup)
			key := fmt.Sprintf("%s/%s", tt.inputGroup.Namespace, tt.inputGroup.Name)
			actualGroupObj, _, _ := npc.internalGroupStore.Get(key)
			actualGroup := actualGroupObj.(*antreatypes.Group)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestUpdateGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	testG := crdv1alpha3.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	cidr := "10.0.0.0/24"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		updatedGroup  *crdv1alpha3.Group
		expectedGroup *antreatypes.Group
	}{
		{
			name: "g-update-ns-selector",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				Selector: antreatypes.NewGroupSelector("nsA", nil, &selectorB, nil, nil),
			},
		},
		{
			name: "g-update-pod-selector",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				Selector: antreatypes.NewGroupSelector("nsA", &selectorC, nil, nil, nil),
			},
		},
		{
			name: "g-update-pod-ns-selector",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				Selector: antreatypes.NewGroupSelector("nsA", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "g-update-ip-block",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{},
					},
				},
				IPNets: []net.IPNet{*ipNet},
			},
		},
		{
			name: "g-update-svc-reference",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					ServiceReference: &crdv1alpha1.NamespacedName{
						Name:      "test-svc",
						Namespace: "nsA",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "nsA",
				},
			},
		},
		{
			name: "g-update-child-groups",
			updatedGroup: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					ChildGroups: []crdv1alpha3.ClusterGroupReference{"gB", "gC"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name:      "gA",
					Namespace: "nsA",
					UID:       "uidA",
				},
				ChildGroups: []string{"gB", "gC"},
			},
		},
	}
	_, npc := newController()
	npc.addGroup(&testG)
	key := fmt.Sprintf("%s/%s", testG.Namespace, testG.Name)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc.updateGroup(&testG, tt.updatedGroup)
			actualGroupObj, _, _ := npc.internalGroupStore.Get(key)
			actualGroup := actualGroupObj.(*antreatypes.Group)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestDeleteG(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	testG := crdv1alpha3.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	key := fmt.Sprintf("%s/%s", testG.Namespace, testG.Name)
	_, npc := newController()
	npc.addGroup(&testG)
	npc.deleteGroup(&testG)
	_, found, _ := npc.internalGroupStore.Get(key)
	assert.False(t, found, "expected internal Group to be deleted")
}

func TestGroupMembersComputedConditionEqual(t *testing.T) {
	tests := []struct {
		name          string
		existingConds []crdv1alpha3.GroupCondition
		checkStatus   corev1.ConditionStatus
		expValue      bool
	}{
		{
			name: "groupmem-cond-exists-not-equal",
			existingConds: []crdv1alpha3.GroupCondition{
				{
					Type:   crdv1alpha3.GroupMembersComputed,
					Status: corev1.ConditionFalse,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    false,
		},
		{
			name: "groupmem-cond-exists-equal",
			existingConds: []crdv1alpha3.GroupCondition{
				{
					Type:   crdv1alpha3.GroupMembersComputed,
					Status: corev1.ConditionTrue,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    true,
		},
		{
			name: "groupmem-cond-not-exists-not-equal",
			existingConds: []crdv1alpha3.GroupCondition{
				{
					Status: corev1.ConditionFalse,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inCond := crdv1alpha3.GroupCondition{
				Type:   crdv1alpha3.GroupMembersComputed,
				Status: tt.checkStatus,
			}
			actualValue := groupMembersComputedConditionEqual(tt.existingConds, inCond)
			assert.Equal(t, tt.expValue, actualValue)
		})
	}
}

func TestGetGroupSourceRef(t *testing.T) {
	tests := []struct {
		name        string
		group       *crdv1alpha3.Group
		expectedRef *controlplane.GroupReference
	}{
		{
			name: "cg-ref",
			group: &crdv1alpha3.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidA"},
			},
			expectedRef: &controlplane.GroupReference{
				Name:      "gA",
				Namespace: "nsA",
				UID:       "uidA",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualRef := getGroupSourceRef(tt.group)
			assert.Equal(t, tt.expectedRef, actualRef)
		})
	}
}

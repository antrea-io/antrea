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
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

func TestProcessClusterGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	cidr := "10.0.0.0/24"
	exceptCIDR := "10.0.0.0/25"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	controlplaneIPNetExcept, _ := cidrStrToIPNet(exceptCIDR)
	_, controlplaneIPNetDiff, _ := net.ParseCIDR("10.0.0.128/25")
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1beta1.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidB",
				SourceReference: &controlplane.GroupReference{
					Name: "cgB",
					UID:  "uidB",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidC",
				SourceReference: &controlplane.GroupReference{
					Name: "cgC",
					UID:  "uidC",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidD",
				SourceReference: &controlplane.GroupReference{
					Name: "cgD",
					UID:  "uidD",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *controlplaneIPNet,
					},
				},
				IPNets: []*net.IPNet{ipNet},
			},
		},
		{
			name: "cg-with-svc-reference",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgE", UID: "uidE"},
				Spec: crdv1beta1.GroupSpec{
					ServiceReference: &crdv1beta1.NamespacedName{
						Name:      "test-svc",
						Namespace: "test-ns",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidE",
				SourceReference: &controlplane.GroupReference{
					Name: "cgE",
					UID:  "uidE",
				},
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "test-ns",
				},
			},
		},
		{
			name: "cg-with-child-groups",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgF", UID: "uidF"},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA", "cgB"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidF",
				SourceReference: &controlplane.GroupReference{
					Name: "cgF",
					UID:  "uidF",
				},
				ChildGroups: []string{"cgA", "cgB"},
			},
		},
		{
			name: "cg-with-ip-block-except",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgG", UID: "uidG"},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{
							CIDR:   cidr,
							Except: []string{exceptCIDR},
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidG",
				SourceReference: &controlplane.GroupReference{
					Name: "cgG",
					UID:  "uidG",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{*controlplaneIPNetExcept},
					},
				},
				IPNets: []*net.IPNet{controlplaneIPNetDiff},
			},
		},
		{
			name: "cg-with-node-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgH", UID: "uidH"},
				Spec: crdv1beta1.GroupSpec{
					NodeSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidH",
				SourceReference: &controlplane.GroupReference{
					Name: "cgH",
					UID:  "uidH",
				},
				Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController(nil, nil)
			actualGroup := c.processClusterGroup(tt.inputGroup)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestAddClusterGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	cidr := "10.0.0.0/24"
	exceptCIDR1, exceptCIDR2 := "10.0.0.0/25", "10.0.0.128/26"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	controlplaneIPNetExcept1, _ := cidrStrToIPNet(exceptCIDR1)
	controlplaneIPNetExcept2, _ := cidrStrToIPNet(exceptCIDR2)
	_, controlplaneIPNetDiff, _ := net.ParseCIDR("10.0.0.192/26")
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1beta1.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidB",
				SourceReference: &controlplane.GroupReference{
					Name: "cgB",
					UID:  "uidB",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidC",
				SourceReference: &controlplane.GroupReference{
					Name: "cgC",
					UID:  "uidC",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidD",
				SourceReference: &controlplane.GroupReference{
					Name: "cgD",
					UID:  "uidD",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *controlplaneIPNet,
					},
				},
				IPNets: []*net.IPNet{ipNet},
			},
		},
		{
			name: "cg-with-ip-block-except",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgE", UID: "uidE"},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{
							CIDR:   cidr,
							Except: []string{exceptCIDR1, exceptCIDR2},
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidE",
				SourceReference: &controlplane.GroupReference{
					Name: "cgE",
					UID:  "uidE",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{*controlplaneIPNetExcept1, *controlplaneIPNetExcept2},
					},
				},
				IPNets: []*net.IPNet{controlplaneIPNetDiff},
			},
		},
		{
			name: "cg-with-node-selector",
			inputGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgF", UID: "uidF"},
				Spec: crdv1beta1.GroupSpec{
					NodeSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidF",
				SourceReference: &controlplane.GroupReference{
					Name: "cgF",
					UID:  "uidF",
				},
				Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			npc.addClusterGroup(tt.inputGroup)
			key := tt.inputGroup.Name
			actualGroupObj, _, _ := npc.internalGroupStore.Get(key)
			actualGroup := actualGroupObj.(*antreatypes.Group)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestUpdateClusterGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	testCG := crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1beta1.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	cidr := "10.0.0.0/24"
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
	_, ipNet, _ := net.ParseCIDR(cidr)
	tests := []struct {
		name          string
		updatedGroup  *crdv1beta1.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-update-ns-selector",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", nil, &selectorB, nil, nil),
			},
		},
		{
			name: "cg-update-pod-selector",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					PodSelector: &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorC, nil, nil, nil),
			},
		},
		{
			name: "cg-update-pod-ns-selector",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil, nil),
			},
		},
		{
			name: "cg-update-ip-block",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					IPBlocks: []crdv1beta1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR: *controlplaneIPNet,
					},
				},
				IPNets: []*net.IPNet{ipNet},
			},
		},
		{
			name: "cg-update-svc-reference",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					ServiceReference: &crdv1beta1.NamespacedName{
						Name:      "test-svc",
						Namespace: "test-ns",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "test-ns",
				},
			},
		},
		{
			name: "cg-update-child-groups",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					ChildGroups: []crdv1beta1.ClusterGroupReference{"cgB", "cgC"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				ChildGroups: []string{"cgB", "cgC"},
			},
		},
		{
			name: "cg-update-node-selector",
			updatedGroup: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1beta1.GroupSpec{
					NodeSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID: "uidA",
				SourceReference: &controlplane.GroupReference{
					Name: "cgA",
					UID:  "uidA",
				},
				Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &selectorA),
			},
		},
	}
	_, npc := newController(nil, nil)
	npc.addClusterGroup(&testCG)
	key := testCG.Name
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc.updateClusterGroup(&testCG, tt.updatedGroup)
			actualGroupObj, _, _ := npc.internalGroupStore.Get(key)
			actualGroup := actualGroupObj.(*antreatypes.Group)
			assert.Equal(t, tt.expectedGroup, actualGroup)
		})
	}
}

func TestDeleteCG(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	testCG := crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1beta1.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	key := testCG.Name
	_, npc := newController(nil, nil)
	npc.addClusterGroup(&testCG)
	npc.deleteClusterGroup(&testCG)
	_, found, _ := npc.internalGroupStore.Get(key)
	assert.False(t, found, "expected internal Group to be deleted")
}

func TestClusterClusterGroupMembersComputedConditionEqual(t *testing.T) {
	tests := []struct {
		name          string
		existingConds []crdv1beta1.GroupCondition
		checkStatus   corev1.ConditionStatus
		expValue      bool
	}{
		{
			name: "groupmem-cond-exists-not-equal",
			existingConds: []crdv1beta1.GroupCondition{
				{
					Type:   crdv1beta1.GroupMembersComputed,
					Status: corev1.ConditionFalse,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    false,
		},
		{
			name: "groupmem-cond-exists-equal",
			existingConds: []crdv1beta1.GroupCondition{
				{
					Type:   crdv1beta1.GroupMembersComputed,
					Status: corev1.ConditionTrue,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    true,
		},
		{
			name: "groupmem-cond-not-exists-not-equal",
			existingConds: []crdv1beta1.GroupCondition{
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
			inCond := crdv1beta1.GroupCondition{
				Type:   crdv1beta1.GroupMembersComputed,
				Status: tt.checkStatus,
			}
			actualValue := groupMembersComputedConditionEqual(tt.existingConds, inCond)
			assert.Equal(t, tt.expValue, actualValue)
		})
	}
}

func TestFilterInternalGroupsForService(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"purpose": "test-select"},
		},
	}
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc2",
			Namespace: "test",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"purpose": "test-select"},
		},
	}
	grp1 := &antreatypes.Group{
		UID: "uid1",
		SourceReference: &controlplane.GroupReference{
			Name: "cgA",
			UID:  "uid1",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
	}
	grp2 := &antreatypes.Group{
		UID: "uid2",
		SourceReference: &controlplane.GroupReference{
			Name: "cgB",
			UID:  "uid1",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
		Selector: antreatypes.NewGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID: "uid3",
		SourceReference: &controlplane.GroupReference{
			Name: "cgC",
			UID:  "uid3",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc2",
			Namespace: "test",
		},
		// Selector is out of sync with latest service spec, but the CG should still be returned.
		Selector: antreatypes.NewGroupSelector("test", nil, nil, nil, nil),
	}
	grp4 := &antreatypes.Group{
		UID: "uid4",
		SourceReference: &controlplane.GroupReference{
			Name: "cgD",
			UID:  "uid4",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name: "svc3",
		},
	}

	tests := []struct {
		name           string
		toMatch        *corev1.Service
		expectedGroups sets.Set[string]
	}{
		{
			"service-match-name-default-ns",
			svc1,
			sets.New[string]("cgA", "cgB"),
		},
		{
			"service-match-name-and-namespace",
			svc2,
			sets.New[string]("cgC"),
		},
	}
	_, npc := newController(nil, nil)
	npc.internalGroupStore.Create(grp1)
	npc.internalGroupStore.Create(grp2)
	npc.internalGroupStore.Create(grp3)
	npc.internalGroupStore.Create(grp4)
	npc.serviceStore.Add(svc1)
	npc.serviceStore.Add(svc2)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedGroups, npc.filterInternalGroupsForService(tt.toMatch),
				"Filtered internal Groups does not match expectation")
		})
	}
}

func TestServiceToGroupSelector(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"purpose": "test-select"},
		},
	}
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc2",
			Namespace: "test",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"purpose": "test-select"},
		},
	}
	svc3 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc3",
			Namespace: "test",
		},
		Spec: corev1.ServiceSpec{},
	}

	grp1 := &antreatypes.Group{
		UID: "uid1",
		SourceReference: &controlplane.GroupReference{
			Name: "cgA",
			UID:  "uid1",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
	}
	grp2 := &antreatypes.Group{
		UID: "uid2",
		SourceReference: &controlplane.GroupReference{
			Name: "cg2",
			UID:  "uidB",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc2",
			Namespace: "test",
		},
	}
	grp3 := &antreatypes.Group{
		UID: "uid3",
		SourceReference: &controlplane.GroupReference{
			Name: "cgC",
			UID:  "uid3",
		},
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc3",
			Namespace: "test",
		},
	}
	tests := []struct {
		name                  string
		toProcess             *corev1.Service
		group                 *antreatypes.Group
		expectedGroupSelector *antreatypes.GroupSelector
	}{
		{
			"service-default-ns",
			svc1,
			grp1,
			antreatypes.NewGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil, nil),
		},
		{
			"service-match-name-and-namespace",
			svc2,
			grp2,
			antreatypes.NewGroupSelector("test", &selectorSpec, nil, nil, nil),
		},
		{
			"service-without-selectors",
			svc3,
			grp3,
			nil,
		},
	}
	_, npc := newController(nil, nil)
	npc.serviceStore.Add(svc1)
	npc.serviceStore.Add(svc2)
	npc.serviceStore.Add(svc3)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := npc.serviceToGroupSelector(tt.toProcess)
			assert.Equal(t, getNormalizedNameForSelector(tt.expectedGroupSelector), getNormalizedNameForSelector(sel),
				"Processed group selector does not match expectation")
		})
	}
}

// Pods for testing proper query results
var testPods = []*corev1.Pod{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "test-ns",
			UID:       "uid1",
			Labels:    map[string]string{"app": "foo"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIPs: []corev1.PodIP{{IP: "10.10.1.1"}},
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "test-ns",
			UID:       "uid2",
			Labels:    map[string]string{"app": "bar"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
			PodIPs: []corev1.PodIP{{IP: "10.10.1.2"}},
		},
	},
}

var externalEntities = []*crdv1alpha2.ExternalEntity{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee1",
			Namespace: "test-ns",
			UID:       "uid3",
			Labels:    map[string]string{"app": "meh"},
		},
		Spec: crdv1alpha2.ExternalEntitySpec{
			Endpoints: []crdv1alpha2.Endpoint{
				{
					IP:   "60.10.0.1",
					Name: "vm1",
				},
			},
			ExternalNode: "nodeA",
		},
	},
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee2",
			Namespace: "test-ns",
			UID:       "uid4",
			Labels:    map[string]string{"app": "bruh"},
		},
		Spec: crdv1alpha2.ExternalEntitySpec{
			Endpoints: []crdv1alpha2.Endpoint{
				{
					IP:   "60.10.0.2",
					Name: "vm2",
				},
			},
			ExternalNode: "nodeA",
		},
	},
}

var groups = []antreatypes.Group{
	{
		UID: "groupUID0",
		SourceReference: &controlplane.GroupReference{
			Name: "group0",
			UID:  "groupUID0",
		},
		Selector: antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
	},
	{
		UID: "groupUID1",
		SourceReference: &controlplane.GroupReference{
			Name: "group1",
			UID:  "groupUID1",
		},
		Selector: antreatypes.NewGroupSelector("test-ns", nil, nil, nil, nil),
	},
	{
		UID: "groupUID2",
		SourceReference: &controlplane.GroupReference{
			Name: "group2",
			UID:  "groupUID2",
		},
		Selector: antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}, nil, nil, nil),
	},
	{
		UID: "groupUID3",
		SourceReference: &controlplane.GroupReference{
			Name: "group3",
			UID:  "groupUID3",
		},
		ChildGroups: []string{"group0", "group1"},
	},
	{
		UID: "groupUID4",
		SourceReference: &controlplane.GroupReference{
			Name: "group4",
			UID:  "groupUID4",
		},
		ChildGroups: []string{"group0", "group2"},
	},
	{
		UID: "groupUID5",
		SourceReference: &controlplane.GroupReference{
			Name: "group5",
			UID:  "groupUID5",
		},
		ChildGroups: []string{"group1", "group2"},
	},
	{
		UID: "groupUID6",
		SourceReference: &controlplane.GroupReference{
			Name: "group6",
			UID:  "groupUID6",
		},
		Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"node": "a"}}),
	},
	{
		UID: "groupUID7",
		SourceReference: &controlplane.GroupReference{
			Name: "group7",
			UID:  "groupUID7",
		},
		Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"alt": "alt"}}),
	},
	{
		UID: "groupUID8",
		SourceReference: &controlplane.GroupReference{
			Name: "group8",
			UID:  "groupUID8",
		},
		Selector: antreatypes.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"node": "b"}}),
	},
}

func TestGetAssociatedGroups(t *testing.T) {
	nodeA := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"node": "a"},
		},
	}
	tests := []struct {
		name           string
		existingGroups []antreatypes.Group
		queryName      string
		queryNamespace string
		expectedGroups []antreatypes.Group
	}{
		{
			"multiple-group-association",
			groups,
			"pod1",
			"test-ns",
			[]antreatypes.Group{groups[0], groups[1], groups[3], groups[4], groups[5]},
		},
		{
			"single-group-association",
			groups,
			"pod2",
			"test-ns",
			[]antreatypes.Group{groups[1], groups[3], groups[5]},
		},
		{
			"no-group-association",
			groups,
			"ee2",
			"test-ns",
			[]antreatypes.Group{},
		},
		{
			"group-with-node-selector",
			groups,
			"nodeA",
			"",
			[]antreatypes.Group{groups[6]},
		},
	}
	_, npc := newController([]runtime.Object{nodeA}, nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.informerFactory.Start(stopCh)
	npc.informerFactory.WaitForCacheSync(stopCh)
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	for j := range externalEntities {
		npc.groupingInterface.AddExternalEntity(externalEntities[j])
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createGroups(npc, tt.existingGroups)
			groups := npc.GetAssociatedGroups(tt.queryName, tt.queryNamespace)
			assert.ElementsMatch(t, tt.expectedGroups, groups)
		})
	}
}

func TestGetGroupsForNode(t *testing.T) {
	nodeA := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"node": "a"},
		},
	}
	nodeB := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeB",
			Labels: map[string]string{"node": "b", "alt": "alt"},
		},
	}
	nodeC := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeC",
			Labels: map[string]string{"node": "c"},
		},
	}
	tests := []struct {
		name           string
		exists         bool
		queryName      string
		expectedGroups []string
	}{
		{
			"single-group-match",
			true,
			"nodeA",
			[]string{groups[6].SourceReference.Name},
		},
		{
			"multiple-group-match",
			true,
			"nodeB",
			[]string{groups[7].SourceReference.Name, groups[8].SourceReference.Name},
		},
		{
			"node cannot be found",
			false,
			"any",
			[]string{},
		},
		{
			"no groups exist",
			false,
			"nodeB",
			[]string{},
		},
		{
			"no applicable groups exist",
			false,
			"nodeC",
			[]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var npc *networkPolicyController
			_, npc = newController([]runtime.Object{nodeA, nodeB, nodeC}, nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			npc.informerFactory.Start(stopCh)
			npc.informerFactory.WaitForCacheSync(stopCh)
			if tt.name != "no groups exist" {
				createGroups(npc, groups)
			}

			groups, exists := npc.getGroupsForNode(tt.queryName)
			if tt.exists {
				assert.True(t, exists)
				assert.ElementsMatch(t, tt.expectedGroups, groups[internalGroupType])
			} else {
				assert.False(t, exists)
			}
		})
	}
}

// Create the given groups onto the controller
func createGroups(npc *networkPolicyController, groups []antreatypes.Group) {
	for _, g := range groups {
		npc.internalGroupStore.Create(&g)
		if g.Selector != nil {
			npc.groupingInterface.AddGroup(internalGroupType, g.SourceReference.Name, g.Selector)
		}
	}
}

func TestGetClusterGroupMembers(t *testing.T) {
	pod1MemberSet := controlplane.GroupMemberSet{}
	pod1MemberSet.Insert(podToGroupMember(testPods[0], true))
	pod12MemberSet := controlplane.GroupMemberSet{}
	pod12MemberSet.Insert(podToGroupMember(testPods[0], true))
	pod12MemberSet.Insert(podToGroupMember(testPods[1], true))
	tests := []struct {
		name            string
		group           antreatypes.Group
		expectedMembers controlplane.GroupMemberSet
	}{
		{
			"multiple-members",
			groups[1],
			pod12MemberSet,
		},
		{
			"single-member",
			groups[0],
			pod1MemberSet,
		},
		{
			"no-member",
			groups[2],
			controlplane.GroupMemberSet{},
		},
	}
	_, npc := newController(nil, nil)
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	for j := range externalEntities {
		npc.groupingInterface.AddExternalEntity(externalEntities[j])
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc.internalGroupStore.Create(&tt.group)
			npc.groupingInterface.AddGroup(internalGroupType, tt.group.SourceReference.Name, tt.group.Selector)
			members, _, err := npc.GetGroupMembers(tt.group.SourceReference.Name)
			assert.Equal(t, nil, err)
			assert.Equal(t, tt.expectedMembers, members)
		})
	}
}

// TestGetClusterGroupMembersNestingExceeded verifies that querying the members of a Group that is
// not realized because of its nesting level says so, instead of returning the empty member list
// that getInternalGroupMembers computes for it, which a user cannot tell apart from a Group that
// legitimately selects nothing. It has to be a BadRequest, since GetPaginatedMembers turns any
// other error into a 500 and this is a user error.
func TestGetClusterGroupMembersNestingExceeded(t *testing.T) {
	overNested := antreatypes.Group{
		UID:                        "uidOverNested",
		SourceReference:            &controlplane.GroupReference{Name: "cgOverNested", UID: "uidOverNested"},
		ChildGroups:                []string{"cgChild"},
		ChildGroupsNestingExceeded: true,
	}
	_, npc := newController(nil, nil)
	npc.internalGroupStore.Create(&overNested)

	members, ipBlocks, err := npc.GetGroupMembers("cgOverNested")
	assert.Nil(t, members)
	assert.Nil(t, ipBlocks)
	require.Error(t, err)
	assert.True(t, apierrors.IsBadRequest(err), "expected a BadRequest, got %v", err)
}

func TestSyncInternalGroup(t *testing.T) {
	p10 := float64(10)
	p20 := float64(20)
	allowAction := crdv1beta1.RuleActionAllow
	cgName := "cgA"
	cgUID := types.UID("uidA")
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName, UID: cgUID},
		Spec:       crdv1beta1.GroupSpec{NamespaceSelector: &selectorA},
	}
	cnp1 := &crdv1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp1", UID: "uid1"},
		Spec: crdv1beta1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1beta1.AppliedTo{
				{PodSelector: &selectorB},
			},
			Priority: p10,
			Ingress: []crdv1beta1.Rule{
				{
					From: []crdv1beta1.NetworkPolicyPeer{
						{Group: cgName},
					},
					Action: &allowAction,
				},
			},
		},
	}
	cnp2 := &crdv1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp2", UID: "uid2"},
		Spec: crdv1beta1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1beta1.AppliedTo{
				{PodSelector: &selectorC},
			},
			Priority: p20,
			Ingress: []crdv1beta1.Rule{
				{
					From: []crdv1beta1.NetworkPolicyPeer{
						{Group: cgName},
					},
					Action: &allowAction,
				},
			},
		},
	}

	_, npc := newControllerWithoutEventHandler(nil, []runtime.Object{cnp1, cnp2, cg})
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.crdInformerFactory.Start(stopCh)
	npc.crdInformerFactory.WaitForCacheSync(stopCh)

	// cnp1 is synced before the ClusterGroup. The rule's From should be empty as the ClusterGroup hasn't been synced,
	require.NoError(t, npc.syncInternalNetworkPolicy(getACNPReference(cnp1)))
	assert.Equal(t, 0, npc.internalNetworkPolicyQueue.Len())
	expectedInternalNetworkPolicy1 := &antreatypes.NetworkPolicy{
		UID:      "uid1",
		Name:     "uid1",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: "cnp1",
			UID:  "uid1",
		},
		Priority:     &p10,
		TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				Priority:  0,
				Action:    &allowAction,
			},
		},
		AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil, nil).NormalizedName)},
	}
	actualInternalNetworkPolicy1, exists, _ := npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp1))
	require.True(t, exists)
	require.Equal(t, expectedInternalNetworkPolicy1, actualInternalNetworkPolicy1)

	// After creating a ClusterGroup:
	// - A corresponding internal group should be added for it.
	// - The internal NetworkPolicies for the ClusterNetworkPolicies that use it should be enqueued.
	// - An AddressGroup should be created for it.
	npc.addClusterGroup(cg)
	err := npc.syncInternalGroup(internalGroupKeyFunc(cg))
	require.NoError(t, err)
	require.Equal(t, 2, npc.internalNetworkPolicyQueue.Len())
	expectedKeys := []controlplane.NetworkPolicyReference{
		*getACNPReference(cnp1),
		*getACNPReference(cnp2),
	}
	actualKeys := make([]controlplane.NetworkPolicyReference, 0, 2)
	for i := 0; i < 2; i++ {
		key, _ := npc.internalNetworkPolicyQueue.Get()
		actualKeys = append(actualKeys, key)
		npc.internalNetworkPolicyQueue.Done(key)
	}
	assert.ElementsMatch(t, expectedKeys, actualKeys)

	expectedInternalNetworkPolicy1.Rules[0].From = controlplane.NetworkPolicyPeer{AddressGroups: []string{cgName}}
	require.NoError(t, npc.syncInternalNetworkPolicy(getACNPReference(cnp1)))
	actualInternalNetworkPolicy1, exists, _ = npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp1))
	require.True(t, exists)
	require.Equal(t, expectedInternalNetworkPolicy1, actualInternalNetworkPolicy1)

	// cnp2 is synced after the ClusterGroup.
	expectedInternalNetworkPolicy2 := &antreatypes.NetworkPolicy{
		UID:      "uid2",
		Name:     "uid2",
		SpanMeta: antreatypes.SpanMeta{NodeNames: sets.New[string]()},
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: "cnp2",
			UID:  "uid2",
		},
		Priority:     &p20,
		TierPriority: ptr.To(crdv1beta1.DefaultTierPriority),
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{cgName}},
				Priority:  0,
				Action:    &allowAction,
			},
		},
		AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, nil, nil, nil).NormalizedName)},
	}
	require.NoError(t, npc.syncInternalNetworkPolicy(getACNPReference(cnp2)))
	actualInternalNetworkPolicy2, exists, _ := npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp2))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy2, actualInternalNetworkPolicy2)

	expectedInternalGroup := &antreatypes.Group{
		UID: cgUID,
		SourceReference: &controlplane.GroupReference{
			Name: cgName,
			UID:  cgUID,
		},
		Selector:        antreatypes.NewGroupSelector("", nil, &selectorA, nil, nil),
		MembersComputed: corev1.ConditionTrue,
	}
	actualInternalGroup, exists, _ := npc.internalGroupStore.Get(internalGroupKeyFunc(cg))
	require.True(t, exists)
	assert.Equal(t, expectedInternalGroup, actualInternalGroup)
	_, exists, _ = npc.addressGroupStore.Get(cgName)
	require.True(t, exists, "An AddressGroup should be created for the ClusterGroup when it's referenced by any ClusterNetworkPolicy")

	// After deleting the ClusterGroup:
	// - Its corresponding internal group should be removed.
	// - The internal NetworkPolicies for the ClusterNetworkPolicies that use it should be updated.
	// - The AddressGroup created for it should be deleted.
	npc.deleteClusterGroup(cg)
	err = npc.syncInternalGroup(internalGroupKeyFunc(cg))
	require.NoError(t, err)

	require.Equal(t, 2, npc.internalNetworkPolicyQueue.Len())
	_, exists, _ = npc.internalGroupStore.Get(internalGroupKeyFunc(cg))
	require.False(t, exists)

	require.NoError(t, npc.syncInternalNetworkPolicy(getACNPReference(cnp1)))
	expectedInternalNetworkPolicy1.Rules[0].From.AddressGroups = nil
	actualInternalNetworkPolicy1, exists, _ = npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp1))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy1, actualInternalNetworkPolicy1)

	require.NoError(t, npc.syncInternalNetworkPolicy(getACNPReference(cnp2)))
	expectedInternalNetworkPolicy2.Rules[0].From.AddressGroups = nil
	actualInternalNetworkPolicy2, exists, _ = npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp2))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy2, actualInternalNetworkPolicy2)

	_, exists, _ = npc.addressGroupStore.Get(cgName)
	require.False(t, exists, "The AddressGroup for the ClusterGroup should be deleted when it's no longer referenced by any ClusterNetworkPolicy")
}

func TestGetClusterGroupSourceRef(t *testing.T) {
	tests := []struct {
		name        string
		group       *crdv1beta1.ClusterGroup
		expectedRef *controlplane.GroupReference
	}{
		{
			name: "cg-ref",
			group: &crdv1beta1.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
			},
			expectedRef: &controlplane.GroupReference{
				Name:      "cgA",
				Namespace: "",
				UID:       "uidA",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualRef := getClusterGroupSourceRef(tt.group)
			assert.Equal(t, tt.expectedRef, actualRef)
		})
	}
}

func TestGetAssociatedIPBlockGroups(t *testing.T) {
	cg1 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "ipBlockGrp1", UID: "UID1"},
		Spec: crdv1beta1.GroupSpec{
			IPBlocks: []crdv1beta1.IPBlock{
				{CIDR: "172.60.0.0/16"},
			},
		},
	}
	cg2 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "ipBlockGrp2", UID: "UID2"},
		Spec: crdv1beta1.GroupSpec{
			IPBlocks: []crdv1beta1.IPBlock{
				{CIDR: "172.60.2.0/24"},
			},
		},
	}
	cg2Parent := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "ipBlockParentGrp", UID: "UID3"},
		Spec: crdv1beta1.GroupSpec{
			ChildGroups: []crdv1beta1.ClusterGroupReference{
				"ipBlockGrp2",
			},
		},
	}
	cgExceptIPv4 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "ipBlockExceptV4", UID: "UID4"},
		Spec: crdv1beta1.GroupSpec{
			IPBlocks: []crdv1beta1.IPBlock{
				{
					CIDR: "192.168.0.0/16",
					Except: []string{
						"192.168.3.0/24", "192.168.4.0/24",
					},
				},
			},
		},
	}
	cgExceptIPv6 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "ipBlockExceptV6", UID: "UID5"},
		Spec: crdv1beta1.GroupSpec{
			IPBlocks: []crdv1beta1.IPBlock{
				{
					CIDR:   "fd00:192:168::/48",
					Except: []string{"fd00:192:168:3::/64", "fd00:192:168:4::/64"},
				},
			},
		},
	}

	_, npc := newControllerWithoutEventHandler(nil, []runtime.Object{cg1, cg2, cg2Parent, cgExceptIPv4, cgExceptIPv6})
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.crdInformerFactory.Start(stopCh)
	npc.crdInformerFactory.WaitForCacheSync(stopCh)

	for _, cg := range []*crdv1beta1.ClusterGroup{cg1, cg2, cg2Parent, cgExceptIPv4, cgExceptIPv6} {
		npc.addClusterGroup(cg)
		npc.syncInternalGroup(internalGroupKeyFunc(cg))
	}

	tests := []struct {
		name           string
		ipQuery        net.IP
		expectedGroups []string
	}{
		{
			name:           "single-group-association",
			ipQuery:        net.ParseIP("172.60.1.1"),
			expectedGroups: []string{"ipBlockGrp1"},
		},
		{
			name:           "multiple-group-association",
			ipQuery:        net.ParseIP("172.60.2.1"),
			expectedGroups: []string{"ipBlockGrp1", "ipBlockGrp2", "ipBlockParentGrp"},
		},
		{
			name:           "no-group-association",
			ipQuery:        net.ParseIP("172.160.0.1"),
			expectedGroups: []string{},
		},
		{
			name:           "group-association-ipv4-group-except",
			ipQuery:        net.ParseIP("192.168.8.1"),
			expectedGroups: []string{"ipBlockExceptV4"},
		},
		{
			name:           "no-group-association-ipv4-group-except",
			ipQuery:        net.ParseIP("192.168.3.1"),
			expectedGroups: []string{},
		},
		{
			name:           "group-association-ipv6-group-except",
			ipQuery:        net.ParseIP("fd00:192:168:0::1"),
			expectedGroups: []string{"ipBlockExceptV6"},
		},
		{
			name:           "no-group-association-ipv6-group-except",
			ipQuery:        net.ParseIP("fd00:192:168:3:abcd:1234:5678:9abc:def0"),
			expectedGroups: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := npc.GetAssociatedIPBlockGroups(tt.ipQuery)
			var groupNames []string
			for _, g := range groups {
				groupNames = append(groupNames, g.SourceReference.ToGroupName())
			}
			assert.ElementsMatch(t, groupNames, tt.expectedGroups)
		})
	}
}

// TestChildGroupsNestingExceeded verifies which Groups are reported as nested too deeply.
// Antrea supports a single level of nesting: a Group with childGroups, whose children must be
// leaves. A Group that reaches a third level is not realized, whether it does so through a
// ChildGroups cycle or not.
func TestChildGroupsNestingExceeded(t *testing.T) {
	groups := []*antreatypes.Group{
		{
			SourceReference: &controlplane.GroupReference{Name: "cgLeaf", UID: "uidLeaf"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgParent", UID: "uidParent"},
			ChildGroups:     []string{"cgLeaf"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgDuplicate", UID: "uidDuplicate"},
			ChildGroups:     []string{"cgLeaf", "cgLeaf"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgGrandParent", UID: "uidGrandParent"},
			ChildGroups:     []string{"cgParent"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgMissingChild", UID: "uidMissingChild"},
			ChildGroups:     []string{"cgDoesNotExist"},
		},
		// cgMissingGrandChild's child exists and declares a childGroup of its own, which does
		// not exist yet. The hierarchy is already invalid, and reporting it now means the
		// answer does not change when cgDoesNotExist is created.
		{
			SourceReference: &controlplane.GroupReference{Name: "cgDeclaresMissingChild", UID: "uidDeclaresMissingChild"},
			ChildGroups:     []string{"cgDoesNotExist"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgMissingGrandChild", UID: "uidMissingGrandChild"},
			ChildGroups:     []string{"cgDeclaresMissingChild"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgCycle1", UID: "uidCycle1"},
			ChildGroups:     []string{"cgCycle2"},
		},
		{
			SourceReference: &controlplane.GroupReference{Name: "cgCycle2", UID: "uidCycle2"},
			ChildGroups:     []string{"cgCycle1"},
		},
		// cgOutside is not itself part of the cgCycle1/cgCycle2 cycle, but it reaches it, which
		// makes it exceed the nesting level too.
		{
			SourceReference: &controlplane.GroupReference{Name: "cgOutside", UID: "uidOutside"},
			ChildGroups:     []string{"cgCycle1"},
		},
		// A Namespaced Group whose childGroups are resolved within its own Namespace.
		{
			SourceReference: &controlplane.GroupReference{Namespace: "nsA", Name: "gSelfLoop", UID: "uidGSelfLoop"},
			ChildGroups:     []string{"gSelfLoop"},
		},
	}
	_, npc := newController(nil, nil)
	for _, grp := range groups {
		npc.internalGroupStore.Create(grp)
	}

	tests := []struct {
		groupName string
		expected  bool
	}{
		{groupName: "cgLeaf", expected: false},
		{groupName: "cgParent", expected: false},
		// A childGroup listed twice is legitimate, and adds no nesting level.
		{groupName: "cgDuplicate", expected: false},
		{groupName: "cgGrandParent", expected: true},
		{groupName: "cgMissingChild", expected: false},
		{groupName: "cgMissingGrandChild", expected: true},
		{groupName: "cgCycle1", expected: true},
		{groupName: "cgCycle2", expected: true},
		{groupName: "cgOutside", expected: true},
		{groupName: "nsA/gSelfLoop", expected: true},
	}
	for _, tt := range tests {
		t.Run(tt.groupName, func(t *testing.T) {
			obj, found, _ := npc.internalGroupStore.Get(tt.groupName)
			require.True(t, found)
			assert.Equal(t, tt.expected, npc.childGroupsNestingExceeded(obj.(*antreatypes.Group)))
		})
	}
}

// TestChildGroupsCycleTerminates verifies that a ChildGroups cycle in the internalGroupStore
// does not cause unbounded recursion. Before the nesting level was enforced in the traversals,
// processing such a cycle recursed forever and crashed antrea-controller with an unrecoverable
// "fatal error: stack overflow" (which no recover() can catch, so this test asserts on the
// returned values: reaching them at all proves termination).
//
// The traversals are called on Groups whose ChildGroupsNestingExceeded is false, which is what
// an ADD/UPDATE event leaves behind until the Group is synced again: termination must not
// depend on that flag.
//
// The self-loop is the case that admission validation used to let through deterministically,
// with no race: on CREATE the object is not in the informer cache yet, and on UPDATE the cache
// still holds the previous version, so neither nesting check saw the self reference.
func TestChildGroupsCycleTerminates(t *testing.T) {
	tests := []struct {
		name   string
		groups []*antreatypes.Group
	}{
		{
			name: "self loop",
			groups: []*antreatypes.Group{
				{
					UID:             "uidA",
					SourceReference: &controlplane.GroupReference{Name: "cgA", UID: "uidA"},
					ChildGroups:     []string{"cgA"},
				},
			},
		},
		{
			name: "mutual cycle",
			groups: []*antreatypes.Group{
				{
					UID:             "uidA",
					SourceReference: &controlplane.GroupReference{Name: "cgA", UID: "uidA"},
					ChildGroups:     []string{"cgB"},
				},
				{
					UID:             "uidB",
					SourceReference: &controlplane.GroupReference{Name: "cgB", UID: "uidB"},
					ChildGroups:     []string{"cgA"},
				},
			},
		},
		{
			name: "cycle of three",
			groups: []*antreatypes.Group{
				{
					UID:             "uidA",
					SourceReference: &controlplane.GroupReference{Name: "cgA", UID: "uidA"},
					ChildGroups:     []string{"cgB"},
				},
				{
					UID:             "uidB",
					SourceReference: &controlplane.GroupReference{Name: "cgB", UID: "uidB"},
					ChildGroups:     []string{"cgC"},
				},
				{
					UID:             "uidC",
					SourceReference: &controlplane.GroupReference{Name: "cgC", UID: "uidC"},
					ChildGroups:     []string{"cgA"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController(nil, nil)
			for _, grp := range tt.groups {
				npc.internalGroupStore.Create(grp)
			}
			cgA := tt.groups[0]

			// No Group in the cycle contributes selectors or ipBlocks, so the cycle resolves
			// to no AddressGroup and no ipBlocks, same as the existing "childGroup not found"
			// path.
			createAddrGroup, ipBlocks := npc.processInternalGroupForRule(cgA)
			assert.False(t, createAddrGroup)
			assert.Empty(t, ipBlocks)

			members, ipBlocks := npc.getInternalGroupMembers(cgA)
			assert.Empty(t, members)
			assert.Empty(t, ipBlocks)

			// Every Group in the cycle must be detected, so that none of them re-enqueues the
			// next one and spins the internalGroup workers.
			for _, grp := range tt.groups {
				assert.True(t, npc.childGroupsNestingExceeded(grp), "expected %s to be reported as nested too deeply", grp.SourceReference.ToGroupName())
			}
		})
	}
}

// TestOverNestedGroupNotRealized verifies that a Group nested deeper than the supported level
// contributes nothing to the policies that select it, instead of being realized with whatever
// part of the hierarchy fits within the level. Both a Group that has already been synced
// (ChildGroupsNestingExceeded set) and one that has not (flag still false) are covered.
//
// An empty result is not a fail-open: a rule whose only peer resolves to no member and no
// ipBlock is never satisfied at the OpenFlow layer, so an Allow rule grants nothing and a
// Drop/Reject rule blocks nothing. See the comment on processInternalGroupForRule.
func TestOverNestedGroupNotRealized(t *testing.T) {
	ipBlock := controlplane.IPBlock{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.ParseIP("10.0.0.0")), PrefixLength: 24}}
	leafPods := antreatypes.Group{
		UID:             "uidLeafPods",
		SourceReference: &controlplane.GroupReference{Name: "cgLeafPods", UID: "uidLeafPods"},
		Selector:        antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
	}
	leafIPBlock := antreatypes.Group{
		UID:             "uidLeafIPBlock",
		SourceReference: &controlplane.GroupReference{Name: "cgLeafIPBlock", UID: "uidLeafIPBlock"},
		IPBlocks:        []controlplane.IPBlock{ipBlock},
	}
	parent := antreatypes.Group{
		UID:             "uidParent",
		SourceReference: &controlplane.GroupReference{Name: "cgParent", UID: "uidParent"},
		ChildGroups:     []string{"cgLeafPods", "cgLeafIPBlock"},
	}
	// grandParent is one level too deep, and has not been synced since it was last updated.
	grandParent := antreatypes.Group{
		UID:             "uidGrandParent",
		SourceReference: &controlplane.GroupReference{Name: "cgGrandParent", UID: "uidGrandParent"},
		ChildGroups:     []string{"cgParent"},
	}
	// syncedGrandParent is the same hierarchy, as it looks after being synced.
	syncedGrandParent := antreatypes.Group{
		UID:                        "uidSyncedGrandParent",
		SourceReference:            &controlplane.GroupReference{Name: "cgSyncedGrandParent", UID: "uidSyncedGrandParent"},
		ChildGroups:                []string{"cgParent"},
		ChildGroupsNestingExceeded: true,
	}

	_, npc := newController(nil, nil)
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	createGroups(npc, []antreatypes.Group{leafPods, leafIPBlock, parent, grandParent, syncedGrandParent})

	tests := []struct {
		name  string
		group antreatypes.Group
	}{
		{"not synced yet", grandParent},
		{"synced", syncedGrandParent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createAddrGroup, ipBlocks := npc.processInternalGroupForRule(&tt.group)
			assert.False(t, createAddrGroup)
			assert.Empty(t, ipBlocks)

			members, ipBlocks := npc.getInternalGroupMembers(&tt.group)
			assert.Empty(t, members)
			assert.Empty(t, ipBlocks)
		})
	}

	// The parent is a valid hierarchy on its own, and is realized as before.
	t.Run("supported nesting level", func(t *testing.T) {
		expectedMembers := controlplane.GroupMemberSet{}
		expectedMembers.Insert(podToGroupMember(testPods[0], true))

		createAddrGroup, ipBlocks := npc.processInternalGroupForRule(&parent)
		assert.True(t, createAddrGroup)
		assert.Equal(t, []controlplane.IPBlock{ipBlock}, ipBlocks)

		members, ipBlocks := npc.getInternalGroupMembers(&parent)
		assert.Equal(t, expectedMembers, members)
		assert.Equal(t, []controlplane.IPBlock{ipBlock}, ipBlocks)
	})
}

// TestChildGroupsDuplicateChildMembersPreserved verifies that enforcing the nesting level in
// the ChildGroups traversals does not drop the members or ipBlocks of a childGroup that is
// legitimately listed more than once.
func TestChildGroupsDuplicateChildMembersPreserved(t *testing.T) {
	ipBlock := controlplane.IPBlock{CIDR: controlplane.IPNet{IP: controlplane.IPAddress(net.ParseIP("10.0.0.0")), PrefixLength: 24}}
	// Leaf selecting testPods[0] via its "app: foo" label.
	leafPods := antreatypes.Group{
		UID:             "uidLeafPods",
		SourceReference: &controlplane.GroupReference{Name: "cgLeafPods", UID: "uidLeafPods"},
		Selector:        antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
	}
	leafIPBlock := antreatypes.Group{
		UID:             "uidLeafIPBlock",
		SourceReference: &controlplane.GroupReference{Name: "cgLeafIPBlock", UID: "uidLeafIPBlock"},
		IPBlocks:        []controlplane.IPBlock{ipBlock},
	}
	// Lists both leaves twice, so each is reached twice from the same parent.
	duplicateChild := antreatypes.Group{
		UID:             "uidDuplicate",
		SourceReference: &controlplane.GroupReference{Name: "cgDuplicate", UID: "uidDuplicate"},
		ChildGroups:     []string{"cgLeafPods", "cgLeafIPBlock", "cgLeafPods", "cgLeafIPBlock"},
	}

	_, npc := newController(nil, nil)
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	createGroups(npc, []antreatypes.Group{leafPods, leafIPBlock, duplicateChild})

	expectedMembers := controlplane.GroupMemberSet{}
	expectedMembers.Insert(podToGroupMember(testPods[0], true))

	// An AddressGroup is still required for the selector-based leaf, and the ipBlock is
	// reported once per reference, as it was before.
	createAddrGroup, ipBlocks := npc.processInternalGroupForRule(&duplicateChild)
	assert.True(t, createAddrGroup)
	assert.Equal(t, []controlplane.IPBlock{ipBlock, ipBlock}, ipBlocks)

	members, ipBlocks := npc.getInternalGroupMembers(&duplicateChild)
	assert.Equal(t, expectedMembers, members)
	assert.Equal(t, []controlplane.IPBlock{ipBlock, ipBlock}, ipBlocks)
}

// TestTriggerParentGroupUpdatesNestingExceeded pins the gate that decides whether a parent is
// enqueued: only a pair in which both the Group being synced and the parent are already known to
// be nested too deeply is skipped.
//
// Skipping that pair is what avoids the CPU spin. Every member of a ChildGroups cycle is also one
// of its own ancestors, and every member of a cycle is flagged (its cycle successor has
// childGroups), so without it the internalGroup workqueue would re-enqueue the cycle on every
// sync and spin the workers at 100% CPU for as long as the cycle exists.
//
// The other three combinations must all enqueue:
//   - an unflagged parent has to be enqueued so that it gets a chance to detect the excessive
//     nesting itself, whatever order the Groups were created in (see
//     TestSyncInternalGroupCycleConverges);
//   - an unflagged child has to enqueue even a flagged parent, because a child losing its own
//     childGroups is exactly the event that lets that parent stop being over-nested (see
//     TestSyncInternalGroupNestingRecovers). Gating on the parent alone would leave the parent
//     unrealized for good.
func TestTriggerParentGroupUpdatesNestingExceeded(t *testing.T) {
	tests := []struct {
		name                  string
		childNestingExceeded  bool
		parentNestingExceeded bool
		expectedEnqueue       int
	}{
		{name: "both over-nested, parent is not enqueued", childNestingExceeded: true, parentNestingExceeded: true, expectedEnqueue: 0},
		{name: "over-nested parent, child within the level", childNestingExceeded: false, parentNestingExceeded: true, expectedEnqueue: 1},
		{name: "over-nested child, parent within the level", childNestingExceeded: true, parentNestingExceeded: false, expectedEnqueue: 1},
		{name: "neither over-nested", childNestingExceeded: false, parentNestingExceeded: false, expectedEnqueue: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cgChild := &antreatypes.Group{
				UID:                        "uidChild",
				SourceReference:            &controlplane.GroupReference{Name: "cgChild", UID: "uidChild"},
				ChildGroupsNestingExceeded: tt.childNestingExceeded,
			}
			// cgParent is the parent of cgChild, and is flagged as over-nested or not.
			cgParent := &antreatypes.Group{
				UID:                        "uidParent",
				SourceReference:            &controlplane.GroupReference{Name: "cgParent", UID: "uidParent"},
				ChildGroups:                []string{"cgChild"},
				ChildGroupsNestingExceeded: tt.parentNestingExceeded,
			}
			_, npc := newController(nil, nil)
			npc.internalGroupStore.Create(cgChild)
			npc.internalGroupStore.Create(cgParent)

			npc.triggerParentGroupUpdates("cgChild")
			assert.Equal(t, tt.expectedEnqueue, npc.internalGroupQueue.Len())
		})
	}

	// A Group that has been deleted from the store is not in the store to be read back, and its
	// parents must still be notified: the delete is what lets an over-nested parent recover.
	t.Run("deleted child enqueues its over-nested parent", func(t *testing.T) {
		cgParent := &antreatypes.Group{
			UID:                        "uidParent",
			SourceReference:            &controlplane.GroupReference{Name: "cgParent", UID: "uidParent"},
			ChildGroups:                []string{"cgChild"},
			ChildGroupsNestingExceeded: true,
		}
		_, npc := newController(nil, nil)
		npc.internalGroupStore.Create(cgParent)

		npc.triggerParentGroupUpdates("cgChild")
		assert.Equal(t, 1, npc.internalGroupQueue.Len())
	})
}

// TestOverNestedGroupNotAppliedTo verifies that a Group nested deeper than the supported level
// selects no workload when it is used as the appliedTo of a policy, instead of applying the
// policy to whatever part of its hierarchy fits within the level. This mirrors what
// TestOverNestedGroupNotRealized covers for the two rule-peer traversals.
func TestOverNestedGroupNotAppliedTo(t *testing.T) {
	// testPods[0] carries the "app: foo" label in the "test-ns" Namespace.
	leafPods := antreatypes.Group{
		UID:             "uidLeafPods",
		SourceReference: &controlplane.GroupReference{Name: "cgLeafPods", UID: "uidLeafPods"},
		Selector:        antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
	}
	childWithChildren := antreatypes.Group{
		UID:             "uidChildWithChildren",
		SourceReference: &controlplane.GroupReference{Name: "cgChildWithChildren", UID: "uidChildWithChildren"},
		ChildGroups:     []string{"cgLeafPods"},
	}
	// parent mixes a leaf, whose workloads the single-level appliedTo traversal does resolve,
	// with a child that has childGroups of its own, which is what puts it over the level. Without
	// the check, it would be applied to the leaf's Pods only: realized, but on an arbitrary
	// subset of what it names.
	parent := antreatypes.Group{
		UID:                        "uidParent",
		SourceReference:            &controlplane.GroupReference{Name: "cgParent", UID: "uidParent"},
		ChildGroups:                []string{"cgLeafPods", "cgChildWithChildren"},
		ChildGroupsNestingExceeded: true,
	}
	validParent := antreatypes.Group{
		UID:             "uidValidParent",
		SourceReference: &controlplane.GroupReference{Name: "cgValidParent", UID: "uidValidParent"},
		ChildGroups:     []string{"cgLeafPods"},
	}

	_, npc := newController(nil, nil)
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	createGroups(npc, []antreatypes.Group{leafPods, childWithChildren, parent, validParent})

	pods, ees, err := npc.getInternalGroupWorkloads(&parent)
	require.NoError(t, err)
	assert.Empty(t, pods)
	assert.Empty(t, ees)

	// The valid hierarchy underneath it still selects its Pods.
	pods, ees, err = npc.getInternalGroupWorkloads(&validParent)
	require.NoError(t, err)
	assert.Equal(t, []*corev1.Pod{testPods[0]}, pods)
	assert.Empty(t, ees)
}

// TestSyncInternalGroupCycleConverges verifies that both members of a ChildGroups cycle end up
// flagged even when the first one was synced before the second one existed, which is the order a
// user creating them one at a time produces.
//
// At that first sync, cgA's only childGroup does not resolve, so cgA is not over-nested yet. It
// is cgB's creation that makes it so, and cgB - flagged on its own first sync - is what has to
// enqueue cgA again. That is why triggerParentGroupUpdates gates on the parent rather than
// returning early for a Group that is itself flagged: with the latter, cgA would keep an
// out-of-date flag and report no reason for its members not being computed.
func TestSyncInternalGroupCycleConverges(t *testing.T) {
	cgA := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"cgB"}},
	}
	cgB := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"}},
	}
	_, npc := newControllerWithoutEventHandler(nil, []runtime.Object{cgA, cgB})
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.crdInformerFactory.Start(stopCh)
	npc.crdInformerFactory.WaitForCacheSync(stopCh)

	nestingExceeded := func(key string) bool {
		obj, found, _ := npc.internalGroupStore.Get(key)
		require.True(t, found)
		return obj.(*antreatypes.Group).ChildGroupsNestingExceeded
	}
	// drainQueue syncs everything the queue holds, and returns how many syncs that took. It is
	// bounded so that a regression that reintroduces the spin fails the test instead of hanging
	// it.
	drainQueue := func() int {
		for synced := 0; ; synced++ {
			require.Less(t, synced, 100, "internalGroup workqueue is not draining, the ChildGroups cycle is spinning")
			if npc.internalGroupQueue.Len() == 0 {
				return synced
			}
			key, _ := npc.internalGroupQueue.Get()
			require.NoError(t, npc.syncInternalGroup(key))
			npc.internalGroupQueue.Done(key)
		}
	}

	// cgA is created first, while cgB does not exist yet: its childGroups do not resolve to
	// anything, so nothing is over-nested.
	npc.addClusterGroup(cgA)
	drainQueue()
	assert.False(t, nestingExceeded("cgA"))

	// cgB closes the cycle. Its own sync flags it, and must also enqueue cgA so that cgA
	// recomputes its now out-of-date flag.
	npc.addClusterGroup(cgB)
	drainQueue()
	assert.True(t, nestingExceeded("cgA"), "expected cgA to be flagged once cgB closed the cycle")
	assert.True(t, nestingExceeded("cgB"))

	// Both are flagged, so neither enqueues the other any more: the queue stays empty.
	npc.triggerParentGroupUpdates("cgA")
	npc.triggerParentGroupUpdates("cgB")
	assert.Equal(t, 0, npc.internalGroupQueue.Len())

	// Both report why they are not realized.
	for _, name := range []string{"cgA", "cgB"} {
		cg, err := npc.crdClient.CrdV1beta1().ClusterGroups().Get(context.TODO(), name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, cg.Status.Conditions, 1, "ClusterGroup %s", name)
		assert.Equal(t, corev1.ConditionFalse, cg.Status.Conditions[0].Status, "ClusterGroup %s", name)
		assert.Equal(t, crdv1beta1.ChildGroupsNestingExceeded, cg.Status.Conditions[0].Reason, "ClusterGroup %s", name)
	}
}

// groupNestingFixture drives TestSyncInternalGroupNestingRecovers against both a ClusterGroup
// hierarchy and a Namespaced Group one. clustergroup.go and group.go implement the same status
// logic independently, so a ClusterGroup-only test would not catch the two copies diverging.
//
// Every fixture is a parent -> child -> grandChild chain, which is one level too deep, so the
// parent is not realized while the child and the grandChild are fine.
type groupNestingFixture struct {
	name string
	// objects seeds the fake CRD client and the informer caches.
	objects []runtime.Object
	// parentKey and childKey are the internal Group keys of the parent and of the child.
	parentKey string
	childKey  string
	// addAll replays the ADD events for the three source objects.
	addAll func(npc *networkPolicyController)
	// fixChild replaces the child's childGroups with a selector, which is what a user following
	// the status message would do.
	fixChild func(npc *networkPolicyController)
	// deleteChild deletes the child.
	deleteChild func(npc *networkPolicyController)
	// parent returns the parent source object as the fake CRD client holds it, i.e. carrying the
	// status the controller last wrote, along with its conditions.
	parent func(npc *networkPolicyController) (runtime.Object, []crdv1beta1.GroupCondition)
	// cacheParent writes a parent source object into the informer cache, so that the lister
	// reports its status without waiting for a watch round-trip.
	cacheParent func(npc *networkPolicyController, parent runtime.Object)
}

// TestSyncInternalGroupNestingRecovers verifies that an over-nested Group or ClusterGroup goes
// back to being realized once the childGroup responsible for the excessive nesting is fixed or
// deleted, without the Group itself being edited.
//
// This is the counterpart of TestSyncInternalGroupCycleConverges, and the reason
// triggerParentGroupUpdates requires both the Group being synced and the parent to be flagged
// before it skips the parent. The event that fixes a hierarchy is always observed by the child,
// so gating on the parent alone would make the flag a one-way door: the status message tells the
// user to fix the definition of the Group "or the definition of one of its childGroups", and only
// the former would actually work.
func TestSyncInternalGroupNestingRecovers(t *testing.T) {
	// cgA -> cgB -> cgC is one level too deep, so cgA is not realized. cgB and cgC are fine.
	cgA := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"cgB"}},
	}
	cgB := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"cgC"}},
	}
	cgC := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
		Spec:       crdv1beta1.GroupSpec{NamespaceSelector: &metav1.LabelSelector{}},
	}
	// cgBFixed is cgB with its childGroups replaced by a selector.
	cgBFixed := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
		Spec:       crdv1beta1.GroupSpec{NamespaceSelector: &metav1.LabelSelector{}},
	}
	// gA -> gB -> gC is the same chain, with Namespaced Groups: the childGroups of a Group are
	// always resolved within its own Namespace.
	gA := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidGA"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"gB"}},
	}
	gB := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gB", UID: "uidGB"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"gC"}},
	}
	gC := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gC", UID: "uidGC"},
		Spec:       crdv1beta1.GroupSpec{PodSelector: &metav1.LabelSelector{}},
	}
	gBFixed := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gB", UID: "uidGB"},
		Spec:       crdv1beta1.GroupSpec{PodSelector: &metav1.LabelSelector{}},
	}
	fixtures := []groupNestingFixture{
		{
			name:      "ClusterGroup",
			objects:   []runtime.Object{cgA, cgB, cgC},
			parentKey: internalGroupKeyFunc(cgA),
			childKey:  internalGroupKeyFunc(cgB),
			addAll: func(npc *networkPolicyController) {
				npc.addClusterGroup(cgC)
				npc.addClusterGroup(cgB)
				npc.addClusterGroup(cgA)
			},
			fixChild: func(npc *networkPolicyController) {
				npc.crdInformerFactory.Crd().V1beta1().ClusterGroups().Informer().GetStore().Update(cgBFixed)
				npc.updateClusterGroup(cgB, cgBFixed)
			},
			deleteChild: func(npc *networkPolicyController) {
				npc.crdInformerFactory.Crd().V1beta1().ClusterGroups().Informer().GetStore().Delete(cgB)
				npc.deleteClusterGroup(cgB)
			},
			parent: func(npc *networkPolicyController) (runtime.Object, []crdv1beta1.GroupCondition) {
				cg, err := npc.crdClient.CrdV1beta1().ClusterGroups().Get(context.TODO(), cgA.Name, metav1.GetOptions{})
				require.NoError(t, err)
				return cg, cg.Status.Conditions
			},
			cacheParent: func(npc *networkPolicyController, parent runtime.Object) {
				npc.crdInformerFactory.Crd().V1beta1().ClusterGroups().Informer().GetStore().Update(parent)
			},
		},
		{
			name:      "Group",
			objects:   []runtime.Object{gA, gB, gC},
			parentKey: internalGroupKeyFunc(gA),
			childKey:  internalGroupKeyFunc(gB),
			addAll: func(npc *networkPolicyController) {
				npc.addGroup(gC)
				npc.addGroup(gB)
				npc.addGroup(gA)
			},
			fixChild: func(npc *networkPolicyController) {
				npc.crdInformerFactory.Crd().V1beta1().Groups().Informer().GetStore().Update(gBFixed)
				npc.updateGroup(gB, gBFixed)
			},
			deleteChild: func(npc *networkPolicyController) {
				npc.crdInformerFactory.Crd().V1beta1().Groups().Informer().GetStore().Delete(gB)
				npc.deleteGroup(gB)
			},
			parent: func(npc *networkPolicyController) (runtime.Object, []crdv1beta1.GroupCondition) {
				g, err := npc.crdClient.CrdV1beta1().Groups(gA.Namespace).Get(context.TODO(), gA.Name, metav1.GetOptions{})
				require.NoError(t, err)
				return g, g.Status.Conditions
			},
			cacheParent: func(npc *networkPolicyController, parent runtime.Object) {
				npc.crdInformerFactory.Crd().V1beta1().Groups().Informer().GetStore().Update(parent)
			},
		},
	}
	tests := []struct {
		name string
		// fix applies the event that is expected to let the parent recover.
		fix func(f groupNestingFixture, npc *networkPolicyController)
		// resetFlag clears the parent's in-memory ChildGroupsNestingExceeded before the fix is
		// applied, which is what an ADD/UPDATE event on the parent, or an antrea-controller
		// restart, leaves behind. Clearing the stale reason then has nothing to go on but the
		// condition the source object reports, i.e. it exercises the
		// groupMembersComputedReportsNestingExceeded fallback rather than the in-memory signal.
		resetFlag bool
		// expectedStatus is what the parent reports afterwards. Deleting the child leaves the
		// parent referencing a childGroup that does not exist, which is the pre-existing "not
		// computed yet" case, so it stays False - but with no reason, since the nesting is no
		// longer the problem.
		expectedStatus corev1.ConditionStatus
	}{
		{
			name:           "childGroup no longer has childGroups of its own",
			fix:            func(f groupNestingFixture, npc *networkPolicyController) { f.fixChild(npc) },
			expectedStatus: corev1.ConditionTrue,
		},
		{
			name:           "childGroup is deleted",
			fix:            func(f groupNestingFixture, npc *networkPolicyController) { f.deleteChild(npc) },
			expectedStatus: corev1.ConditionFalse,
		},
		{
			name:           "childGroup is deleted after the in-memory flag was reset",
			fix:            func(f groupNestingFixture, npc *networkPolicyController) { f.deleteChild(npc) },
			resetFlag:      true,
			expectedStatus: corev1.ConditionFalse,
		},
	}
	for _, f := range fixtures {
		for _, tt := range tests {
			t.Run(f.name+"/"+tt.name, func(t *testing.T) {
				_, npc := newControllerWithoutEventHandler(nil, f.objects)
				stopCh := make(chan struct{})
				defer close(stopCh)
				npc.crdInformerFactory.Start(stopCh)
				npc.crdInformerFactory.WaitForCacheSync(stopCh)

				nestingExceeded := func(key string) bool {
					obj, found, _ := npc.internalGroupStore.Get(key)
					require.True(t, found)
					return obj.(*antreatypes.Group).ChildGroupsNestingExceeded
				}
				// drainQueue is bounded, so a regression that reintroduces the spin fails the
				// test instead of hanging it.
				drainQueue := func() {
					for synced := 0; npc.internalGroupQueue.Len() > 0; synced++ {
						require.Less(t, synced, 100, "internalGroup workqueue is not draining")
						key, _ := npc.internalGroupQueue.Get()
						require.NoError(t, npc.syncInternalGroup(key))
						npc.internalGroupQueue.Done(key)
					}
				}

				f.addAll(npc)
				drainQueue()
				require.True(t, nestingExceeded(f.parentKey), "%s nests one level too deep through %s", f.parentKey, f.childKey)
				require.False(t, nestingExceeded(f.childKey))
				parentObj, conditions := f.parent(npc)
				require.Len(t, conditions, 1)
				require.Equal(t, crdv1beta1.ChildGroupsNestingExceeded, conditions[0].Reason)

				if tt.resetFlag {
					// Make the lister report that status without waiting for a watch
					// round-trip, then drop the in-memory flag.
					f.cacheParent(npc, parentObj)
					obj, found, _ := npc.internalGroupStore.Get(f.parentKey)
					require.True(t, found)
					unflagged := *obj.(*antreatypes.Group)
					unflagged.ChildGroupsNestingExceeded = false
					npc.internalGroupStore.Update(&unflagged)
				}

				tt.fix(f, npc)
				drainQueue()

				// The parent is no longer over-nested, without having been edited itself.
				assert.False(t, nestingExceeded(f.parentKey), "expected %s to recover once %s was fixed", f.parentKey, f.childKey)
				_, conditions = f.parent(npc)
				require.Len(t, conditions, 1)
				assert.Equal(t, tt.expectedStatus, conditions[0].Status)
				// The stale reason and message do not survive the transition either way.
				assert.Empty(t, conditions[0].Reason)
				assert.Empty(t, conditions[0].Message)
			})
		}
	}
}

// TestSyncInternalGroupNestingExceeded verifies that the first real sync of a self-referencing
// ClusterGroup, and of a self-referencing Group, detects the excessive nesting, reports it in
// the GroupMembersComputed condition, and honors it in the same pass, i.e. that the CPU spin
// never starts in the first place.
//
// This exercises syncInternalGroup end to end instead of presetting ChildGroupsNestingExceeded
// on the internal Group directly (as TestTriggerParentGroupUpdatesNestingExceeded does),
// because syncInternalGroup only avoids the spin if childGroupsNestingExceeded is computed and
// persisted to the internal Group store before the deferred triggerParentGroupUpdates call
// reads it back. That is a same-function ordering constraint which a preset flag does not
// exercise, and which a future refactor could silently break with every other test still green.
func TestSyncInternalGroupNestingExceeded(t *testing.T) {
	cgA := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"cgA"}},
	}
	gA := &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: "nsA", Name: "gA", UID: "uidGA"},
		Spec:       crdv1beta1.GroupSpec{ChildGroups: []crdv1beta1.ClusterGroupReference{"gA"}},
	}
	tests := []struct {
		name string
		key  string
		add  func(npc *networkPolicyController)
		// conditions returns the status conditions of the source object, as stored by the
		// fake CRD client.
		conditions func(npc *networkPolicyController) []crdv1beta1.GroupCondition
	}{
		{
			name: "ClusterGroup",
			key:  internalGroupKeyFunc(cgA),
			add:  func(npc *networkPolicyController) { npc.addClusterGroup(cgA) },
			conditions: func(npc *networkPolicyController) []crdv1beta1.GroupCondition {
				cg, err := npc.crdClient.CrdV1beta1().ClusterGroups().Get(context.TODO(), cgA.Name, metav1.GetOptions{})
				require.NoError(t, err)
				return cg.Status.Conditions
			},
		},
		{
			name: "Group",
			key:  internalGroupKeyFunc(gA),
			add:  func(npc *networkPolicyController) { npc.addGroup(gA) },
			conditions: func(npc *networkPolicyController) []crdv1beta1.GroupCondition {
				g, err := npc.crdClient.CrdV1beta1().Groups(gA.Namespace).Get(context.TODO(), gA.Name, metav1.GetOptions{})
				require.NoError(t, err)
				return g.Status.Conditions
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newControllerWithoutEventHandler(nil, []runtime.Object{cgA, gA})
			stopCh := make(chan struct{})
			defer close(stopCh)
			npc.crdInformerFactory.Start(stopCh)
			npc.crdInformerFactory.WaitForCacheSync(stopCh)

			tt.add(npc)
			// Drain the ADD handler's own enqueue, which is unrelated to the cycle: it is what
			// a real worker's queue.Get() would have consumed before calling syncInternalGroup.
			key, _ := npc.internalGroupQueue.Get()
			npc.internalGroupQueue.Done(key)
			require.Equal(t, 0, npc.internalGroupQueue.Len())

			require.NoError(t, npc.syncInternalGroup(tt.key))

			obj, found, _ := npc.internalGroupStore.Get(tt.key)
			require.True(t, found)
			assert.True(t, obj.(*antreatypes.Group).ChildGroupsNestingExceeded)
			// If this were 1, the Group re-enqueued itself as its own parent: the first sync
			// detected the excessive nesting too late to prevent triggerParentGroupUpdates
			// from acting on stale data.
			assert.Equal(t, 0, npc.internalGroupQueue.Len())

			conditions := tt.conditions(npc)
			require.Len(t, conditions, 1)
			assert.Equal(t, crdv1beta1.GroupMembersComputed, conditions[0].Type)
			assert.Equal(t, corev1.ConditionFalse, conditions[0].Status)
			assert.Equal(t, crdv1beta1.ChildGroupsNestingExceeded, conditions[0].Reason)
			assert.NotEmpty(t, conditions[0].Message)
		})
	}
}

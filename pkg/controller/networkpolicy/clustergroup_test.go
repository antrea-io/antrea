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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
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
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{},
					},
				},
				IPNets: []net.IPNet{*ipNet},
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
	controlplaneIPNet, _ := cidrStrToIPNet(cidr)
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
						CIDR:   *controlplaneIPNet,
						Except: []controlplane.IPNet{},
					},
				},
				IPNets: []net.IPNet{*ipNet},
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
}

func TestGetAssociatedGroups(t *testing.T) {
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
			for i, g := range tt.existingGroups {
				npc.internalGroupStore.Create(&tt.existingGroups[i])
				if g.Selector != nil {
					npc.groupingInterface.AddGroup(internalGroupType, g.SourceReference.Name, g.Selector)
				}
			}
			groups := npc.GetAssociatedGroups(tt.queryName, tt.queryNamespace)
			assert.ElementsMatch(t, tt.expectedGroups, groups)
		})
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
		actualKeys = append(actualKeys, key.(controlplane.NetworkPolicyReference))
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

	_, npc := newControllerWithoutEventHandler(nil, []runtime.Object{cg1, cg2, cg2Parent})
	stopCh := make(chan struct{})
	defer close(stopCh)
	npc.crdInformerFactory.Start(stopCh)
	npc.crdInformerFactory.WaitForCacheSync(stopCh)

	npc.addClusterGroup(cg1)
	npc.syncInternalGroup(internalGroupKeyFunc(cg1))
	npc.addClusterGroup(cg2)
	npc.syncInternalGroup(internalGroupKeyFunc(cg2))
	npc.addClusterGroup(cg2Parent)
	npc.syncInternalGroup(internalGroupKeyFunc(cg2Parent))

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

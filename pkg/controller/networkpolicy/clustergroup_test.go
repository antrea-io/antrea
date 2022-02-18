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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

func TestProcessClusterGroup(t *testing.T) {
	selectorA := metav1.LabelSelector{MatchLabels: map[string]string{"foo1": "bar1"}}
	selectorB := metav1.LabelSelector{MatchLabels: map[string]string{"foo2": "bar2"}}
	selectorC := metav1.LabelSelector{MatchLabels: map[string]string{"foo3": "bar3"}}
	selectorD := metav1.LabelSelector{MatchLabels: map[string]string{"foo4": "bar4"}}
	cidr := "10.0.0.0/24"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1alpha3.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: antreatypes.NewGroupSelector("", nil, &selectorA, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidB",
				Name:     "cgB",
				Selector: antreatypes.NewGroupSelector("", &selectorB, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidC",
				Name:     "cgC",
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidD",
				Name: "cgD",
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []controlplane.IPNet{},
					},
				},
			},
		},
		{
			name: "cg-with-svc-reference",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgE", UID: "uidE"},
				Spec: crdv1alpha3.GroupSpec{
					ServiceReference: &crdv1alpha3.ServiceReference{
						Name:      "test-svc",
						Namespace: "test-ns",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidE",
				Name: "cgE",
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "test-ns",
				},
			},
		},
		{
			name: "cg-with-child-groups",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgF", UID: "uidF"},
				Spec: crdv1alpha3.GroupSpec{
					ChildGroups: []crdv1alpha3.ClusterGroupReference{"cgA", "cgB"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:         "uidF",
				Name:        "cgF",
				ChildGroups: []string{"cgA", "cgB"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newController()
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
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	tests := []struct {
		name          string
		inputGroup    *crdv1alpha3.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: antreatypes.NewGroupSelector("", nil, &selectorA, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidB",
				Name:     "cgB",
				Selector: antreatypes.NewGroupSelector("", &selectorB, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidC",
				Name:     "cgC",
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidD",
				Name: "cgD",
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []controlplane.IPNet{},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, npc := newController()
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
	testCG := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	cidr := "10.0.0.0/24"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	tests := []struct {
		name          string
		updatedGroup  *crdv1alpha3.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-update-ns-selector",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: antreatypes.NewGroupSelector("", nil, &selectorB, nil),
			},
		},
		{
			name: "cg-update-pod-selector",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					PodSelector: &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: antreatypes.NewGroupSelector("", &selectorC, nil, nil),
			},
		},
		{
			name: "cg-update-pod-ns-selector",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: antreatypes.NewGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-update-ip-block",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					IPBlocks: []crdv1alpha1.IPBlock{
						{
							CIDR: cidr,
						},
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidA",
				Name: "cgA",
				IPBlocks: []controlplane.IPBlock{
					{
						CIDR:   *cidrIPNet,
						Except: []controlplane.IPNet{},
					},
				},
			},
		},
		{
			name: "cg-update-svc-reference",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					ServiceReference: &crdv1alpha3.ServiceReference{
						Name:      "test-svc",
						Namespace: "test-ns",
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidA",
				Name: "cgA",
				ServiceReference: &controlplane.ServiceReference{
					Name:      "test-svc",
					Namespace: "test-ns",
				},
			},
		},
		{
			name: "cg-update-child-groups",
			updatedGroup: &crdv1alpha3.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: crdv1alpha3.GroupSpec{
					ChildGroups: []crdv1alpha3.ClusterGroupReference{"cgB", "cgC"},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:         "uidA",
				Name:        "cgA",
				ChildGroups: []string{"cgB", "cgC"},
			},
		},
	}
	_, npc := newController()
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
	testCG := crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	key := testCG.Name
	_, npc := newController()
	npc.addClusterGroup(&testCG)
	npc.deleteClusterGroup(&testCG)
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
		UID:  "uid1",
		Name: "cgA",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
	}
	grp2 := &antreatypes.Group{
		UID:  "uid2",
		Name: "cgB",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
		Selector: antreatypes.NewGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:  "uid3",
		Name: "cgC",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc2",
			Namespace: "test",
		},
		// Selector is out of sync with latest service spec, but the CG should still be returned.
		Selector: antreatypes.NewGroupSelector("test", nil, nil, nil),
	}
	grp4 := &antreatypes.Group{
		UID:  "uid4",
		Name: "cgD",
		ServiceReference: &controlplane.ServiceReference{
			Name: "svc3",
		},
	}

	tests := []struct {
		name           string
		toMatch        *corev1.Service
		expectedGroups sets.String
	}{
		{
			"service-match-name-default-ns",
			svc1,
			sets.NewString("cgA", "cgB"),
		},
		{
			"service-match-name-and-namespace",
			svc2,
			sets.NewString("cgC"),
		},
	}
	_, npc := newController()
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
		UID:  "uid1",
		Name: "cgA",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc1",
			Namespace: metav1.NamespaceDefault,
		},
	}
	grp2 := &antreatypes.Group{
		UID:  "uid2",
		Name: "cgB",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc2",
			Namespace: "test",
		},
	}
	grp3 := &antreatypes.Group{
		UID:  "uid3",
		Name: "cgC",
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
			antreatypes.NewGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil),
		},
		{
			"service-match-name-and-namespace",
			svc2,
			grp2,
			antreatypes.NewGroupSelector("test", &selectorSpec, nil, nil),
		},
		{
			"service-without-selectors",
			svc3,
			grp3,
			nil,
		},
	}
	_, npc := newController()
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
		UID:      "groupUID0",
		Name:     "group0",
		Selector: antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil),
	},
	{
		UID:      "groupUID1",
		Name:     "group1",
		Selector: antreatypes.NewGroupSelector("test-ns", nil, nil, nil),
	},
	{
		UID:      "groupUID2",
		Name:     "group2",
		Selector: antreatypes.NewGroupSelector("test-ns", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}, nil, nil),
	},
	{
		UID:         "groupUID3",
		Name:        "group3",
		ChildGroups: []string{"group0", "group1"},
	},
	{
		UID:         "groupUID4",
		Name:        "group4",
		ChildGroups: []string{"group0", "group2"},
	},
	{
		UID:         "groupUID5",
		Name:        "group5",
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
	_, npc := newController()
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
					npc.groupingInterface.AddGroup(clusterGroupType, g.Name, g.Selector)
				}
			}
			groups, err := npc.GetAssociatedGroups(tt.queryName, tt.queryNamespace)
			assert.Equal(t, err, nil)
			assert.ElementsMatch(t, tt.expectedGroups, groups)
		})
	}
}

func TestGetGroupMembers(t *testing.T) {
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
	_, npc := newController()
	for i := range testPods {
		npc.groupingInterface.AddPod(testPods[i])
	}
	for j := range externalEntities {
		npc.groupingInterface.AddExternalEntity(externalEntities[j])
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			npc.internalGroupStore.Create(&tt.group)
			npc.groupingInterface.AddGroup(clusterGroupType, tt.group.Name, tt.group.Selector)
			members, _, err := npc.GetGroupMembers(tt.group.Name)
			assert.Equal(t, nil, err)
			assert.Equal(t, tt.expectedMembers, members)
		})
	}
}

func TestSyncInternalGroup(t *testing.T) {
	p10 := float64(10)
	p20 := float64(20)
	allowAction := crdv1alpha1.RuleActionAllow
	cgName := "cgA"
	cgUID := types.UID("uidA")
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName, UID: cgUID},
		Spec:       crdv1alpha3.GroupSpec{NamespaceSelector: &selectorA},
	}
	cnp1 := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp1", UID: "uid1"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
				{PodSelector: &selectorB},
			},
			Priority: p10,
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
						{Group: cgName},
					},
					Action: &allowAction,
				},
			},
		},
	}
	cnp2 := &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cnp2", UID: "uid2"},
		Spec: crdv1alpha1.ClusterNetworkPolicySpec{
			AppliedTo: []crdv1alpha1.NetworkPolicyPeer{
				{PodSelector: &selectorC},
			},
			Priority: p20,
			Ingress: []crdv1alpha1.Rule{
				{
					From: []crdv1alpha1.NetworkPolicyPeer{
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

	// After creating a ClusterGroup:
	// - A corresponding internal group should be added for it.
	// - The internal NetworkPolicies for the ClusterNetworkPolicies that use it should reference to it regardless of
	//   whether they are added before the ClusterGroup or after it.
	// - An AddressGroup should be created for it.

	// cnp1 is added before the ClusterGroup.
	npc.addCNP(cnp1)
	npc.addClusterGroup(cg)
	err := npc.syncInternalGroup(internalGroupKeyFunc(cg))
	require.NoError(t, err)
	// cnp2 is added after the ClusterGroup.
	npc.addCNP(cnp2)

	expectedInternalNetworkPolicy1 := &antreatypes.NetworkPolicy{
		UID:  "uid1",
		Name: "uid1",
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: "cnp1",
			UID:  "uid1",
		},
		Priority:     &p10,
		TierPriority: &DefaultTierPriority,
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{cgName}},
				Priority:  0,
				Action:    &allowAction,
			},
		},
		AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorB, nil, nil).NormalizedName)},
	}
	actualInternalNetworkPolicy1, exists, _ := npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp1))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy1, actualInternalNetworkPolicy1)

	expectedInternalNetworkPolicy2 := &antreatypes.NetworkPolicy{
		UID:  "uid2",
		Name: "uid2",
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: "cnp2",
			UID:  "uid2",
		},
		Priority:     &p20,
		TierPriority: &DefaultTierPriority,
		Rules: []controlplane.NetworkPolicyRule{
			{
				Direction: controlplane.DirectionIn,
				From:      controlplane.NetworkPolicyPeer{AddressGroups: []string{cgName}},
				Priority:  0,
				Action:    &allowAction,
			},
		},
		AppliedToGroups: []string{getNormalizedUID(antreatypes.NewGroupSelector("", &selectorC, nil, nil).NormalizedName)},
	}
	actualInternalNetworkPolicy2, exists, _ := npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp2))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy2, actualInternalNetworkPolicy2)

	expectedInternalGroup := &antreatypes.Group{
		UID:             cgUID,
		Name:            cgName,
		Selector:        antreatypes.NewGroupSelector("", nil, &selectorA, nil),
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

	_, exists, _ = npc.internalGroupStore.Get(internalGroupKeyFunc(cg))
	require.False(t, exists)

	expectedInternalNetworkPolicy1.Rules[0].From.AddressGroups = nil
	actualInternalNetworkPolicy1, exists, _ = npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp1))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy1, actualInternalNetworkPolicy1)

	expectedInternalNetworkPolicy2.Rules[0].From.AddressGroups = nil
	actualInternalNetworkPolicy2, exists, _ = npc.internalNetworkPolicyStore.Get(internalNetworkPolicyKeyFunc(cnp2))
	require.True(t, exists)
	assert.Equal(t, expectedInternalNetworkPolicy2, actualInternalNetworkPolicy2)

	_, exists, _ = npc.addressGroupStore.Get(cgName)
	require.False(t, exists, "The AddressGroup for the ClusterGroup should be deleted when it's no longer referenced by any ClusterNetworkPolicy")
}

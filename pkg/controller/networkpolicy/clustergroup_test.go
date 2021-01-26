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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	corev1a2 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
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
		inputGroup    *corev1a2.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: toGroupSelector("", nil, &selectorA, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: corev1a2.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidB",
				Name:     "cgB",
				Selector: toGroupSelector("", &selectorB, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidC",
				Name:     "cgC",
				Selector: toGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: corev1a2.GroupSpec{
					IPBlock: &secv1alpha1.IPBlock{
						CIDR: cidr,
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidD",
				Name: "cgD",
				IPBlock: &controlplane.IPBlock{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name: "cg-with-svc-reference",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgE", UID: "uidE"},
				Spec: corev1a2.GroupSpec{
					ServiceReference: &corev1a2.ServiceReference{
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
		inputGroup    *corev1a2.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-with-ns-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorA,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: toGroupSelector("", nil, &selectorA, nil),
			},
		},
		{
			name: "cg-with-pod-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgB", UID: "uidB"},
				Spec: corev1a2.GroupSpec{
					PodSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidB",
				Name:     "cgB",
				Selector: toGroupSelector("", &selectorB, nil, nil),
			},
		},
		{
			name: "cg-with-pod-ns-selector",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgC", UID: "uidC"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidC",
				Name:     "cgC",
				Selector: toGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-with-ip-block",
			inputGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgD", UID: "uidD"},
				Spec: corev1a2.GroupSpec{
					IPBlock: &secv1alpha1.IPBlock{
						CIDR: cidr,
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidD",
				Name: "cgD",
				IPBlock: &controlplane.IPBlock{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
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
	testCG := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: corev1a2.GroupSpec{
			NamespaceSelector: &selectorA,
		},
	}
	cidr := "10.0.0.0/24"
	cidrIPNet, _ := cidrStrToIPNet(cidr)
	tests := []struct {
		name          string
		updatedGroup  *corev1a2.ClusterGroup
		expectedGroup *antreatypes.Group
	}{
		{
			name: "cg-update-ns-selector",
			updatedGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorB,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: toGroupSelector("", nil, &selectorB, nil),
			},
		},
		{
			name: "cg-update-pod-selector",
			updatedGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					PodSelector: &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: toGroupSelector("", &selectorC, nil, nil),
			},
		},
		{
			name: "cg-update-pod-ns-selector",
			updatedGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					NamespaceSelector: &selectorD,
					PodSelector:       &selectorC,
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:      "uidA",
				Name:     "cgA",
				Selector: toGroupSelector("", &selectorC, &selectorD, nil),
			},
		},
		{
			name: "cg-update-ip-block",
			updatedGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					IPBlock: &secv1alpha1.IPBlock{
						CIDR: cidr,
					},
				},
			},
			expectedGroup: &antreatypes.Group{
				UID:  "uidA",
				Name: "cgA",
				IPBlock: &controlplane.IPBlock{
					CIDR:   *cidrIPNet,
					Except: []controlplane.IPNet{},
				},
			},
		},
		{
			name: "cg-update-svc-reference",
			updatedGroup: &corev1a2.ClusterGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
				Spec: corev1a2.GroupSpec{
					ServiceReference: &corev1a2.ServiceReference{
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
	testCG := corev1a2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "cgA", UID: "uidA"},
		Spec: corev1a2.GroupSpec{
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

func TestFilterInternalGroupsForPod(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "ns1",
			Labels: map[string]string{"purpose": "test-select"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
		},
	}
	grp1 := &antreatypes.Group{
		UID:      "uid1",
		Name:     "cgA",
		Selector: toGroupSelector("", &selectorSpec, nil, nil),
	}
	grp2 := &antreatypes.Group{
		UID:      "uid2",
		Name:     "cgB",
		Selector: toGroupSelector("", nil, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:      "uid3",
		Name:     "cgC",
		Selector: toGroupSelector("", nil, &selectorSpec, nil),
	}
	grp4 := &antreatypes.Group{
		UID:      "uid4",
		Name:     "cgD",
		Selector: toGroupSelector("", &selectorSpec, &selectorSpec, nil),
	}

	pod1 := getPod("pod1", "ns1", "node1", "1.1.1.1", false)
	pod1.Labels = map[string]string{"purpose": "test-select"}
	pod2 := getPod("pod2", "ns1", "node1", "1.1.1.2", false)
	pod3 := getPod("pod3", "ns2", "node1", "1.1.1.3", false)
	tests := []struct {
		name           string
		toMatch        metav1.Object
		expectedGroups sets.String
	}{
		{
			"pod-match-selector-match-ns",
			pod1,
			sets.NewString("cgA", "cgC", "cgD"),
		},
		{
			"pod-unmatch-selector-match-ns",
			pod2,
			sets.NewString("cgC"),
		},
		{
			"pod-unmatch-selector-unmatch-ns",
			pod3,
			sets.String{},
		},
	}
	_, npc := newController()
	npc.internalGroupStore.Create(grp1)
	npc.internalGroupStore.Create(grp2)
	npc.internalGroupStore.Create(grp3)
	npc.internalGroupStore.Create(grp4)
	npc.namespaceStore.Add(ns1)
	npc.namespaceStore.Add(ns2)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedGroups, npc.filterInternalGroupsForPod(tt.toMatch),
				"Filtered internal Groups does not match expectation")
		})
	}
}

func TestFilterInternalGroupsForNamespace(t *testing.T) {
	selectorSpec := metav1.LabelSelector{
		MatchLabels: map[string]string{"purpose": "test-select"},
	}
	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "ns1",
			Labels: map[string]string{"purpose": "test-select"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
		},
	}
	grp1 := &antreatypes.Group{
		UID:      "uid1",
		Name:     "cgA",
		Selector: toGroupSelector("", &selectorSpec, nil, nil),
	}
	grp2 := &antreatypes.Group{
		UID:      "uid2",
		Name:     "cgB",
		Selector: toGroupSelector("", nil, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:      "uid3",
		Name:     "cgC",
		Selector: toGroupSelector("", nil, &selectorSpec, nil),
	}
	grp4 := &antreatypes.Group{
		UID:      "uid4",
		Name:     "cgD",
		Selector: toGroupSelector("", &selectorSpec, &selectorSpec, nil),
	}

	tests := []struct {
		name           string
		toMatch        *corev1.Namespace
		expectedGroups sets.String
	}{
		{
			"ns-match-selector",
			ns1,
			sets.NewString("cgC", "cgD"),
		},
		{
			"ns-unmatch-selector",
			ns2,
			sets.String{},
		},
	}
	_, npc := newController()
	npc.internalGroupStore.Create(grp1)
	npc.internalGroupStore.Create(grp2)
	npc.internalGroupStore.Create(grp3)
	npc.internalGroupStore.Create(grp4)
	npc.namespaceStore.Add(ns1)
	npc.namespaceStore.Add(ns2)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedGroups, npc.filterInternalGroupsForNamespace(tt.toMatch),
				"Filtered internal Groups does not match expectation")
		})
	}
}

func TestGroupMembersComputedConditionEqual(t *testing.T) {
	tests := []struct {
		name          string
		existingConds []corev1a2.GroupCondition
		checkStatus   corev1.ConditionStatus
		expValue      bool
	}{
		{
			name: "groupmem-cond-exists-not-equal",
			existingConds: []corev1a2.GroupCondition{
				{
					Type:   corev1a2.GroupMembersComputed,
					Status: corev1.ConditionFalse,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    false,
		},
		{
			name: "groupmem-cond-exists-equal",
			existingConds: []corev1a2.GroupCondition{
				{
					Type:   corev1a2.GroupMembersComputed,
					Status: corev1.ConditionTrue,
				},
			},
			checkStatus: corev1.ConditionTrue,
			expValue:    true,
		},
		{
			name: "groupmem-cond-not-exists-not-equal",
			existingConds: []corev1a2.GroupCondition{
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
			inCond := corev1a2.GroupCondition{
				Type:   corev1a2.GroupMembersComputed,
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
		Selector: toGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:  "uid3",
		Name: "cgC",
		ServiceReference: &controlplane.ServiceReference{
			Name:      "svc2",
			Namespace: "test",
		},
		// Selector is out of sync with latest service spec, but the CG should still be returned.
		Selector: toGroupSelector("test", nil, nil, nil),
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
			toGroupSelector(metav1.NamespaceDefault, &selectorSpec, nil, nil),
		},
		{
			"service-match-name-and-namespace",
			svc2,
			grp2,
			toGroupSelector("test", &selectorSpec, nil, nil),
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
			sel := npc.serviceToGroupSelector(tt.toProcess, tt.group)
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
			PodIP: "10.10.1.1",
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
			PodIP: "10.10.1.2",
		},
	},
}

var externalEntities = []*corev1a2.ExternalEntity{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ee1",
			Namespace: "test-ns",
			UID:       "uid3",
			Labels:    map[string]string{"app": "meh"},
		},
		Spec: corev1a2.ExternalEntitySpec{
			Endpoints: []corev1a2.Endpoint{
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
		Spec: corev1a2.ExternalEntitySpec{
			Endpoints: []corev1a2.Endpoint{
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
		UID:  "groupUID1",
		Name: "group1",
		Selector: &antreatypes.GroupSelector{
			Namespace: "test-ns",
		},
		GroupMembers: controlplane.GroupMemberSet{
			"groupMemberkey1": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod1",
					Namespace: "test-ns",
				},
			},
		},
	},
	{
		UID:  "groupUID2",
		Name: "group2",
		Selector: &antreatypes.GroupSelector{
			Namespace: "test-ns",
		},
		GroupMembers: controlplane.GroupMemberSet{
			"groupMemberKey1": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod1",
					Namespace: "test-ns",
				},
			},
			"groupMemberKey2": &controlplane.GroupMember{
				Pod: &controlplane.PodReference{
					Name:      "pod2",
					Namespace: "test-ns",
				},
			},
		},
	},
	{
		UID:  "groupUID3",
		Name: "group3",
		Selector: &antreatypes.GroupSelector{
			Namespace: "test-ns",
		},
		GroupMembers: controlplane.GroupMemberSet{
			"groupMemberKey3": &controlplane.GroupMember{
				ExternalEntity: &controlplane.ExternalEntityReference{
					Name:      "ee1",
					Namespace: "test-ns",
				},
			},
		},
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
			[]antreatypes.Group{groups[0], groups[1]},
		},
		{
			"single-group-association",
			groups,
			"pod2",
			"test-ns",
			[]antreatypes.Group{groups[1]},
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
		npc.podStore.Add(testPods[i])
	}
	for j := range externalEntities {
		npc.externalEntityStore.Add(externalEntities[j])
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.existingGroups {
				npc.internalGroupStore.Create(&tt.existingGroups[i])
			}
			groups, err := npc.GetAssociatedGroups(tt.queryName, tt.queryNamespace)
			assert.Equal(t, err, nil)
			assert.ElementsMatch(t, tt.expectedGroups, groups)
		})
	}
}

func TestGetGroupMembers(t *testing.T) {
	_, npc := newController()
	for i := range groups {
		npc.internalGroupStore.Create(&groups[i])
	}
	for j := range groups {
		members, err := npc.GetGroupMembers(groups[j].Name)
		assert.Equal(t, err, nil)
		assert.Equal(t, members, groups[j].GroupMembers)
	}
}

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
				Selector: *toGroupSelector("", nil, &selectorA, nil),
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
				Selector: *toGroupSelector("", &selectorB, nil, nil),
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
				Selector: *toGroupSelector("", &selectorC, &selectorD, nil),
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
				Selector: *toGroupSelector("", nil, &selectorA, nil),
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
				Selector: *toGroupSelector("", &selectorB, nil, nil),
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
				Selector: *toGroupSelector("", &selectorC, &selectorD, nil),
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
				Selector: *toGroupSelector("", nil, &selectorB, nil),
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
				Selector: *toGroupSelector("", &selectorC, nil, nil),
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
				Selector: *toGroupSelector("", &selectorC, &selectorD, nil),
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
		Selector: *toGroupSelector("", &selectorSpec, nil, nil),
	}
	grp2 := &antreatypes.Group{
		UID:      "uid2",
		Name:     "cgB",
		Selector: *toGroupSelector("", nil, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:      "uid3",
		Name:     "cgC",
		Selector: *toGroupSelector("", nil, &selectorSpec, nil),
	}
	grp4 := &antreatypes.Group{
		UID:      "uid4",
		Name:     "cgD",
		Selector: *toGroupSelector("", &selectorSpec, &selectorSpec, nil),
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
		Selector: *toGroupSelector("", &selectorSpec, nil, nil),
	}
	grp2 := &antreatypes.Group{
		UID:      "uid2",
		Name:     "cgB",
		Selector: *toGroupSelector("", nil, nil, nil),
	}
	grp3 := &antreatypes.Group{
		UID:      "uid3",
		Name:     "cgC",
		Selector: *toGroupSelector("", nil, &selectorSpec, nil),
	}
	grp4 := &antreatypes.Group{
		UID:      "uid4",
		Name:     "cgD",
		Selector: *toGroupSelector("", &selectorSpec, &selectorSpec, nil),
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

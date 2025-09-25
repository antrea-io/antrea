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

package grouping

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/types"
)

const (
	groupType1 GroupType = "fakeGroup1"
	groupType2 GroupType = "fakeGroup2"
)

var (
	// Fake Pods
	podFoo1                 = newPod("default", "podFoo1", map[string]string{"app": "foo"})
	podFoo1OnNode           = newPodOnNode("default", "podFoo1", "nodeFoo", map[string]string{"app": "foo"})
	podFoo2OnNode           = newPodOnNode("default", "podFoo2", "nodeFoo", map[string]string{"app": "foo"})
	podFoo2                 = newPod("default", "podFoo2", map[string]string{"app": "foo"})
	podBar1                 = newPod("default", "podBar1", map[string]string{"app": "bar"})
	podFoo1InOtherNamespace = newPod("other", "podFoo1", map[string]string{"app": "foo"})
	// Fake ExternalEntities
	eeFoo1                 = newExternalEntity("default", "eeFoo1", map[string]string{"app": "foo"})
	eeFoo2                 = newExternalEntity("default", "eeFoo2", map[string]string{"app": "foo"})
	eeBar1                 = newExternalEntity("default", "eeBar1", map[string]string{"app": "bar"})
	eeFoo1InOtherNamespace = newExternalEntity("other", "eeFoo1", map[string]string{"app": "foo"})
	// Fake Namespaces
	nsDefault = newNamespace("default", map[string]string{"company": "default"})
	nsOther   = newNamespace("other", map[string]string{"company": "other"})
	// Fake Node
	nodeFoo         = newNode("nodeFoo", map[string]string{"node": "foo"})
	nodeFooModified = newNode("nodeFoo", map[string]string{"node": "foo-modified"})
	// Fake groups
	groupPodFooType1             = &group{groupType: groupType1, groupName: "groupPodFooType1", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil)}
	groupPodFooType2             = &group{groupType: groupType2, groupName: "groupPodFooType2", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil)}
	groupPodBarType1             = &group{groupType: groupType1, groupName: "groupPodBarType1", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bar"}}, nil, nil, nil)}
	groupEEFooType1              = &group{groupType: groupType1, groupName: "groupEEFooType1", groupSelector: types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil)}
	groupEEFooType2              = &group{groupType: groupType2, groupName: "groupEEFooType2", groupSelector: types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil)}
	groupPodFooAllNamespaceType1 = &group{groupType: groupType1, groupName: "groupPodFooAllNamespaceType1", groupSelector: types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil)}
	groupPodAllNamespaceType1    = &group{groupType: groupType1, groupName: "groupPodAllNamespaceType1", groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{}, nil, nil)}
	groupEEFooAllNamespaceType1  = &group{groupType: groupType1, groupName: "groupEEFooAllNamespaceType1", groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{}, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil)}
)

type group struct {
	groupType     GroupType
	groupName     string
	groupSelector *types.GroupSelector
}

func copyAndMutatePod(pod *v1.Pod, mutateFunc func(*v1.Pod)) *v1.Pod {
	newPod := pod.DeepCopy()
	mutateFunc(newPod)
	return newPod
}

func copyAndMutateExternalEntity(ee *v1alpha2.ExternalEntity, mutateFunc func(*v1alpha2.ExternalEntity)) *v1alpha2.ExternalEntity {
	newEE := ee.DeepCopy()
	mutateFunc(newEE)
	return newEE
}

func copyAndMutateNamespace(ns *v1.Namespace, mutateFunc func(*v1.Namespace)) *v1.Namespace {
	newNS := ns.DeepCopy()
	mutateFunc(newNS)
	return newNS
}

func newNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func newPod(namespace, name string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
}

func newPodOnNode(namespace, name, nodeName string, labels map[string]string) *v1.Pod {
	pod := newPod(namespace, name, labels)
	pod.Spec = v1.PodSpec{
		NodeName: nodeName,
	}

	return pod
}

func newNode(name string, labels map[string]string) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func newExternalEntity(namespace, name string, labels map[string]string) *v1alpha2.ExternalEntity {
	return &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
}

func TestGroupEntityIndexGetEntities(t *testing.T) {
	tests := []struct {
		name                     string
		existingPods             []*v1.Pod
		existingExternalEntities []*v1alpha2.ExternalEntity
		existingNamespaces       []*v1.Namespace
		existingNodes            []*v1.Node
		inputGroupSelector       *types.GroupSelector
		expectedPods             []*v1.Pod
		expectedExternalEntities []*v1alpha2.ExternalEntity
	}{
		{
			name:                     "nodeSelector",
			existingPods:             []*v1.Pod{podFoo1OnNode, podFoo2OnNode, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			existingNodes:            []*v1.Node{nodeFoo},
			inputGroupSelector:       types.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"node": "foo"}}),
			expectedPods:             []*v1.Pod{podFoo1OnNode, podFoo2OnNode},
		},
		{
			name:                     "namespace scoped pod selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
			expectedPods:             []*v1.Pod{podFoo1, podFoo2},
		},
		{
			name:                     "namespace scoped externalEntity selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil),
			expectedExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2},
		},
		{
			name:                     "cluster scoped pod selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil),
			expectedPods:             []*v1.Pod{podFoo1, podFoo2, podFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped externalEntity selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil),
			expectedExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped pod selector with namespaceSelector",
			existingNamespaces:       []*v1.Namespace{nsDefault, nsOther},
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil, nil),
			expectedPods:             []*v1.Pod{podFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped pod selector with namespaceSelector but no namespaces",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil, nil),
			expectedPods:             []*v1.Pod{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := NewGroupEntityIndex()

			if tt.existingNodes != nil {
				for _, node := range tt.existingNodes {
					index.AddNode(node)
				}
			}
			for _, pod := range tt.existingPods {
				index.AddPod(pod)
			}
			for _, ns := range tt.existingNamespaces {
				index.AddNamespace(ns)
			}
			for _, ee := range tt.existingExternalEntities {
				index.AddExternalEntity(ee)
			}
			index.AddGroup(groupType1, "group", tt.inputGroupSelector)

			pods, ees := index.GetEntities(groupType1, "group")
			assert.ElementsMatch(t, tt.expectedPods, pods)
			assert.ElementsMatch(t, tt.expectedExternalEntities, ees)
		})
	}
}

func TestGroupEntityIndexGetGroups(t *testing.T) {
	index := NewGroupEntityIndex()
	pods := []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace}
	externalEntities := []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace}
	namespaces := []*v1.Namespace{nsDefault, nsOther}
	groups := []*group{groupPodFooType1, groupPodFooType2, groupPodFooAllNamespaceType1, groupEEFooType1, groupEEFooType2, groupEEFooAllNamespaceType1}
	for _, pod := range pods {
		index.AddPod(pod)
	}
	for _, ee := range externalEntities {
		index.AddExternalEntity(ee)
	}
	for _, ns := range namespaces {
		index.AddNamespace(ns)
	}
	for _, group := range groups {
		index.AddGroup(group.groupType, group.groupName, group.groupSelector)
	}
	tests := []struct {
		name           string
		inputEntity    metav1.Object
		expectedGroups map[GroupType][]string
		expectedFound  bool
	}{
		{
			name:          "Pod matching groups",
			inputEntity:   podFoo1,
			expectedFound: true,
			expectedGroups: map[GroupType][]string{
				groupType1: {groupPodFooType1.groupName, groupPodFooAllNamespaceType1.groupName},
				groupType2: {groupPodFooType2.groupName},
			},
		},
		{
			name:          "ExternalEntity matching groups",
			inputEntity:   eeFoo1,
			expectedFound: true,
			expectedGroups: map[GroupType][]string{
				groupType1: {groupEEFooType1.groupName, groupEEFooAllNamespaceType1.groupName},
				groupType2: {groupEEFooType2.groupName},
			},
		},
		{
			name:           "Pod matching no groups",
			inputEntity:    podBar1,
			expectedFound:  true,
			expectedGroups: map[GroupType][]string{},
		},
		{
			name:           "ExternalEntity matching no groups",
			inputEntity:    eeBar1,
			expectedFound:  true,
			expectedGroups: map[GroupType][]string{},
		},
		{
			name: "Non-existing Pod",
			inputEntity: copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
				pod.Name = "non-existing-pod"
			}),
			expectedFound:  false,
			expectedGroups: nil,
		},
		{
			name: "Non-existing ExternalEntity",
			inputEntity: copyAndMutateExternalEntity(eeFoo1, func(ee *v1alpha2.ExternalEntity) {
				ee.Name = "non-existing-externalentity"
			}),
			expectedFound:  false,
			expectedGroups: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualGroups map[GroupType][]string
			var actualFound bool
			if _, ok := tt.inputEntity.(*v1.Pod); ok {
				actualGroups, actualFound = index.GetGroupsForPod(tt.inputEntity.GetNamespace(), tt.inputEntity.GetName())
			} else {
				actualGroups, actualFound = index.GetGroupsForExternalEntity(tt.inputEntity.GetNamespace(), tt.inputEntity.GetName())
			}
			assert.Equal(t, tt.expectedFound, actualFound)
			assert.Equal(t, len(tt.expectedGroups), len(actualGroups))
			for groupType, expected := range tt.expectedGroups {
				assert.ElementsMatch(t, expected, actualGroups[groupType])
			}
		})
	}
}

func TestGroupEntityIndexUpdateGroup(t *testing.T) {
	index := NewGroupEntityIndex()
	pods := []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace}
	externalEntities := []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace}
	namespaces := []*v1.Namespace{nsDefault}
	for _, pod := range pods {
		index.AddPod(pod)
	}
	for _, ee := range externalEntities {
		index.AddExternalEntity(ee)
	}
	for _, ns := range namespaces {
		index.AddNamespace(ns)
	}
	index.AddGroup(groupType1, "group1", types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil, nil))
	actualGroups, _ := index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType1: {"group1"}}, actualGroups)
	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{}, actualGroups)
	actualPods, actualExternalEntities := index.GetEntities(groupType1, "group1")
	assert.ElementsMatch(t, []*v1.Pod{podFoo1, podFoo2}, actualPods)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{}, actualExternalEntities)

	index.AddGroup(groupType1, "group1", types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil))
	actualGroups, _ = index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{}, actualGroups)
	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType1: {"group1"}}, actualGroups)
	actualPods, actualExternalEntities = index.GetEntities(groupType1, "group1")
	assert.ElementsMatch(t, []*v1.Pod{}, actualPods)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2}, actualExternalEntities)
}

func TestGroupEntityIndexDeleteGroup(t *testing.T) {
	index := NewGroupEntityIndex()
	pods := []*v1.Pod{podFoo1, podFoo2, podBar1}
	externalEntities := []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1}
	namespaces := []*v1.Namespace{nsDefault}
	groups := []*group{groupPodFooType1, groupPodFooType2, groupEEFooType1, groupEEFooType2}
	for _, pod := range pods {
		index.AddPod(pod)
	}
	for _, ee := range externalEntities {
		index.AddExternalEntity(ee)
	}
	for _, ns := range namespaces {
		index.AddNamespace(ns)
	}
	for _, group := range groups {
		index.AddGroup(group.groupType, group.groupName, group.groupSelector)
	}

	actualGroups, _ := index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType1: {groupPodFooType1.groupName}, groupType2: {groupPodFooType2.groupName}}, actualGroups)
	index.DeleteGroup(groupPodFooType1.groupType, groupPodFooType1.groupName)
	actualGroups, _ = index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType2: {groupPodFooType2.groupName}}, actualGroups)
	index.DeleteGroup(groupPodFooType2.groupType, groupPodFooType2.groupName)
	actualGroups, _ = index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{}, actualGroups)

	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType1: {groupEEFooType1.groupName}, groupType2: {groupEEFooType2.groupName}}, actualGroups)
	index.DeleteGroup(groupEEFooType1.groupType, groupEEFooType1.groupName)
	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType2: {groupEEFooType2.groupName}}, actualGroups)
	index.DeleteGroup(groupEEFooType2.groupType, groupEEFooType2.groupName)
	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{}, actualGroups)

	// Ensure all relevant data are cleaned up.
	assert.Empty(t, index.groupItems)
	assert.Empty(t, index.selectorItems)
	assert.Empty(t, index.selectorItemIndex[podEntityType])
	assert.Empty(t, index.selectorItemIndex[externalEntityType])
	for _, lItem := range index.labelItems {
		assert.Empty(t, lItem.selectorItemKeys)
	}
}

func TestGroupEntityIndexDeleteEntity(t *testing.T) {
	index := NewGroupEntityIndex()
	pods := []*v1.Pod{podFoo1, podFoo2}
	externalEntities := []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2}
	namespaces := []*v1.Namespace{nsDefault}
	groups := []*group{groupPodFooType1, groupPodFooType2, groupEEFooType1, groupEEFooType2}
	for _, pod := range pods {
		index.AddPod(pod)
	}
	for _, ee := range externalEntities {
		index.AddExternalEntity(ee)
	}
	for _, ns := range namespaces {
		index.AddNamespace(ns)
	}
	for _, group := range groups {
		index.AddGroup(group.groupType, group.groupName, group.groupSelector)
	}

	actualPods, _ := index.GetEntities(groupPodFooType1.groupType, groupPodFooType1.groupName)
	assert.ElementsMatch(t, []*v1.Pod{podFoo1, podFoo2}, actualPods)
	index.DeletePod(podFoo1)
	actualPods, _ = index.GetEntities(groupPodFooType1.groupType, groupPodFooType1.groupName)
	assert.ElementsMatch(t, []*v1.Pod{podFoo2}, actualPods)
	index.DeletePod(podFoo2)
	actualPods, _ = index.GetEntities(groupPodFooType1.groupType, groupPodFooType1.groupName)
	assert.ElementsMatch(t, []*v1.Pod{}, actualPods)

	_, actualExternalEntities := index.GetEntities(groupEEFooType1.groupType, groupEEFooType1.groupName)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2}, actualExternalEntities)
	index.DeleteExternalEntity(eeFoo1)
	_, actualExternalEntities = index.GetEntities(groupEEFooType1.groupType, groupEEFooType1.groupName)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{eeFoo2}, actualExternalEntities)
	index.DeleteExternalEntity(eeFoo2)
	_, actualExternalEntities = index.GetEntities(groupEEFooType1.groupType, groupEEFooType1.groupName)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{}, actualExternalEntities)

	// Ensure all relevant data are cleaned up.
	assert.Empty(t, index.entityItems)
	assert.Empty(t, index.labelItems)
	assert.Empty(t, index.labelItemIndex[podEntityType])
	assert.Empty(t, index.labelItemIndex[externalEntityType])
	for _, sItem := range index.selectorItems {
		assert.Empty(t, sItem.labelItemKeys)
	}
}

func TestGroupEntityIndexEventHandlers(t *testing.T) {
	tests := []struct {
		name                     string
		existingPods             []*v1.Pod
		existingNamespaces       []*v1.Namespace
		existingExternalEntities []*v1alpha2.ExternalEntity
		existingGroups           []*group
		inputEvent               func(*GroupEntityIndex)
		addedPod                 *v1.Pod
		deletedPod               *v1.Pod
		addedNamespace           *v1.Namespace
		expectedGroupsCalled     map[GroupType][]string
	}{
		{
			name:                     "add a new pod",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodBarType1, groupPodFooType2, groupPodFooAllNamespaceType1, groupEEFooType1},
			inputEvent:               func(i *GroupEntityIndex) { i.AddPod(podFoo2) },
			expectedGroupsCalled:     map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodFooAllNamespaceType1.groupName}, groupType2: {groupPodFooType2.groupName}},
		},
		{
			name:                     "update an existing pod's labels",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodBarType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Labels = map[string]string{"app": "bar", "tier": "backend"}
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodBarType1.groupName, groupPodFooAllNamespaceType1.groupName}},
		},
		{
			name:                     "update an existing pod's attributes",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodBarType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Status.PodIP = "2.2.2.2"
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodFooAllNamespaceType1.groupName, groupPodAllNamespaceType1.groupName}},
		},
		{
			name:                     "update an existing pod's labels and attributes",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodBarType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Labels = map[string]string{"app": "bar", "tier": "backend"}
					pod.Status.PodIP = "2.2.2.2"
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodBarType1.groupName, groupPodFooAllNamespaceType1.groupName, groupPodAllNamespaceType1.groupName}},
		},
		{
			name:                     "update an existing pod's annotations",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Annotations = map[string]string{"foo": "bar"}
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{},
		},
		{
			name:           "update an existing pod's phase to running",
			existingPods:   []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingGroups: []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Status.Phase = v1.PodRunning
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{},
		},
		{
			name:           "update an existing pod's phase to succeeded",
			existingPods:   []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingGroups: []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podFoo1, func(pod *v1.Pod) {
					pod.Status.Phase = v1.PodSucceeded
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodFooAllNamespaceType1.groupName, groupPodAllNamespaceType1.groupName}},
		},
		{
			name:           "update an existing pod's phase to failed",
			existingPods:   []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingGroups: []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupPodBarType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddPod(copyAndMutatePod(podBar1, func(pod *v1.Pod) {
					pod.Status.Phase = v1.PodFailed
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodBarType1.groupName, groupPodAllNamespaceType1.groupName}},
		},
		{
			name:                     "delete an existing pod",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.DeletePod(podFoo1)
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupPodFooType1.groupName, groupPodFooAllNamespaceType1.groupName, groupPodAllNamespaceType1.groupName}},
		},
		{
			name:                     "update an existing external entity's attributes",
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups:           []*group{groupPodFooType1, groupPodBarType1, groupPodFooAllNamespaceType1, groupEEFooType1, groupEEFooType2, groupPodAllNamespaceType1},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddExternalEntity(copyAndMutateExternalEntity(eeFoo1, func(ee *v1alpha2.ExternalEntity) {
					ee.Spec.ExternalNode = "new node"
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {groupEEFooType1.groupName}, groupType2: {groupEEFooType2.groupName}},
		},
		{
			name:                     "update an existing namespace's labels",
			existingNamespaces:       []*v1.Namespace{nsDefault, nsOther},
			existingPods:             []*v1.Pod{podFoo1, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeBar1, eeFoo1InOtherNamespace},
			existingGroups: []*group{groupPodFooType1, groupPodFooAllNamespaceType1, groupPodAllNamespaceType1, {
				groupType:     groupType1,
				groupName:     "groupCompanyDefault",
				groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{MatchLabels: nsDefault.Labels}, nil, nil),
			},
				{
					groupType:     groupType1,
					groupName:     "groupCompanyOther",
					groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil, nil),
				}},
			inputEvent: func(i *GroupEntityIndex) {
				i.AddNamespace(copyAndMutateNamespace(nsDefault, func(namespace *v1.Namespace) {
					namespace.Labels["company"] = "other"
				}))
			},
			expectedGroupsCalled: map[GroupType][]string{groupType1: {"groupCompanyDefault", "groupCompanyOther"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			index := NewGroupEntityIndex()
			go index.Run(stopCh)

			var lock sync.Mutex
			actualGroupsCalled := map[GroupType][]string{}
			for groupType := range tt.expectedGroupsCalled {
				index.AddEventHandler(groupType, func(gType GroupType) eventHandler {
					return func(group string) {
						lock.Lock()
						defer lock.Unlock()
						actualGroupsCalled[gType] = append(actualGroupsCalled[gType], group)
					}
				}(groupType))
			}
			for _, pod := range tt.existingPods {
				index.AddPod(pod)
			}
			for _, ns := range tt.existingNamespaces {
				index.AddNamespace(ns)
			}
			for _, ee := range tt.existingExternalEntities {
				index.AddExternalEntity(ee)
			}
			for _, group := range tt.existingGroups {
				index.AddGroup(group.groupType, group.groupName, group.groupSelector)
			}
			tt.inputEvent(index)

			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				lock.Lock()
				defer lock.Unlock()
				if !assert.Equal(t, len(tt.expectedGroupsCalled), len(actualGroupsCalled)) {
					// If the lengths don't match, don't bother checking the contents, return early.
					return
				}
				for groupType, expected := range tt.expectedGroupsCalled {
					assert.ElementsMatch(t, expected, actualGroupsCalled[groupType])
				}
			}, 1*time.Second, 50*time.Millisecond)
		})
	}
}

func TestDeleteGroup(t *testing.T) {
	t.Run("Group with nodeSelector", func(t *testing.T) {
		index := NewGroupEntityIndex()
		index.AddNode(nodeFoo)
		index.AddPod(podFoo1OnNode)
		nodeSelectorGroup := types.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"node": "foo"}})
		index.AddGroup(groupType1, "group1", nodeSelectorGroup)
		index.DeleteGroup(groupType1, "group1")
		assert.Equal(t, 0, len(index.nodeLabelItems["node/node=foo"].selectorItemKeys))
	})
}

func TestCreateNodeLabelItems(t *testing.T) {
	t.Run("nodeLabelItem is added to the Index", func(t *testing.T) {
		groupEntityIndex := NewGroupEntityIndex()
		testLabels := labels.Set{"some-node": "red"}
		labelItemKey := getNodeLabelItemKey(testLabels)
		testEntityItem := &entityItem{
			entity: podFoo1,
		}

		nodeLabelItem := groupEntityIndex.createNodeLabelItem(testEntityItem, testLabels)
		assert.Equal(t, groupEntityIndex.nodeLabelItems[labelItemKey], nodeLabelItem)
	})
	t.Run("when label item exists", func(t *testing.T) {
		t.Run("nodeLabelItem is not duplicated on the index", func(t *testing.T) {
			groupEntityIndex := NewGroupEntityIndex()
			testLabels := labels.Set{"some-node": "red"}
			testEntityItem := &entityItem{
				entity: podFoo1,
			}
			testEntityItem2 := &entityItem{
				entity: podFoo2,
			}

			groupEntityIndex.createNodeLabelItem(testEntityItem, testLabels)
			groupEntityIndex.createNodeLabelItem(testEntityItem2, testLabels)
			assert.Equal(t, len(groupEntityIndex.nodeLabelItems), 1)
		})
		t.Run("nodeLabelItem is updated with multiple links to pods", func(t *testing.T) {
			groupEntityIndex := NewGroupEntityIndex()
			testLabels := labels.Set{"some-node": "red"}
			testEntityItem := &entityItem{
				entity: podFoo1,
			}
			testEntityItem2 := &entityItem{
				entity: podFoo2,
			}

			groupEntityIndex.createNodeLabelItem(testEntityItem, testLabels)
			updatedNodeLabelItem := groupEntityIndex.createNodeLabelItem(testEntityItem2, testLabels)
			assert.Equal(t, len(updatedNodeLabelItem.entityItemKeys), 2)
		})
	})
	t.Run("nodeLabelItem links back to pod", func(t *testing.T) {
		groupEntityIndex := NewGroupEntityIndex()
		nodeLabels := labels.Set{"node": "foo"}
		testEntityItem := &entityItem{
			entity: podFoo1OnNode,
		}
		entityItemKey := getEntityItemKey(podEntityType, podFoo1)

		nodeLabelItem := groupEntityIndex.createNodeLabelItem(testEntityItem, nodeLabels)
		assert.Contains(t, nodeLabelItem.entityItemKeys, entityItemKey)
	})
	t.Run("nodeLabelItem links to matching selector item", func(t *testing.T) {
		groupEntityIndex := NewGroupEntityIndex()
		testLabels := map[string]string{"some-node": "red"}
		testEntityItem := &entityItem{
			entity: podFoo1,
		}
		labelSelector := metav1.LabelSelector{
			MatchLabels: testLabels,
		}
		selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
		selectorNormalizedName := "selector-normalized-name"
		groupSelector := &types.GroupSelector{
			NormalizedName: selectorNormalizedName,
			NodeSelector:   selector,
		}
		groupItem := &groupItem{
			groupType:       groupType1,
			name:            "group-node-label",
			selector:        groupSelector,
			selectorItemKey: getSelectorItemKey(groupSelector),
		}
		groupEntityIndex.createSelectorItem(groupItem)
		groupEntityIndex.selectorItemIndex[podEntityType][emptyNamespace] = sets.New[string](selectorNormalizedName)

		nodeLabelItem := groupEntityIndex.createNodeLabelItem(testEntityItem, testLabels)
		assert.Contains(t, nodeLabelItem.selectorItemKeys, selectorNormalizedName)
	})
}

func TestCreateSelectorItem(t *testing.T) {
	t.Run("when NodeSelector is set", func(t *testing.T) {
		t.Run("when matching labelItems exists", func(t *testing.T) {
			t.Run("selectorItem links to matching label item and vice versa", func(t *testing.T) {
				groupEntityIndex := NewGroupEntityIndex()
				testLabels := map[string]string{"some-node": "red"}
				labelItemKey := getNodeLabelItemKey(testLabels)
				testEntityItem := &entityItem{
					entity:       podFoo1,
					labelItemKey: labelItemKey,
				}
				nodeLabelItem := groupEntityIndex.createNodeLabelItem(testEntityItem, testLabels)

				labelSelector := metav1.LabelSelector{
					MatchLabels: testLabels,
				}
				selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
				selectorNormalizedName := "selector-normalized-name"
				groupSelector := &types.GroupSelector{
					NormalizedName: selectorNormalizedName,
					NodeSelector:   selector,
				}
				groupItem := &groupItem{
					groupType:       groupType1,
					name:            "group-node-label",
					selector:        groupSelector,
					selectorItemKey: getSelectorItemKey(groupSelector),
				}
				selectorItem := groupEntityIndex.createSelectorItem(groupItem)
				assert.Contains(t, selectorItem.labelItemKeys, labelItemKey)
				assert.Contains(t, nodeLabelItem.selectorItemKeys, selectorNormalizedName)
			})
		})
	})
}

func TestAddNode(t *testing.T) {
	t.Run("nodeLabels contains new node", func(t *testing.T) {
		index := NewGroupEntityIndex()
		index.AddNode(nodeFoo)
		assert.Contains(t, index.nodeLabels, "nodeFoo")
		assert.Equal(t, index.nodeLabels["nodeFoo"], labels.Set(labels.Set{"node": "foo"}))
	})
	t.Run("nodeLabels is unchanged when node is readded", func(t *testing.T) {
		index := NewGroupEntityIndex()
		index.AddNode(nodeFoo)
		index.AddNode(nodeFoo)
		assert.Contains(t, index.nodeLabels, "nodeFoo")
		assert.Equal(t, len(index.nodeLabels), 1)
		assert.Equal(t, index.nodeLabels["nodeFoo"], labels.Set(labels.Set{"node": "foo"}))
	})
	t.Run("nodeLabels is updated when node is readded with new labels", func(t *testing.T) {
		index := NewGroupEntityIndex()
		index.AddNode(nodeFoo)
		index.AddNode(nodeFooModified)
		assert.Contains(t, index.nodeLabels, "nodeFoo")
		assert.Equal(t, len(index.nodeLabels), 1)
		assert.Equal(t, index.nodeLabels["nodeFoo"], labels.Set(labels.Set{"node": "foo-modified"}))
	})
}

func TestDeleteNode(t *testing.T) {
	t.Run("node is removed from index", func(t *testing.T) {
		index := NewGroupEntityIndex()
		index.AddNode(nodeFoo)
		index.DeleteNode(nodeFoo)
		assert.NotContains(t, index.nodeLabels, "nodeFoo")
	})
}

func TestAddPod(t *testing.T) {
	t.Run("nodeLabelItemKey is on the entity", func(t *testing.T) {
		index := NewGroupEntityIndex()
		nodeLabel := map[string]string{"node": "foo"}
		nodeLabelItemKey := getNodeLabelItemKey(nodeLabel)
		entityItemKey := getEntityItemKey(podEntityType, podFoo1OnNode)
		index.AddNode(nodeFoo)

		index.AddPod(podFoo1OnNode)
		assert.Equal(t, index.entityItems[entityItemKey].nodeLabelItemKey, nodeLabelItemKey)
	})
	t.Run("existing group is synced with Pod", func(t *testing.T) {
		index := NewGroupEntityIndex()
		nodeLabel := map[string]string{"node": "foo"}

		labelSelector := metav1.LabelSelector{
			MatchLabels: nodeLabel,
		}
		selector, _ := metav1.LabelSelectorAsSelector(&labelSelector)
		selectorNormalizedName := "selector-normalized-name"
		groupSelector := &types.GroupSelector{
			NormalizedName: selectorNormalizedName,
			NodeSelector:   selector,
		}
		groupItem := &groupItem{
			groupType:       groupType1,
			name:            "group-node-label",
			selector:        groupSelector,
			selectorItemKey: getSelectorItemKey(groupSelector),
		}
		selectorItem := index.createSelectorItem(groupItem)

		index.AddNode(nodeFoo)
		index.AddPod(podFoo1OnNode)

		assert.Equal(t, len(selectorItem.labelItemKeys), 1)
	})
}

func TestDeletePod(t *testing.T) {
	t.Run("when a single pod is linked to a nodeLabelItem", func(t *testing.T) {
		t.Run("the nodeLabelItem is removed from nodeLabelItems", func(t *testing.T) {
			index := NewGroupEntityIndex()
			testLabels := labels.Set{"node": "foo"}
			labelItemKey := getNodeLabelItemKey(testLabels)
			index.AddPod(podFoo1OnNode)

			index.DeletePod(podFoo1)
			assert.NotContains(t, index.nodeLabelItems, labelItemKey)
		})
		t.Run("matched selector items remove their link to the nodeLabelItem", func(t *testing.T) {
			index := NewGroupEntityIndex()
			index.AddNode(nodeFoo)
			index.AddPod(podFoo1OnNode)
			nodeFooLabel := map[string]string{"node": "foo"}
			nodeSelectorGroup := types.NewGroupSelector("", nil, nil, nil, &metav1.LabelSelector{MatchLabels: nodeFooLabel})
			index.AddGroup(groupType1, "group1", nodeSelectorGroup)

			index.DeletePod(podFoo1OnNode)
			assert.NotContains(t, index.selectorItems[nodeSelectorGroup.NormalizedName].labelItemKeys, getNodeLabelItemKey(nodeFooLabel))
		})
	})
	t.Run("when multiple pods are linked to a nodeLabelItem", func(t *testing.T) {
		t.Run("the nodeLabelItem is not removed from nodeLabelItems", func(t *testing.T) {
			index := NewGroupEntityIndex()
			testLabels := labels.Set{"node": "foo"}
			labelItemKey := getNodeLabelItemKey(testLabels)
			index.AddNode(nodeFoo)
			index.AddPod(podFoo1OnNode)
			index.AddPod(podFoo2OnNode)

			index.DeletePod(podFoo1)
			assert.Contains(t, index.nodeLabelItems, labelItemKey)
		})
		t.Run("nodeLabelItem's link to the entity is removed", func(t *testing.T) {
			index := NewGroupEntityIndex()
			testLabels := labels.Set{"node": "foo"}
			labelItemKey := getNodeLabelItemKey(testLabels)
			index.AddNode(nodeFoo)
			index.AddPod(podFoo1OnNode)
			index.AddPod(podFoo2OnNode)
			nodeLabelItem := index.nodeLabelItems[labelItemKey]

			index.DeletePod(podFoo1OnNode)
			assert.Equal(t, len(nodeLabelItem.entityItemKeys), 1)
		})
	})
}

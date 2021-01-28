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

	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

const (
	groupType1 GroupType = "fakeGroup1"
	groupType2 GroupType = "fakeGroup2"
)

var (
	// Fake Pods
	podFoo1                 = newPod("default", "podFoo1", map[string]string{"app": "foo"})
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
	// Fake groups
	groupPodFooType1             = &group{groupType: groupType1, groupName: "groupPodFooType1", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil)}
	groupPodFooType2             = &group{groupType: groupType2, groupName: "groupPodFooType2", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil)}
	groupPodBarType1             = &group{groupType: groupType1, groupName: "groupPodBarType1", groupSelector: types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bar"}}, nil, nil)}
	groupEEFooType1              = &group{groupType: groupType1, groupName: "groupEEFooType1", groupSelector: types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}})}
	groupEEFooType2              = &group{groupType: groupType2, groupName: "groupEEFooType2", groupSelector: types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}})}
	groupPodFooAllNamespaceType1 = &group{groupType: groupType1, groupName: "groupPodFooAllNamespaceType1", groupSelector: types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil)}
	groupPodAllNamespaceType1    = &group{groupType: groupType1, groupName: "groupPodAllNamespaceType1", groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{}, nil)}
	groupEEFooAllNamespaceType1  = &group{groupType: groupType1, groupName: "groupEEFooAllNamespaceType1", groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{}, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}})}
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
		inputGroupSelector       *types.GroupSelector
		expectedPods             []*v1.Pod
		expectedExternalEntities []*v1alpha2.ExternalEntity
	}{
		{
			name:                     "namespace scoped pod selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil),
			expectedPods:             []*v1.Pod{podFoo1, podFoo2},
		},
		{
			name:                     "namespace scoped externalEntity selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}),
			expectedExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2},
		},
		{
			name:                     "cluster scoped pod selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil),
			expectedPods:             []*v1.Pod{podFoo1, podFoo2, podFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped externalEntity selector",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}),
			expectedExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped pod selector with namespaceSelector",
			existingNamespaces:       []*v1.Namespace{nsDefault, nsOther},
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil),
			expectedPods:             []*v1.Pod{podFoo1InOtherNamespace},
		},
		{
			name:                     "cluster scoped pod selector with namespaceSelector but no namespaces",
			existingPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			existingExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			inputGroupSelector:       types.NewGroupSelector("", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil),
			expectedPods:             []*v1.Pod{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index := NewGroupEntityIndex()

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
	index.AddGroup(groupType1, "group1", types.NewGroupSelector("default", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}, nil, nil))
	actualGroups, _ := index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
	assert.Equal(t, map[GroupType][]string{groupType1: {"group1"}}, actualGroups)
	actualGroups, _ = index.GetGroupsForExternalEntity(eeFoo1.Namespace, eeFoo1.Name)
	assert.Equal(t, map[GroupType][]string{}, actualGroups)
	actualPods, actualExternalEntities := index.GetEntities(groupType1, "group1")
	assert.ElementsMatch(t, []*v1.Pod{podFoo1, podFoo2}, actualPods)
	assert.ElementsMatch(t, []*v1alpha2.ExternalEntity{}, actualExternalEntities)

	index.AddGroup(groupType1, "group1", types.NewGroupSelector("default", nil, nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}}))
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
				groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{MatchLabels: nsDefault.Labels}, nil),
			},
				{
					groupType:     groupType1,
					groupName:     "groupCompanyOther",
					groupSelector: types.NewGroupSelector("", nil, &metav1.LabelSelector{MatchLabels: nsOther.Labels}, nil),
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

			time.Sleep(100 * time.Millisecond)
			lock.Lock()
			defer lock.Unlock()
			assert.Equal(t, len(tt.expectedGroupsCalled), len(actualGroupsCalled))
			for groupType, expected := range tt.expectedGroupsCalled {
				assert.ElementsMatch(t, expected, actualGroupsCalled[groupType])
			}
		})
	}
}

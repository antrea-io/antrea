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
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

const informerDefaultResync = 30 * time.Second

func TestGroupEntityControllerRun(t *testing.T) {
	tests := []struct {
		name                    string
		initialPods             []*v1.Pod
		initialExternalEntities []*v1alpha2.ExternalEntity
		initialNamespaces       []*v1.Namespace
		initialGroups           []*group
		antreaPolicyEnabled     bool
	}{
		{
			name:                    "AntreaPolicy enabled",
			initialPods:             []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			initialExternalEntities: []*v1alpha2.ExternalEntity{eeFoo1, eeFoo2, eeBar1, eeFoo1InOtherNamespace},
			initialNamespaces:       []*v1.Namespace{nsDefault, nsOther},
			initialGroups:           []*group{groupPodFooType1, groupPodFooType2, groupPodFooAllNamespaceType1, groupEEFooType1, groupEEFooType2, groupEEFooAllNamespaceType1},
			antreaPolicyEnabled:     true,
		},
		{
			name:                "AntreaPolicy disabled",
			initialPods:         []*v1.Pod{podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace},
			initialNamespaces:   []*v1.Namespace{nsDefault, nsOther},
			initialGroups:       []*group{groupPodFooType1, groupPodFooType2, groupPodFooAllNamespaceType1},
			antreaPolicyEnabled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Even with only 1 buffer, the code should work as expected - as opposed to hanging somewhere.
			originalEventChanSize := eventChanSize
			eventChanSize = 1
			defer func() {
				eventChanSize = originalEventChanSize
			}()

			var objs []runtime.Object
			for _, pod := range tt.initialPods {
				objs = append(objs, pod)
			}
			for _, namespace := range tt.initialNamespaces {
				objs = append(objs, namespace)
			}
			var crdObjs []runtime.Object
			for _, externalEntity := range tt.initialExternalEntities {
				crdObjs = append(crdObjs, externalEntity)
			}
			index := NewGroupEntityIndex()
			for _, group := range tt.initialGroups {
				index.AddGroup(group.groupType, group.groupName, group.groupSelector)
			}
			client := fake.NewSimpleClientset(objs...)
			crdClient := fakeversioned.NewSimpleClientset(crdObjs...)
			informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
			crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
			stopCh := make(chan struct{})
			defer close(stopCh)

			c := NewGroupEntityController(index, informerFactory.Core().V1().Pods(), informerFactory.Core().V1().Namespaces(), crdInformerFactory.Crd().V1alpha2().ExternalEntities())
			assert.False(t, index.HasSynced(), "GroupEntityIndex has been synced before starting InformerFactories")

			informerFactory.Start(stopCh)
			crdInformerFactory.Start(stopCh)
			assert.False(t, index.HasSynced(), "GroupEntityIndex has been synced before starting GroupEntityController")
			go c.groupEntityIndex.Run(stopCh)
			go c.Run(stopCh)

			assert.Eventually(t, func() bool {
				return index.HasSynced()
			}, time.Second, 10*time.Millisecond, "GroupEntityIndex hasn't been synced in 1 second after starting GroupEntityController")
		})
	}
}

func TestGroupEntityControllerHandlePodUpdate(t *testing.T) {
	var objs []runtime.Object
	initialPods := []*v1.Pod{podFoo1, podFoo2, podBar1}
	initialNamespaces := []*v1.Namespace{nsDefault, nsOther}
	initialGroups := []*group{groupPodFooType1, groupPodFooType2, groupPodBarType1, groupPodFooAllNamespaceType1}
	for _, pod := range initialPods {
		objs = append(objs, pod)
	}
	for _, namespace := range initialNamespaces {
		objs = append(objs, namespace)
	}
	index := NewGroupEntityIndex()
	for _, group := range initialGroups {
		index.AddGroup(group.groupType, group.groupName, group.groupSelector)
	}

	client := fake.NewSimpleClientset(objs...)
	crdClient := fakeversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	stopCh := make(chan struct{})
	defer close(stopCh)

	c := NewGroupEntityController(index, informerFactory.Core().V1().Pods(), informerFactory.Core().V1().Namespaces(), crdInformerFactory.Crd().V1alpha2().ExternalEntities())
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)
	go c.groupEntityIndex.Run(stopCh)
	go c.Run(stopCh)
	// Wait for the GroupEntityIndex to be synced
	require.Eventually(t, func() bool {
		return index.HasSynced()
	}, time.Second, 10*time.Millisecond, "GroupEntityIndex hasn't been synced in 1 second after starting GroupEntityController")

	podFoo1Succeeded := podFoo1.DeepCopy()
	podFoo1Succeeded.Status.Phase = v1.PodSucceeded
	client.CoreV1().Pods("default").Update(context.TODO(), podFoo1Succeeded, metav1.UpdateOptions{})
	podFoo2Failed := podFoo2.DeepCopy()
	podFoo2Failed.Status.Phase = v1.PodFailed
	client.CoreV1().Pods("default").Update(context.TODO(), podFoo2Failed, metav1.UpdateOptions{})
	podBar1Running := podBar1.DeepCopy()
	podBar1Running.Status.Phase = v1.PodRunning
	client.CoreV1().Pods("default").Update(context.TODO(), podBar1Running, metav1.UpdateOptions{})

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// The following two Foo Pods should be removed from all groups as they are terminated
		_, groupForFoo1Found := index.GetGroupsForPod(podFoo1.Namespace, podFoo1.Name)
		assert.False(t, groupForFoo1Found, "Succeeded Pod should be removed from the GroupEntityIndex")
		_, groupForFoo2Found := index.GetGroupsForPod(podFoo2.Namespace, podFoo2.Name)
		assert.False(t, groupForFoo2Found, "Failed Pod should be removed from the GroupEntityIndex")
		// The following Bar Pod should still remain in the group that selects it
		_, groupForBar1Found := index.GetGroupsForPod(podBar1.Namespace, podBar1.Name)
		assert.True(t, groupForBar1Found, "Running Pod should remain in the GroupEntityIndex")
	}, time.Second, 10*time.Millisecond, "GroupEntityIndex did not process Pod update event correctly")
}

func TestPodIPsIndexFunc(t *testing.T) {
	type args struct {
		obj interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name:    "invalid input",
			args:    args{obj: &struct{}{}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "nil IPs",
			args:    args{obj: &v1.Pod{}},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "zero IPs",
			args:    args{obj: &v1.Pod{Status: v1.PodStatus{PodIPs: []v1.PodIP{}}}},
			want:    nil,
			wantErr: false,
		},
		{
			name: "PodFailed with podIPs",
			args: args{
				obj: &v1.Pod{
					Status: v1.PodStatus{
						PodIPs: []v1.PodIP{{IP: "1.2.3.4"}, {IP: "aaaa::bbbb"}},
						Phase:  v1.PodFailed,
					},
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "PodRunning with podIPs",
			args: args{
				obj: &v1.Pod{
					Status: v1.PodStatus{
						PodIPs: []v1.PodIP{{IP: "1.2.3.4"}, {IP: "aaaa::bbbb"}},
						Phase:  v1.PodRunning,
					},
				},
			},
			want:    []string{"1.2.3.4", "aaaa::bbbb"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PodIPsIndexFunc(tt.args.obj)
			if (err != nil) != tt.wantErr {
				t.Errorf("podIPsIndexFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("podIPsIndexFunc() got = %v, want %v", got, tt.want)
			}
		})
	}
}

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

package egress

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	corev1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/egress/store"
	"antrea.io/antrea/pkg/controller/grouping"
)

var (
	node1 = "node1"
	node2 = "node2"
	node3 = "node3"
	// Fake Pods
	podFoo1                 = newPod("default", "podFoo1", map[string]string{"app": "foo"}, node1, "1.1.1.1")
	podFoo2                 = newPod("default", "podFoo2", map[string]string{"app": "foo"}, node2, "1.1.2.1")
	podBar1                 = newPod("default", "podBar1", map[string]string{"app": "bar"}, node1, "1.1.1.2")
	podFoo1InOtherNamespace = newPod("other", "podFoo1", map[string]string{"app": "foo"}, node1, "1.1.1.3")
	podUnscheduled          = newPod("default", "podUnscheduled", map[string]string{"app": "foo"}, "", "")
	podNonIP                = newPod("default", "podNonIP", map[string]string{"app": "foo"}, "node1", "")
	// Fake Namespaces
	nsDefault = newNamespace("default", map[string]string{"company": "default"})
	nsOther   = newNamespace("other", map[string]string{"company": "other"})
)

func newNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

func newPod(namespace, name string, labels map[string]string, nodeName string, ip string) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			NodeName: nodeName,
		},
	}
	if len(ip) > 0 {
		pod.Status.PodIP = ip
		pod.Status.PodIPs = []v1.PodIP{{IP: ip}}
	}
	return pod
}

type egressController struct {
	*EgressController
	client             kubernetes.Interface
	crdClient          versioned.Interface
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
	groupingController *grouping.GroupEntityController
}

// objects is an initial set of K8s objects that is exposed through the client.
func newController(objects ...runtime.Object) *egressController {
	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	egressGroupStore := store.NewEgressGroupStore()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupingController := grouping.NewGroupEntityController(groupEntityIndex,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		crdInformerFactory.Crd().V1alpha2().ExternalEntities())
	controller := NewEgressController(groupEntityIndex, egressInformer, egressGroupStore)
	return &egressController{
		controller,
		client,
		crdClient,
		informerFactory,
		crdInformerFactory,
		groupingController,
	}
}

func TestAddEgress(t *testing.T) {
	tests := []struct {
		name                 string
		inputEgress          *v1alpha2.Egress
		expectedEgressGroups map[string]*controlplane.EgressGroup
	}{
		{
			name: "Egress with podSelector and namespaceSelector",
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					AppliedTo: corev1a2.AppliedTo{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "foo"},
						},
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: nsDefault.Labels,
						},
					},
					EgressIP: "1.1.1.1",
				},
			},
			expectedEgressGroups: map[string]*controlplane.EgressGroup{
				node1: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo1.Name, Namespace: podFoo1.Namespace}},
					},
				},
				node2: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo2.Name, Namespace: podFoo2.Namespace}},
					},
				},
				node3: nil,
			},
		},
		{
			name: "Egress with namespaceSelector",
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					AppliedTo: corev1a2.AppliedTo{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: nsDefault.Labels,
						},
					},
					EgressIP: "1.1.1.1",
				},
			},
			expectedEgressGroups: map[string]*controlplane.EgressGroup{
				node1: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo1.Name, Namespace: podFoo1.Namespace}},
						{Pod: &controlplane.PodReference{Name: podBar1.Name, Namespace: podBar1.Namespace}},
					},
				},
				node2: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo2.Name, Namespace: podFoo2.Namespace}},
					},
				},
				node3: nil,
			},
		},
		{
			name: "Egress with podSelector",
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					AppliedTo: corev1a2.AppliedTo{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "foo"},
						},
					},
					EgressIP: "1.1.1.1",
				},
			},
			expectedEgressGroups: map[string]*controlplane.EgressGroup{
				node1: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo1.Name, Namespace: podFoo1.Namespace}},
						{Pod: &controlplane.PodReference{Name: podFoo1InOtherNamespace.Name, Namespace: podFoo1InOtherNamespace.Namespace}},
					},
				},
				node2: {
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					GroupMembers: []controlplane.GroupMember{
						{Pod: &controlplane.PodReference{Name: podFoo2.Name, Namespace: podFoo2.Namespace}},
					},
				},
				node3: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeObjects []runtime.Object
			fakeObjects = append(fakeObjects, nsDefault, nsOther)
			fakeObjects = append(fakeObjects, podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace, podUnscheduled, podNonIP)
			controller := newController(fakeObjects...)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.groupingInterface.Run(stopCh)
			go controller.groupingController.Run(stopCh)
			go controller.Run(stopCh)

			controller.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), tt.inputEgress, metav1.CreateOptions{})

			for nodeName, expectedEgressGroup := range tt.expectedEgressGroups {
				watcher, err := controller.egressGroupStore.Watch(context.TODO(), "", nil, fields.ParseSelectorOrDie(fmt.Sprintf("nodeName=%s", nodeName)))
				assert.NoError(t, err)
				gotEgressGroup := func() *controlplane.EgressGroup {
					for {
						select {
						case <-stopCh:
							return nil
						case <-time.After(500 * time.Millisecond):
							return nil
						case event := <-watcher.ResultChan():
							if event.Type == watch.Added {
								return event.Object.(*controlplane.EgressGroup)
							}
						}
					}
				}()

				if expectedEgressGroup == nil {
					assert.Nil(t, gotEgressGroup)
				} else {
					require.NotNil(t, gotEgressGroup)
					assert.Equal(t, expectedEgressGroup.ObjectMeta, gotEgressGroup.ObjectMeta)
					assert.ElementsMatch(t, expectedEgressGroup.GroupMembers, gotEgressGroup.GroupMembers)
				}
			}
		})
	}
}

func TestUpdateEgress(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	controller := newController(nsDefault, podFoo1)
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.groupingInterface.Run(stopCh)
	go controller.groupingController.Run(stopCh)
	go controller.Run(stopCh)

	egress := &v1alpha2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec: v1alpha2.EgressSpec{
			AppliedTo: corev1a2.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "foo"},
				},
			},
			EgressIP: "1.1.1.1",
		},
	}
	controller.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})

	watcher, err := controller.egressGroupStore.Watch(context.TODO(), "", nil, fields.ParseSelectorOrDie(fmt.Sprintf("nodeName=%s", node1)))
	assert.NoError(t, err)

	getEvent := func() *watch.Event {
		for {
			select {
			case <-stopCh:
				return nil
			case <-time.After(500 * time.Millisecond):
				return nil
			case event := <-watcher.ResultChan():
				if event.Type != watch.Bookmark {
					return &event
				}
			}
		}
	}

	assert.Equal(t, &watch.Event{
		Type: watch.Added,
		Object: &controlplane.EgressGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
			GroupMembers: []controlplane.GroupMember{
				{Pod: &controlplane.PodReference{Name: podFoo1.Name, Namespace: podFoo1.Namespace}},
			},
		},
	}, getEvent())

	// Add a Pod matching the Egress's selector and running on this Node.
	controller.client.CoreV1().Pods(podFoo1InOtherNamespace.Namespace).Create(context.TODO(), podFoo1InOtherNamespace, metav1.CreateOptions{})
	assert.Equal(t, &watch.Event{
		Type: watch.Modified,
		Object: &controlplane.EgressGroupPatch{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
			AddedGroupMembers: []controlplane.GroupMember{
				{Pod: &controlplane.PodReference{Name: podFoo1InOtherNamespace.Name, Namespace: podFoo1InOtherNamespace.Namespace}},
			},
		},
	}, getEvent())

	// Delete the above Pod.
	controller.client.CoreV1().Pods(podFoo1InOtherNamespace.Namespace).Delete(context.TODO(), podFoo1InOtherNamespace.Name, metav1.DeleteOptions{})
	assert.Equal(t, &watch.Event{
		Type: watch.Modified,
		Object: &controlplane.EgressGroupPatch{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
			RemovedGroupMembers: []controlplane.GroupMember{
				{Pod: &controlplane.PodReference{Name: podFoo1InOtherNamespace.Name, Namespace: podFoo1InOtherNamespace.Namespace}},
			},
		},
	}, getEvent())

	// Updating the Egress's spec to make it match no Pods on this Node.
	egress.Spec.AppliedTo = corev1a2.AppliedTo{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "non-existing-app"},
		},
	}
	controller.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	assert.Equal(t, &watch.Event{
		Type: watch.Deleted,
		Object: &controlplane.EgressGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		},
	}, getEvent())
}

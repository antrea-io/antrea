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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
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
	// Fake ExternalIPPools
	eipFoo1 = newExternalIPPool("pool1", "1.1.1.0/24", "", "")
	eipFoo2 = newExternalIPPool("pool2", "", "2.2.2.10", "2.2.2.20")
)

func newEgress(name, egressIP, externalIPPool string, podSelector, namespaceSelector *metav1.LabelSelector) *v1alpha2.Egress {
	egress := &v1alpha2.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha2.EgressSpec{
			AppliedTo: corev1a2.AppliedTo{
				PodSelector:       podSelector,
				NamespaceSelector: namespaceSelector,
			},
			EgressIP:       egressIP,
			ExternalIPPool: externalIPPool,
		},
	}
	return egress
}

func newExternalIPPool(name, cidr, start, end string) *v1alpha2.ExternalIPPool {
	pool := &v1alpha2.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if len(cidr) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, corev1a2.IPRange{CIDR: cidr})
	}
	if len(start) > 0 && len(end) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, corev1a2.IPRange{Start: start, End: end})
	}
	return pool
}

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
func newController(objects, crdObjects []runtime.Object) *egressController {
	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	egressGroupStore := store.NewEgressGroupStore()
	egressInformer := crdInformerFactory.Crd().V1alpha2().Egresses()
	externalIPPoolInformer := crdInformerFactory.Crd().V1alpha2().ExternalIPPools()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupingController := grouping.NewGroupEntityController(groupEntityIndex,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		crdInformerFactory.Crd().V1alpha2().ExternalEntities())
	controller := NewEgressController(crdClient, groupEntityIndex, egressInformer, externalIPPoolInformer, egressGroupStore)
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
		expectedEgressIP     string
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
			expectedEgressIP: "1.1.1.1",
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
			expectedEgressIP: "1.1.1.1",
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
			expectedEgressIP: "1.1.1.1",
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
		{
			name: "Egress with podSelector and empty EgressIP",
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					AppliedTo: corev1a2.AppliedTo{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "foo"},
						},
					},
					EgressIP:       "",
					ExternalIPPool: eipFoo1.Name,
				},
			},
			expectedEgressIP: "1.1.1.1",
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
			var fakeCRDObjects []runtime.Object
			fakeCRDObjects = append(fakeCRDObjects, eipFoo1)
			controller := newController(fakeObjects, fakeCRDObjects)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.groupingController.Run(stopCh)
			go controller.Run(stopCh)

			controller.crdClient.CrdV1alpha2().Egresses().Create(context.TODO(), tt.inputEgress, metav1.CreateOptions{})

			for nodeName, expectedEgressGroup := range tt.expectedEgressGroups {
				watcher, err := controller.egressGroupStore.Watch(context.TODO(), "", nil, fields.ParseSelectorOrDie(fmt.Sprintf("nodeName=%s", nodeName)))
				require.NoError(t, err)
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

			gotEgress, err := controller.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), tt.inputEgress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedEgressIP, gotEgress.Spec.EgressIP)
		})
	}
}

func TestUpdateEgress(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)
	controller := newController([]runtime.Object{nsDefault, podFoo1}, []runtime.Object{eipFoo1, eipFoo2})
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
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
			EgressIP:       "",
			ExternalIPPool: eipFoo1.Name,
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

	gotEgressIP := func() string {
		var err error
		egress, err = controller.crdClient.CrdV1alpha2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
		if err != nil {
			return ""
		}
		return egress.Spec.EgressIP
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
	assert.Equal(t, "1.1.1.1", gotEgressIP())
	checkExternalIPPoolUsed(t, controller, eipFoo1.Name, 1)

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

	// Updating the Egress's spec to make it match no Pods on this Node and use a new ExternalIPPool.
	egress.Spec.AppliedTo = corev1a2.AppliedTo{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "non-existing-app"},
		},
	}
	egress.Spec.ExternalIPPool = eipFoo2.Name
	egress.Spec.EgressIP = ""
	controller.crdClient.CrdV1alpha2().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	assert.Equal(t, &watch.Event{
		Type: watch.Deleted,
		Object: &controlplane.EgressGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		},
	}, getEvent())
	assert.Equal(t, "2.2.2.10", gotEgressIP())
	checkExternalIPPoolUsed(t, controller, eipFoo1.Name, 0)
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 1)

	// Delete the IPPool in use. The EgressIP should be released.
	controller.crdClient.CrdV1alpha2().ExternalIPPools().Delete(context.TODO(), eipFoo2.Name, metav1.DeleteOptions{})
	err = wait.PollImmediate(50*time.Millisecond, 1*time.Second, func() (found bool, err error) {
		_, _, exists := controller.getIPAllocation(egress.Name)
		return !exists, nil
	})
	assert.NoError(t, err, "IP allocation was not deleted after the ExternalIPPool was deleted")
	_, exists := controller.getIPAllocator(eipFoo2.Name)
	assert.False(t, exists, "IP allocator was not deleted after the ExternalIPPool was deleted")
	assert.Equal(t, "", gotEgressIP(), "EgressIP was not deleted after the ExternalIPPool was deleted")

	// Recreate the ExternalIPPool. An EgressIP should be allocated.
	controller.crdClient.CrdV1alpha2().ExternalIPPools().Create(context.TODO(), eipFoo2, metav1.CreateOptions{})
	err = wait.PollImmediate(50*time.Millisecond, 1*time.Second, func() (found bool, err error) {
		_, _, exists := controller.getIPAllocation(egress.Name)
		return exists, nil
	})
	assert.NoError(t, err, "IP was not allocated after the ExternalIPPool was created")
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 1)

	// Delete the Egress. The EgressIP should be released.
	controller.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
	err = wait.PollImmediate(50*time.Millisecond, 1*time.Second, func() (found bool, err error) {
		_, _, exists := controller.getIPAllocation(egress.Name)
		return !exists, nil
	})
	assert.NoError(t, err, "IP allocation was not deleted after the Egress was deleted")
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 0)
}

func TestSyncEgressIP(t *testing.T) {
	tests := []struct {
		name                       string
		existingEgresses           []*v1alpha2.Egress
		existingExternalIPPool     *v1alpha2.ExternalIPPool
		inputEgress                *v1alpha2.Egress
		expectedEgressIP           string
		expectedExternalIPPoolUsed int
		expectErr                  bool
	}{
		{
			name: "Egress with empty EgressIP and existing ExternalIPPool",
			existingEgresses: []*v1alpha2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.1",
						ExternalIPPool: "ipPoolA",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			// The first IPRange 1.1.1.0/30 should be occupied by the existing Egresses. The input Egress's IP should
			// be allocated from the second IPRange 1.1.2.10-1.1.2.20.
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/30", "1.1.2.10", "1.1.2.20"),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "1.1.2.10",
			expectedExternalIPPoolUsed: 3,
			expectErr:                  false,
		},
		{
			name:                   "Egress with empty EgressIP and non-existing ExternalIPPool",
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "",
					ExternalIPPool: "ipPoolB",
				},
			},
			expectedEgressIP:           "",
			expectedExternalIPPoolUsed: 0,
			expectErr:                  true,
		},
		{
			name:                   "Egress with non-empty EgressIP and proper ExternalIPPool",
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "1.1.1.2",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "1.1.1.2",
			expectedExternalIPPoolUsed: 1,
			expectErr:                  false,
		},
		{
			name:                   "Egress with non-empty EgressIP and improper ExternalIPPool",
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "1.1.2.2",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "",
			expectedExternalIPPoolUsed: 0,
			expectErr:                  true,
		},
		{
			name: "Egress with updated EgressIP",
			existingEgresses: []*v1alpha2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "1.1.1.3",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "1.1.1.3",
			expectedExternalIPPoolUsed: 1,
			expectErr:                  false,
		},
		{
			name: "Egress with unchanged EgressIP",
			existingEgresses: []*v1alpha2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "1.1.1.2",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "1.1.1.2",
			expectedExternalIPPoolUsed: 1,
			expectErr:                  false,
		},
		{
			name: "Egress with conflicting EgressIP",
			existingEgresses: []*v1alpha2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec: v1alpha2.EgressSpec{
					EgressIP:       "1.1.1.2",
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "",
			expectedExternalIPPoolUsed: 1,
			expectErr:                  true,
		},
		{
			name: "Egress with empty ExternalIPPool",
			existingEgresses: []*v1alpha2.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1alpha2.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1alpha2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1alpha2.EgressSpec{
					EgressIP: "10.10.10.10",
				},
			},
			expectedEgressIP:           "10.10.10.10",
			expectedExternalIPPoolUsed: 0,
			expectErr:                  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var fakeObjects []runtime.Object
			fakeObjects = append(fakeObjects, tt.inputEgress)
			controller := newController(nil, fakeObjects)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			controller.createOrUpdateIPAllocator(tt.existingExternalIPPool)
			for _, egress := range tt.existingEgresses {
				controller.updateIPAllocation(egress)
			}
			gotEgressIP, err := controller.syncEgressIP(tt.inputEgress)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, net.ParseIP(tt.expectedEgressIP), gotEgressIP)
			checkExternalIPPoolUsed(t, controller, tt.existingExternalIPPool.Name, tt.expectedExternalIPPoolUsed)
		})
	}
}

func checkExternalIPPoolUsed(t *testing.T, controller *egressController, poolName string, used int) {
	ipAllocator, exists := controller.getIPAllocator(poolName)
	require.True(t, exists)
	assert.Equal(t, used, ipAllocator.Used())
}

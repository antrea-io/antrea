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
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	"antrea.io/antrea/v2/pkg/controller/egress/store"
	"antrea.io/antrea/v2/pkg/controller/externalippool"
	"antrea.io/antrea/v2/pkg/controller/grouping"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

var (
	node1 = "node1"
	node2 = "node2"
	node3 = "node3"
	// Fake Pods
	podFoo1                 = newPod("default", "podFoo1", map[string]string{"app": "foo"}, node1, "1.1.1.1", false)
	podFoo2                 = newPod("default", "podFoo2", map[string]string{"app": "foo"}, node2, "1.1.2.1", false)
	podBar1                 = newPod("default", "podBar1", map[string]string{"app": "bar"}, node1, "1.1.1.2", false)
	podFoo1InOtherNamespace = newPod("other", "podFoo1", map[string]string{"app": "foo"}, node1, "1.1.1.3", false)
	podUnscheduled          = newPod("default", "podUnscheduled", map[string]string{"app": "foo"}, "", "", false)
	podNonIP                = newPod("default", "podNonIP", map[string]string{"app": "foo"}, node1, "", false)
	podWithHostNetwork      = newPod("default", "podHostNetwork", map[string]string{"app": "bar"}, node1, "172.16.100.1", true)
	// Fake Namespaces
	nsDefault = newNamespace("default", map[string]string{"company": "default"})
	nsOther   = newNamespace("other", map[string]string{"company": "other"})
	// Fake ExternalIPPools
	eipFoo1 = newExternalIPPool("pool1", "1.1.1.0/24", "", "")
	eipFoo2 = newExternalIPPool("pool2", "", "2.2.2.10", "2.2.2.20")
)

func newEgress(name, egressIP, externalIPPool string, podSelector, namespaceSelector *metav1.LabelSelector, bandwidth *v1beta1.Bandwidth) *v1beta1.Egress {
	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector:       podSelector,
				NamespaceSelector: namespaceSelector,
			},
			EgressIP:       egressIP,
			ExternalIPPool: externalIPPool,
			Bandwidth:      bandwidth,
		},
	}
	return egress
}

func newExternalIPPool(name, cidr, start, end string) *v1beta1.ExternalIPPool {
	pool := &v1beta1.ExternalIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	if len(cidr) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, v1beta1.IPRange{CIDR: cidr})
	}
	if len(start) > 0 && len(end) > 0 {
		pool.Spec.IPRanges = append(pool.Spec.IPRanges, v1beta1.IPRange{Start: start, End: end})
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

func newPod(namespace, name string, labels map[string]string, nodeName string, ip string, hostNetwork bool) *v1.Pod {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
		Spec: v1.PodSpec{
			NodeName:    nodeName,
			HostNetwork: hostNetwork,
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
	client              kubernetes.Interface
	crdClient           versioned.Interface
	informerFactory     informers.SharedInformerFactory
	crdInformerFactory  crdinformers.SharedInformerFactory
	groupingController  *grouping.GroupEntityController
	externalIPAllocator *externalippool.ExternalIPPoolController
}

// objects is an initial set of K8s objects that is exposed through the client.
func newController(objects, crdObjects []runtime.Object) *egressController {
	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)
	// These reactors are in charge of incrementing Generation for Egress resources, so that
	// changes done through crdClient are not ignored by the EgressController.
	egressUpdateReactor, egressPatchReactor := func() (k8stesting.ReactionFunc, k8stesting.ReactionFunc) {
		// We use a map to ensure different generation counters for different Egress
		// resources. We do not reset the map when a resource is deleted and re-created with
		// the same name as it is not necessary for tests (it could easily be done with
		// delete & create reactors).
		generation := map[string]int64{}
		updateReactor := func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			ua := action.(k8stesting.UpdateAction)
			egress := ua.GetObject().(*v1beta1.Egress)
			generation[egress.Name] += 1
			egress.Generation = generation[egress.Name]
			return false, egress, nil
		}
		patchReactor := func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			pa := action.(k8stesting.PatchActionImpl)
			patchType := pa.GetPatchType()
			// This is the only patch type we support, and the only one used in the
			// Egress controller.
			if patchType != types.MergePatchType {
				return true, nil, fmt.Errorf("unsupported patch type: %v", patchType)
			}
			patch := map[string]interface{}{}
			json.Unmarshal(pa.GetPatch(), &patch)
			name := pa.GetName()
			generation[name] += 1
			patch["metadata"] = map[string]interface{}{
				"generation": generation[name],
			}
			pa.Patch, _ = json.Marshal(patch)
			// Because action is an object and not a pointer, we cannot mutate it
			// directly. So we need the following to apply our updated patch.
			return k8stesting.ObjectReaction(crdClient.Tracker())(pa)
		}
		return updateReactor, patchReactor
	}()
	crdClient.PrependReactor("update", "egresses", egressUpdateReactor)
	crdClient.PrependReactor("patch", "egresses", egressPatchReactor)
	informerFactory := informers.NewSharedInformerFactory(client, resyncPeriod)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	externalIPAllocator := externalippool.NewExternalIPPoolController(crdClient, crdInformerFactory.Crd().V1beta1().ExternalIPPools())
	egressGroupStore := store.NewEgressGroupStore()
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	groupingController := grouping.NewGroupEntityController(groupEntityIndex,
		informerFactory.Core().V1().Pods(),
		informerFactory.Core().V1().Namespaces(),
		crdInformerFactory.Crd().V1alpha2().ExternalEntities())
	controller := NewEgressController(crdClient, groupEntityIndex, egressInformer, externalIPAllocator, egressGroupStore)
	return &egressController{
		controller,
		client,
		crdClient,
		informerFactory,
		crdInformerFactory,
		groupingController,
		externalIPAllocator,
	}
}

func TestAddEgress(t *testing.T) {
	podSucceeded := newPod("default", "succeeded-pod", map[string]string{"app": "foo"}, node1, "1.1.5.1", false)
	podSucceeded.Status.Phase = v1.PodSucceeded
	podFailed := newPod("default", "failed-pod", map[string]string{"app": "foo"}, node1, "1.1.5.2", false)
	podFailed.Status.Phase = v1.PodFailed

	tests := []struct {
		name                 string
		inputEgress          *v1beta1.Egress
		expectedEgressIP     string
		expectedEgressGroups map[string]*controlplane.EgressGroup
	}{
		{
			name: "Egress with podSelector and namespaceSelector",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					AppliedTo: v1beta1.AppliedTo{
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
						{Pod: &controlplane.PodReference{Name: podNonIP.Name, Namespace: podNonIP.Namespace}},
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
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					AppliedTo: v1beta1.AppliedTo{
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
						{Pod: &controlplane.PodReference{Name: podNonIP.Name, Namespace: podNonIP.Namespace}},
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
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					AppliedTo: v1beta1.AppliedTo{
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
						{Pod: &controlplane.PodReference{Name: podNonIP.Name, Namespace: podNonIP.Namespace}},
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
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					AppliedTo: v1beta1.AppliedTo{
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
						{Pod: &controlplane.PodReference{Name: podNonIP.Name, Namespace: podNonIP.Namespace}},
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
			fakeObjects = append(fakeObjects, podFoo1, podFoo2, podBar1, podFoo1InOtherNamespace, podUnscheduled, podNonIP, podWithHostNetwork, podSucceeded, podFailed)
			var fakeCRDObjects []runtime.Object
			fakeCRDObjects = append(fakeCRDObjects, eipFoo1)
			controller := newController(fakeObjects, fakeCRDObjects)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			go controller.groupingInterface.Run(stopCh)
			go controller.groupingController.Run(stopCh)
			go controller.Run(stopCh)

			controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), tt.inputEgress, metav1.CreateOptions{})

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

			gotEgress, err := controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), tt.inputEgress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedEgressIP, gotEgress.Spec.EgressIP)
			if gotEgress.Spec.ExternalIPPool != "" && gotEgress.Spec.EgressIP != "" {
				checkExternalIPPoolUsed(t, controller, gotEgress.Spec.ExternalIPPool, 1)
			}
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
	go controller.externalIPAllocator.Run(stopCh)
	require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
	go controller.groupingInterface.Run(stopCh)
	go controller.groupingController.Run(stopCh)
	go controller.Run(stopCh)

	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "foo"},
				},
			},
			EgressIP:       "",
			ExternalIPPool: eipFoo1.Name,
		},
	}
	controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})

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

	getEgressIP := func() string {
		var err error
		egress, err = controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
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
	assert.Equal(t, "1.1.1.1", getEgressIP())
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
	egress.Spec.AppliedTo = v1beta1.AppliedTo{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "non-existing-app"},
		},
	}
	egress.Spec.ExternalIPPool = eipFoo2.Name
	egress.Spec.EgressIP = ""
	controller.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), egress, metav1.UpdateOptions{})
	assert.Equal(t, &watch.Event{
		Type: watch.Deleted,
		Object: &controlplane.EgressGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		},
	}, getEvent())
	assert.Equal(t, "2.2.2.10", getEgressIP())
	checkExternalIPPoolUsed(t, controller, eipFoo1.Name, 0)
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 1)

	// Delete the IPPool in use. The EgressIP should be released.
	controller.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), eipFoo2.Name, metav1.DeleteOptions{})
	assert.Eventually(t, func() bool {
		_, _, exists := controller.getIPAllocation(egress.Name)
		if exists {
			return false
		}
		ip := getEgressIP()
		return ip == ""
	}, time.Second, 50*time.Millisecond, "EgressIP was not deleted after the ExternalIPPool was deleted")

	// Recreate the ExternalIPPool. An EgressIP should be allocated.
	controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eipFoo2, metav1.CreateOptions{})
	assert.Eventually(t, func() bool {
		_, _, exists := controller.getIPAllocation(egress.Name)
		return exists
	}, time.Second, 50*time.Millisecond, "IP was not allocated after the ExternalIPPool was created")
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 1)

	// Delete the Egress. The EgressIP should be released.
	controller.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})
	assert.Eventually(t, func() bool {
		_, _, exists := controller.getIPAllocation(egress.Name)
		return !exists
	}, time.Second, 50*time.Millisecond, "IP allocation was not deleted after the Egress was deleted")
	checkExternalIPPoolUsed(t, controller, eipFoo2.Name, 0)
}

// TestRecreateExternalIPPoolWithNewRange tests the case where an ExternalIPPool is deleted, then
// immediately recreated with a different IP range. Specifically we test the scenario where
// syncEgress / syncEgressIP are called only once because the DELETE and CREATE events are merged in
// the workqueue. Ideally, the behavior observed by the user should be the same irrespective of
// whether the events are merged or not.
// Note that in an actual cluster, it is very unlikely that both events would be merged.
func TestRecreateExternalIPPoolWithNewRange(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	eipFoo1 := newExternalIPPool("pool1", "1.1.1.0/24", "", "")
	egress := &v1beta1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec: v1beta1.EgressSpec{
			AppliedTo: v1beta1.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "foo"},
				},
			},
			EgressIP:       "",
			ExternalIPPool: eipFoo1.Name,
		},
	}

	controller := newController(nil, []runtime.Object{eipFoo1, egress})
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.externalIPAllocator.Run(stopCh)
	require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
	controller.restoreIPAllocations([]*v1beta1.Egress{egress})

	require.True(t, controller.externalIPAllocator.IPPoolExists(eipFoo1.Name))
	getEgressIP, egress, err := controller.syncEgressIP(egress)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("1.1.1.1"), getEgressIP)

	// Delete and recreate the ExternalIPPool immediately with a different IP range. We do not
	// call syncEgressIP in-between, so the Egress controller doesn't have a chance to process
	// both changes independently.
	controller.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), eipFoo1.Name, metav1.DeleteOptions{})
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.False(t, controller.externalIPAllocator.IPPoolExists(eipFoo1.Name))
	}, 1*time.Second, 10*time.Millisecond)

	eipFoo1 = newExternalIPPool("pool1", "1.1.2.0/24", "", "")
	controller.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), eipFoo1, metav1.CreateOptions{})
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.True(t, controller.externalIPAllocator.IPPoolExists(eipFoo1.Name))
	}, 1*time.Second, 10*time.Millisecond)

	getEgressIP, _, err = controller.syncEgressIP(egress)
	require.NoError(t, err)
	assert.Equal(t, net.ParseIP("1.1.2.1"), getEgressIP)
}

func TestRecreateExternalIPPoolWithNewGateway(t *testing.T) {
	for _, tt := range []struct {
		name       string
		gateway    string
		newGateway string
		initialIPs []string
		wantIPs    []string
	}{
		{
			name: "single allocation", gateway: "192.0.2.1", newGateway: "192.0.2.2",
			initialIPs: []string{"192.0.2.2"}, wantIPs: []string{"192.0.2.1"},
		},
		{
			name: "multiple allocations with unchanged gateway", gateway: "192.0.2.6", newGateway: "192.0.2.6",
			initialIPs: []string{"192.0.2.1", "192.0.2.2"}, wantIPs: []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name: "multiple allocations with new gateway", gateway: "192.0.2.6", newGateway: "192.0.2.1",
			initialIPs: []string{"192.0.2.1", "192.0.2.2"}, wantIPs: []string{"192.0.2.3", "192.0.2.2"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			pool := newExternalIPPool("pool", "192.0.2.0/29", "", "")
			pool.UID = "old"
			pool.Spec.SubnetInfo = &v1beta1.SubnetInfo{Gateway: tt.gateway, PrefixLength: 29}
			egresses := []*v1beta1.Egress{
				newEgress("egress-a", "", pool.Name, nil, nil, nil),
				newEgress("egress-b", "", pool.Name, nil, nil, nil),
			}[:len(tt.initialIPs)]
			objects := []runtime.Object{pool}
			for _, egress := range egresses {
				objects = append(objects, egress)
			}
			c := newController(nil, objects)
			// The fake client does not enforce resource versions. Prevent a stale status
			// update from replacing the recreated pool's spec, which a real API server rejects.
			c.crdClient.(*fakeversioned.Clientset).PrependReactor("update", "externalippools",
				func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.GetSubresource() == "status" {
						return true, action.(k8stesting.UpdateAction).GetObject(), nil
					}
					return false, nil, nil
				})
			c.informerFactory.Start(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			go c.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, c.externalIPAllocator.HasSynced))
			c.restoreIPAllocations(egresses)
			for i, egress := range egresses {
				ip, updated, err := c.syncEgressIP(egress)
				require.NoError(t, err)
				require.Equal(t, tt.initialIPs[i], ip.String())
				egresses[i] = updated
			}

			// Process both pool events before reconciling Egresses, as when work items coalesce.
			require.NoError(t, c.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{}))
			require.Eventually(t, func() bool {
				return !c.externalIPAllocator.IPPoolExists(pool.Name)
			}, time.Second, 10*time.Millisecond)
			recreated := pool.DeepCopy()
			recreated.UID = "new"
			recreated.Spec.SubnetInfo.Gateway = tt.newGateway
			_, err := c.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), recreated, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return c.externalIPAllocator.IPPoolExists(pool.Name)
			}, time.Second, 10*time.Millisecond)
			require.False(t, c.externalIPAllocator.IPPoolHasIP(pool.Name, net.ParseIP(tt.newGateway)))
			require.Error(t, c.externalIPAllocator.UpdateIPAllocation(pool.Name, net.ParseIP(tt.newGateway)))

			var ips []string
			for _, egress := range egresses {
				ip, updated, err := c.syncEgressIP(egress)
				require.NoError(t, err)
				assert.Equal(t, ip.String(), updated.Spec.EgressIP)
				allocatedIP, allocatedPool, exists := c.getIPAllocation(egress.Name)
				require.True(t, exists)
				assert.Equal(t, ip, allocatedIP)
				assert.Equal(t, pool.Name, allocatedPool)
				ips = append(ips, ip.String())
			}
			assert.Equal(t, tt.wantIPs, ips)
			for _, ip := range ips {
				require.Error(t, c.externalIPAllocator.UpdateIPAllocation(pool.Name, net.ParseIP(ip)),
					"consumer IP %s must remain allocated after pool recreation", ip)
			}
		})
	}
}

func TestSyncEgressIP(t *testing.T) {
	tests := []struct {
		name                       string
		existingEgresses           []*v1beta1.Egress
		existingExternalIPPool     *v1beta1.ExternalIPPool
		inputEgress                *v1beta1.Egress
		expectedEgressIP           string
		expectedExternalIPPoolUsed int
		expectErr                  bool
	}{
		{
			name: "Egress with empty EgressIP and existing ExternalIPPool",
			existingEgresses: []*v1beta1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.1",
						ExternalIPPool: "ipPoolA",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			// The first IPRange 1.1.1.0/30 should be occupied by the existing Egresses. The input Egress's IP should
			// be allocated from the second IPRange 1.1.2.10-1.1.2.20.
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/30", "1.1.2.10", "1.1.2.20"),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressC", UID: "uidC"},
				Spec: v1beta1.EgressSpec{
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
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					EgressIP:       "",
					ExternalIPPool: "ipPoolB",
				},
			},
			expectedEgressIP:           "",
			expectedExternalIPPoolUsed: 0,
			expectErr:                  true,
		},
		{
			name:                   "[IPv6]Egress with empty EgressIP and proper ExternalIPPool",
			existingExternalIPPool: newExternalIPPool("ipPoolA", "2021:2::aaa0/124", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					ExternalIPPool: "ipPoolA",
				},
			},
			expectedEgressIP:           "2021:2::aaa1",
			expectedExternalIPPoolUsed: 1,
			expectErr:                  false,
		},
		{
			name:                   "Egress with non-empty EgressIP and proper ExternalIPPool",
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
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
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
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
			existingEgresses: []*v1beta1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
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
			existingEgresses: []*v1beta1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
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
			existingEgresses: []*v1beta1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
				Spec: v1beta1.EgressSpec{
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
			existingEgresses: []*v1beta1.Egress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
					Spec: v1beta1.EgressSpec{
						EgressIP:       "1.1.1.2",
						ExternalIPPool: "ipPoolA",
					},
				},
			},
			existingExternalIPPool: newExternalIPPool("ipPoolA", "1.1.1.0/24", "", ""),
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
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
			fakeObjects = append(fakeObjects, tt.inputEgress, tt.existingExternalIPPool)
			controller := newController(nil, fakeObjects)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			controller.restoreIPAllocations(tt.existingEgresses)
			getEgressIP, _, err := controller.syncEgressIP(tt.inputEgress)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, net.ParseIP(tt.expectedEgressIP), getEgressIP)
			checkExternalIPPoolUsed(t, controller, tt.existingExternalIPPool.Name, tt.expectedExternalIPPoolUsed)
		})
	}
}

func checkExternalIPPoolUsed(t *testing.T, controller *egressController, poolName string, used int) {
	exists := controller.externalIPAllocator.IPPoolExists(poolName)
	require.True(t, exists)
	err := wait.PollUntilContextTimeout(context.Background(), 50*time.Millisecond, 2*time.Second, true,
		func(ctx context.Context) (found bool, err error) {
			eip, err := controller.crdClient.CrdV1beta1().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			return eip.Status.Usage.Used == used, nil
		})
	assert.NoError(t, err)
}

func TestUpdateEgressAllocatedCondition(t *testing.T) {
	tests := []struct {
		name           string
		inputEgress    *v1beta1.Egress
		inputErr       error
		expectedStatus v1beta1.EgressStatus
	}{
		{
			name: "allocating IP succeeds",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					EgressIP:       "1.1.1.1",
					ExternalIPPool: "pool1",
				},
			},
			expectedStatus: v1beta1.EgressStatus{
				Conditions: []v1beta1.EgressCondition{
					{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "allocating IP fails",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					ExternalIPPool: "pool1",
				},
			},
			inputErr: fmt.Errorf("no available IP"),
			expectedStatus: v1beta1.EgressStatus{
				Conditions: []v1beta1.EgressCondition{
					{Type: v1beta1.IPAllocated, Status: v1.ConditionFalse, Reason: "AllocationError", Message: "Cannot allocate EgressIP from ExternalIPPool: no available IP"},
				},
			},
		},
		{
			name: "specifying IP fails",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					EgressIP:       "1.1.1.1",
					ExternalIPPool: "pool1",
				},
			},
			inputErr: fmt.Errorf("IP already used"),
			expectedStatus: v1beta1.EgressStatus{
				Conditions: []v1beta1.EgressCondition{
					{Type: v1beta1.IPAllocated, Status: v1.ConditionFalse, Reason: "AllocationError", Message: "Cannot allocate EgressIP from ExternalIPPool: IP already used"},
				},
			},
		},
		{
			name: "updating condition succeeds",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					EgressIP:       "1.1.1.1",
					ExternalIPPool: "pool1",
				},
				Status: v1beta1.EgressStatus{
					Conditions: []v1beta1.EgressCondition{
						{Type: v1beta1.IPAllocated, Status: v1.ConditionFalse, Reason: "AllocationError", Message: "Cannot allocate EgressIP from ExternalIPPool: no available IP"},
					},
				},
			},
			expectedStatus: v1beta1.EgressStatus{
				Conditions: []v1beta1.EgressCondition{
					{Type: v1beta1.IPAllocated, Status: v1.ConditionTrue, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
				},
			},
		},
		{
			name: "removing condition succeeds",
			inputEgress: &v1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec: v1beta1.EgressSpec{
					EgressIP:       "1.1.1.1",
					ExternalIPPool: "", // ExternalIPPool is removed.
				},
				Status: v1beta1.EgressStatus{
					Conditions: []v1beta1.EgressCondition{
						{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully allocated"},
						{Type: v1beta1.IPAllocated, Status: v1.ConditionFalse, Reason: "Allocated", Message: "EgressIP is successfully allocated"},
					},
				},
			},
			expectedStatus: v1beta1.EgressStatus{
				Conditions: []v1beta1.EgressCondition{ // It should only delete IPAllocated condition.
					{Type: v1beta1.IPAssigned, Status: v1.ConditionTrue, Reason: "Assigned", Message: "EgressIP is successfully allocated"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController(nil, []runtime.Object{tt.inputEgress})
			controller.updateEgressAllocatedCondition(tt.inputEgress, tt.inputErr)
			gotEgress, err := controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), tt.inputEgress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.True(t, k8s.SemanticIgnoringTime.DeepEqual(tt.expectedStatus, gotEgress.Status), "Expected:\n%v\ngot:\n%v", tt.expectedStatus, gotEgress.Status)
		})
	}
}

func TestDeleteEgress_Tombstone(t *testing.T) {
	egress := newEgress("egressA", "", "", &metav1.LabelSelector{}, nil, nil)
	egress.UID = "uidA"
	controller := newController(nil, []runtime.Object{egress})

	// Simulate the controller having processed the Egress ADD event.
	controller.addEgress(egress)
	_, found, _ := controller.egressGroupStore.Get(egress.Name)
	require.True(t, found)

	// Deliver the delete as a cache.DeletedFinalStateUnknown tombstone, as the
	// informer does after a watch reconnect. This exercises the tombstone path
	// in deleteEgress rather than the direct *Egress type assertion.
	controller.deleteEgress(cache.DeletedFinalStateUnknown{
		Key: egress.Name,
		Obj: egress,
	})
}

func TestSyncUntrackedEgressAfterPoolRecreation(t *testing.T) {
	for _, tt := range []struct {
		name         string
		cidr         string
		gateway      string
		egressIP     string
		newGateway   string
		pendingIP    string
		wantIP       string
		prefixLength int32
		concurrent   bool
		uncached     bool
		wantErr      bool
	}{
		{
			name: "IPv4", cidr: "192.168.1.144/28", gateway: "192.168.1.145",
			egressIP: "192.168.1.146", newGateway: "192.168.1.146", prefixLength: 28,
			wantIP: "192.168.1.145",
		},
		{
			name: "IPv6", cidr: "2001:db8::/124", gateway: "2001:db8::1",
			egressIP: "2001:0db8:0000:0000:0000:0000:0000:0002", newGateway: "2001:db8::2", prefixLength: 124,
			wantIP: "2001:db8::1",
		},
		{
			name: "IPv4 with another pending Egress", cidr: "192.0.2.0/29", gateway: "192.0.2.6",
			egressIP: "192.0.2.1", newGateway: "192.0.2.1", pendingIP: "192.0.2.2", prefixLength: 29,
			wantIP: "192.0.2.3",
		},
		{
			name: "IPv6 with another pending Egress", cidr: "2001:db8::/125", gateway: "2001:db8::6",
			egressIP: "2001:db8::1", newGateway: "2001:db8::1", pendingIP: "2001:db8::2", prefixLength: 125,
			wantIP: "2001:db8::3",
		},
		{
			name: "IPv4 with concurrent reconciliation", cidr: "192.0.2.0/29", gateway: "192.0.2.6",
			egressIP: "192.0.2.1", newGateway: "192.0.2.1", pendingIP: "192.0.2.2", prefixLength: 29,
			wantIP: "192.0.2.3", concurrent: true,
		},
		{
			name: "IPv6 with concurrent reconciliation", cidr: "2001:db8::/125", gateway: "2001:db8::6",
			egressIP: "2001:db8::1", newGateway: "2001:db8::1", pendingIP: "2001:db8::2", prefixLength: 125,
			wantIP: "2001:db8::3", concurrent: true,
		},
		{
			name: "IPv4 with pending Egress absent from informer", cidr: "192.0.2.0/29", gateway: "192.0.2.6",
			egressIP: "192.0.2.1", newGateway: "192.0.2.1", pendingIP: "192.0.2.2", prefixLength: 29,
			wantIP: "192.0.2.3", uncached: true,
		},
		{
			name: "IPv4 with pool exhausted by pending Egress", cidr: "192.0.2.0/30", gateway: "192.0.2.6",
			egressIP: "192.0.2.1", newGateway: "192.0.2.1", pendingIP: "192.0.2.2", prefixLength: 29,
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool := newExternalIPPool("pool", tt.cidr, "", "")
			pool.UID = "old"
			pool.Spec.SubnetInfo = &v1beta1.SubnetInfo{Gateway: tt.gateway, PrefixLength: tt.prefixLength}
			c := newController(nil, []runtime.Object{pool})
			// Prevent stale status updates from replacing the recreated pool in the fake client.
			c.crdClient.(*fakeversioned.Clientset).PrependReactor("update", "externalippools",
				func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.GetSubresource() == "status" {
						return true, action.(k8stesting.UpdateAction).GetObject(), nil
					}
					return false, nil, nil
				})
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			go c.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, c.externalIPAllocator.HasSynced))
			c.externalIPAllocator.RestoreIPAllocations(nil)

			createEgress := func(name, ip string) *v1beta1.Egress {
				egress := newEgress(name, ip, pool.Name, nil, nil, nil)
				response := c.ValidateEgress(&admv1.AdmissionReview{Request: &admv1.AdmissionRequest{
					Operation: admv1.Create,
					Object:    runtime.RawExtension{Raw: marshal(egress)},
				}})
				require.True(t, response.Allowed, "the explicit IP must be valid before the pool is recreated")
				egress, err := c.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
				require.NoError(t, err)
				require.Eventually(t, func() bool {
					_, err := c.egressLister.Get(name)
					return err == nil
				}, time.Second, 10*time.Millisecond)
				return egress
			}
			egress := createEgress("egress", tt.egressIP)
			var pending *v1beta1.Egress
			if tt.pendingIP != "" {
				pending = createEgress("pending-egress", tt.pendingIP)
			}

			// Recreate the pool before the Egress's first allocation reconciliation.
			require.NoError(t, c.crdClient.CrdV1beta1().ExternalIPPools().Delete(context.TODO(), pool.Name, metav1.DeleteOptions{}))
			require.Eventually(t, func() bool {
				return !c.externalIPAllocator.IPPoolExists(pool.Name)
			}, time.Second, 10*time.Millisecond)
			recreated := pool.DeepCopy()
			recreated.UID = "new"
			recreated.Spec.SubnetInfo.Gateway = tt.newGateway
			_, err := c.crdClient.CrdV1beta1().ExternalIPPools().Create(context.TODO(), recreated, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return c.externalIPAllocator.IPPoolExists(pool.Name) &&
					!c.externalIPAllocator.IPPoolHasIP(pool.Name, net.ParseIP(tt.egressIP))
			}, time.Second, 10*time.Millisecond)
			_, _, exists := c.getIPAllocation(egress.Name)
			require.False(t, exists)
			if tt.uncached {
				require.NoError(t, c.crdInformerFactory.Crd().V1beta1().Egresses().Informer().GetIndexer().Delete(pending))
				_, err := c.egressLister.Get(pending.Name)
				require.Error(t, err)
			}

			var ip, pendingIP net.IP
			var updated, updatedPending *v1beta1.Egress
			if tt.concurrent {
				type syncResult struct {
					name   string
					ip     net.IP
					egress *v1beta1.Egress
					err    error
				}
				start := make(chan struct{})
				results := make(chan syncResult, 2)
				for _, candidate := range []*v1beta1.Egress{egress, pending} {
					go func(candidate *v1beta1.Egress) {
						<-start
						ip, updated, err := c.syncEgressIP(candidate)
						results <- syncResult{name: candidate.Name, ip: ip, egress: updated, err: err}
					}(candidate)
				}
				close(start)
				for i := 0; i < 2; i++ {
					select {
					case result := <-results:
						require.NoError(t, result.err, "concurrent reconciliation of %s must succeed", result.name)
						if result.name == egress.Name {
							ip, updated = result.ip, result.egress
						} else {
							pendingIP, updatedPending = result.ip, result.egress
						}
					case <-time.After(5 * time.Second):
						t.Fatal("Timed out waiting for concurrent Egress reconciliation")
					}
				}
			} else {
				ip, updated, err = c.syncEgressIP(egress)
				if tt.wantErr {
					require.Error(t, err)
					for i := 0; i < 2; i++ {
						require.Empty(t, updated.Spec.EgressIP)
						ip, updated, err = c.syncEgressIP(updated)
						require.Error(t, err, "retries after clearing the gateway must preserve the pending IP")
					}
				} else {
					require.NoError(t, err)
				}
				if pending != nil {
					pendingIP, updatedPending, err = c.syncEgressIP(pending)
					require.NoError(t, err, "repairing the gateway Egress must preserve the other Egress's valid IP")
				}
			}
			stored, err := c.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			allocatedIP, allocatedPool, exists := c.getIPAllocation(egress.Name)
			var egresses []*v1beta1.Egress
			if tt.wantErr {
				require.Nil(t, ip)
				require.Empty(t, stored.Spec.EgressIP, "an exhausted pool must not leave the gateway in the Egress spec")
				require.False(t, exists)
			} else {
				assert.Equal(t, tt.wantIP, ip.String())
				assert.Equal(t, ip.String(), updated.Spec.EgressIP)
				assert.Equal(t, ip.String(), stored.Spec.EgressIP)
				require.True(t, exists)
				assert.True(t, ip.Equal(allocatedIP))
				assert.Equal(t, pool.Name, allocatedPool)
				egresses = append(egresses, updated)
			}
			require.Error(t, c.externalIPAllocator.UpdateIPAllocation(pool.Name, net.ParseIP(tt.newGateway)))
			if pending != nil {
				assert.Equal(t, tt.pendingIP, pendingIP.String())
				assert.False(t, ip.Equal(pendingIP), "distinct admitted Egresses must retain distinct addresses")
				egresses = append(egresses, updatedPending)
			}
			for _, egress := range egresses {
				retriedIP, _, err := c.syncEgressIP(egress)
				require.NoError(t, err)
				assert.Equal(t, egress.Spec.EgressIP, retriedIP.String(), "retries must preserve each Egress's allocation")
			}
			for _, egress := range egresses {
				require.NoError(t, c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{}))
				require.Eventually(t, func() bool {
					_, err := c.egressLister.Get(egress.Name)
					return err != nil
				}, time.Second, 10*time.Millisecond)
				require.NoError(t, c.syncEgress(egress.Name))
				_, _, exists := c.getIPAllocation(egress.Name)
				require.False(t, exists)
				releasedIP := net.ParseIP(egress.Spec.EgressIP)
				require.NoError(t, c.externalIPAllocator.UpdateIPAllocation(pool.Name, releasedIP),
					"deleting an Egress must release its allocation")
				require.NoError(t, c.externalIPAllocator.ReleaseIP(pool.Name, releasedIP))
			}
		})
	}
}

func TestSyncUntrackedEgressGatewayFailures(t *testing.T) {
	for _, tt := range []struct {
		name     string
		verb     string
		resource string
	}{
		{name: "pool lookup", verb: "get", resource: "externalippools"},
		{name: "clear gateway", verb: "patch", resource: "egresses"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool := newExternalIPPool("pool", "192.168.1.144/28", "", "")
			pool.Spec.SubnetInfo = &v1beta1.SubnetInfo{Gateway: "192.168.1.145", PrefixLength: 28}
			egress := newEgress("egress", pool.Spec.SubnetInfo.Gateway, pool.Name, nil, nil, nil)
			c := newController(nil, []runtime.Object{pool, egress})
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.informerFactory.Start(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.informerFactory.WaitForCacheSync(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			go c.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, c.externalIPAllocator.HasSynced))
			c.externalIPAllocator.RestoreIPAllocations(nil)
			c.crdClient.(*fakeversioned.Clientset).PrependReactor(tt.verb, tt.resource,
				func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("%s failed", tt.name)
				})

			_, updated, err := c.syncEgressIP(egress)
			require.ErrorContains(t, err, tt.name+" failed")
			assert.Equal(t, egress.Spec.EgressIP, updated.Spec.EgressIP)
			_, _, exists := c.getIPAllocation(egress.Name)
			assert.False(t, exists)
			ip, err := c.externalIPAllocator.AllocateIPFromPool(pool.Name)
			require.NoError(t, err)
			assert.Equal(t, "192.168.1.146", ip.String(), "failed reconciliation must not allocate another IP")
		})
	}
}

// Copyright 2023 Antrea Authors
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

package l7flowexporter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/controller/networkpolicy/l7engine"
	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	annotationsEmpty          = map[string]string{}
	annotationsDifferent      = map[string]string{"annotation.antrea.io": "mockVal1"}
	annotationsIncorrect      = map[string]string{types.L7FlowExporterAnnotationKey: "mockVal2"}
	annotationsCorrectIngress = map[string]string{types.L7FlowExporterAnnotationKey: "ingress"}
	annotationsCorrectEgress  = map[string]string{types.L7FlowExporterAnnotationKey: "egress"}
	annotationsCorrectBoth    = map[string]string{types.L7FlowExporterAnnotationKey: "both"}

	pod1NN        = k8s.NamespacedName("test-ns1", "test-pod1")
	pod2NN        = k8s.NamespacedName("test-ns1", "test-pod2")
	pod3NN        = k8s.NamespacedName("test-ns2", "test-pod3")
	pod4NN        = k8s.NamespacedName("test-ns2", "test-pod4")
	podInterface1 = newPodInterface("test-pod1", "test-ns1", int32(pod1OFPort))
	podInterface2 = newPodInterface("test-pod2", "test-ns1", int32(pod2OFPort))
	podInterface3 = newPodInterface("test-pod3", "test-ns2", int32(pod3OFPort))
	podInterface4 = newPodInterface("test-pod4", "test-ns2", int32(pod4OFPort))

	ctx = context.Background()
)

const (
	pod1OFPort = uint32(1)
	pod2OFPort = uint32(2)
	pod3OFPort = uint32(3)
	pod4OFPort = uint32(4)
)

type fakeController struct {
	*L7FlowExporterController
	mockOFClient     *openflowtest.MockClient
	client           *fake.Clientset
	informerFactory  informers.SharedInformerFactory
	localPodInformer cache.SharedIndexInformer
}

func (c *fakeController) startInformers(stopCh chan struct{}) {
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	go c.localPodInformer.Run(stopCh)
	go c.namespaceInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, c.localPodInformer.HasSynced, c.namespaceInformer.HasSynced)
}

func newFakeControllerAndWatcher(t *testing.T, objects []runtime.Object, interfaces []*interfacestore.InterfaceConfig) *fakeController {
	controller := gomock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(controller)

	client := fake.NewSimpleClientset(objects...)
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	nsInformer := informerFactory.Core().V1().Namespaces()

	localPodInformer := coreinformers.NewFilteredPodInformer(
		client,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", "fakeNode").String()
		},
	)

	ifaceStore := interfacestore.NewInterfaceStore()
	for _, itf := range interfaces {
		ifaceStore.AddInterface(itf)
	}

	l7Reconciler := l7engine.NewReconciler()
	l7w := NewL7FlowExporterController(mockOFClient, ifaceStore, localPodInformer, nsInformer, l7Reconciler)

	return &fakeController{
		L7FlowExporterController: l7w,
		mockOFClient:             mockOFClient,
		client:                   client,
		informerFactory:          informerFactory,
		localPodInformer:         localPodInformer,
	}
}

func newPodObject(name, namespace string, annotations map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: v1.PodSpec{
			NodeName: "fakeNode",
		},
		Status: v1.PodStatus{
			PodIP: "10.0.0.1",
		},
	}
}

func newNamespaceObject(name string, annotations map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
			Labels: map[string]string{
				"fakeKey": "fakeValue",
			},
		},
	}
}

func newPodInterface(podName, podNamespace string, ofPort int32) *interfacestore.InterfaceConfig {
	containerName := k8s.NamespacedName(podNamespace, podName)
	return &interfacestore.InterfaceConfig{
		InterfaceName:            util.GenerateContainerInterfaceName(podName, podNamespace, containerName),
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: podName, PodNamespace: podNamespace, ContainerID: containerName},
		OVSPortConfig:            &interfacestore.OVSPortConfig{OFPort: ofPort},
	}
}

func waitEvents(t *testing.T, expectedEvents int, c *fakeController) {
	require.Eventually(t, func() bool {
		return c.queue.Len() == expectedEvents
	}, 5*time.Second, 10*time.Millisecond)
}

func TestPodAdd(t *testing.T) {
	var targetPort uint32
	testNS1 := newNamespaceObject("test-ns1", annotationsEmpty)
	pod1 := newPodObject("test-pod1", "test-ns1", annotationsCorrectIngress)
	pod2 := newPodObject("test-pod2", "test-ns1", annotationsIncorrect)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
	}
	testcases := []struct {
		name                      string
		addedPod                  *v1.Pod
		expectedPodToDirectionMap map[string]v1alpha2.Direction
		expectedCalls             func(mockOFClient *openflowtest.MockClient)
		expectedError             error
	}{
		{
			name:     "Add pod with correct annotations",
			addedPod: pod1,
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod1NN: v1alpha2.DirectionIngress,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN), []uint32{uint32(podInterface1.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
		}, {
			name:                      "Add pod with incorrect annotations",
			addedPod:                  pod2,
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{},
			expectedCalls:             func(mockOFClient *openflowtest.MockClient) {},
			expectedError:             errInvalidAnnotation,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeControllerAndWatcher(t, []runtime.Object{tt.addedPod, testNS1}, interfaces)
			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)
			assert.Eventuallyf(t, func() bool {
				ns, _ := c.namespaceLister.List(labels.Everything())
				return len(c.localPodInformer.GetIndexer().List()) == 1 && len(ns) == 1
			}, 1*time.Second, 10*time.Millisecond, "Pod should be added to Informers")
			waitEvents(t, 1, c)
			item, _ := c.queue.Get()
			tt.expectedCalls(c.mockOFClient)
			err := c.syncPod(item.(string))
			if tt.expectedError != nil {
				assert.ErrorContains(t, err, tt.expectedError.Error())
			} else {
				assert.Equal(t, tt.expectedPodToDirectionMap, c.podToDirectionMap)
			}
			c.queue.Done(item)
		})
	}
}

func TestPodUpdate(t *testing.T) {
	var targetPort uint32
	testNS1 := newNamespaceObject("test-ns1", annotationsEmpty)
	testNS2 := newNamespaceObject("test-ns2", annotationsEmpty)
	pod1 := newPodObject("test-pod1", "test-ns1", annotationsDifferent)
	pod2 := newPodObject("test-pod2", "test-ns1", annotationsIncorrect)
	pod3 := newPodObject("test-pod3", "test-ns2", annotationsEmpty)
	pod4 := newPodObject("test-pod4", "test-ns2", annotationsCorrectIngress)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
		podInterface3,
		podInterface4,
	}
	testcases := []struct {
		name                      string
		updatedPod                *v1.Pod
		expectedPodToDirectionMap map[string]v1alpha2.Direction
		expectedCalls             func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name:       "Update Pod with different annotation to correct annotation",
			updatedPod: newPodObject("test-pod1", "test-ns1", annotationsCorrectEgress),
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod1NN: v1alpha2.DirectionEgress,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN), []uint32{uint32(podInterface1.OFPort)}, targetPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
		}, {
			name:       "Update Pod with Incorrect annotation to correct annotation",
			updatedPod: newPodObject("test-pod2", "test-ns1", annotationsCorrectBoth),
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod2NN: v1alpha2.DirectionBoth,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod2NN), []uint32{uint32(podInterface2.OFPort)}, targetPort, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
		}, {
			name:       "Update Pod with no annotation to correct annotation",
			updatedPod: newPodObject("test-pod3", "test-ns2", annotationsCorrectIngress),
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod3NN: v1alpha2.DirectionIngress,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod3NN), []uint32{uint32(podInterface3.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
		}, {
			name:       "Update Pod with ingress annotation to egress annotation",
			updatedPod: newPodObject("test-pod4", "test-ns2", annotationsCorrectEgress),
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod4NN: v1alpha2.DirectionEgress,
			},
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod4NN), []uint32{uint32(podInterface4.OFPort)}, targetPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeControllerAndWatcher(t, []runtime.Object{pod1, pod2, pod3, pod4, testNS1, testNS2}, interfaces)
			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			assert.Eventuallyf(t, func() bool {
				ns, _ := c.namespaceLister.List(labels.Everything())
				return len(c.localPodInformer.GetIndexer().List()) == 4 && len(ns) == 2
			}, 1*time.Second, 10*time.Millisecond, "Pods should be added to Informers")

			// Pod2 has the correction annotation key (but an invalid annotation value) and Pod4 has the correct
			// annotation item, so they will be queued once for the ADD event. We ignore these events.
			waitEvents(t, 2, c)
			for i := 0; i < 2; i++ {
				item, _ := c.queue.Get()
				c.queue.Done(item)
			}

			tt.expectedCalls(c.mockOFClient)

			// Update Pods with new annotations
			_, err := c.client.CoreV1().Pods(tt.updatedPod.Namespace).Update(ctx, tt.updatedPod, metav1.UpdateOptions{})
			require.NoError(t, err)

			waitEvents(t, 1, c)
			item, _ := c.queue.Get()
			require.NoError(t, c.syncPod(item.(string)))
			assert.Equal(t, tt.expectedPodToDirectionMap, c.podToDirectionMap)
			c.queue.Done(item)
		})
	}
}

func TestPodUpdateRemoveFlows(t *testing.T) {
	var targetPort uint32
	testNS1 := newNamespaceObject("test-ns1", annotationsEmpty)
	pod1 := newPodObject("test-pod1", "test-ns1", annotationsCorrectIngress)
	pod2 := newPodObject("test-pod2", "test-ns1", annotationsCorrectIngress)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
	}
	expectedInstallCalls := func(mockOFClient *openflowtest.MockClient) {
		mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN), []uint32{uint32(podInterface1.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
		mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod2NN), []uint32{uint32(podInterface2.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
	}
	testcases := []struct {
		name                               string
		pod                                *v1.Pod
		deletePod                          bool
		expectedL7PodNNDirAfterFlowRemoved map[string]v1alpha2.Direction
		expectedUninstallCalls             func(mockOFClient *openflowtest.MockClient)
	}{
		{
			name:                               "Remove flows for annotation removed",
			pod:                                newPodObject("test-pod1", "test-ns1", annotationsEmpty),
			deletePod:                          false,
			expectedL7PodNNDirAfterFlowRemoved: map[string]v1alpha2.Direction{pod2NN: v1alpha2.DirectionIngress},
			expectedUninstallCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN))
			},
		}, {
			name:                               "Remove flows for deletedPod",
			pod:                                newPodObject("test-pod2", "test-ns1", annotationsCorrectIngress),
			deletePod:                          true,
			expectedL7PodNNDirAfterFlowRemoved: map[string]v1alpha2.Direction{pod1NN: v1alpha2.DirectionIngress},
			expectedUninstallCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod2NN))
			},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeControllerAndWatcher(t, []runtime.Object{pod1, pod2, testNS1}, interfaces)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.startInformers(stopCh)
			assert.Eventuallyf(t, func() bool {
				ns, _ := c.namespaceLister.List(labels.Everything())
				return len(c.localPodInformer.GetIndexer().List()) == 2 && len(ns) == 1
			}, 1*time.Second, 10*time.Millisecond, "Pods should be added to Informers")
			expectedInstallCalls(c.mockOFClient)
			waitEvents(t, 2, c)
			for i := 0; i < 2; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncPod(item.(string)))
				c.queue.Done(item)
			}
			if tt.deletePod {
				//Delete Pod
				err := c.client.CoreV1().Pods(tt.pod.Namespace).Delete(ctx, tt.pod.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			} else {
				// Update Pods with no annotations
				_, err := c.client.CoreV1().Pods(tt.pod.Namespace).Update(ctx, tt.pod, metav1.UpdateOptions{})
				require.NoError(t, err)
			}

			tt.expectedUninstallCalls(c.mockOFClient)

			waitEvents(t, 1, c)
			item, _ := c.queue.Get()
			require.NoError(t, c.syncPod(item.(string)))
			assert.Equal(t, tt.expectedL7PodNNDirAfterFlowRemoved, c.podToDirectionMap)
			c.queue.Done(item)
		})
	}
}

func TestNamespaceUpdate(t *testing.T) {
	var targetPort uint32
	testNS1 := newNamespaceObject("test-ns1", annotationsEmpty)
	testNS2 := newNamespaceObject("test-ns2", annotationsEmpty)
	pod1 := newPodObject("test-pod1", "test-ns1", annotationsEmpty)
	pod2 := newPodObject("test-pod2", "test-ns1", annotationsEmpty)
	pod3 := newPodObject("test-pod3", "test-ns2", annotationsEmpty)
	pod4 := newPodObject("test-pod4", "test-ns2", annotationsCorrectIngress)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
		podInterface3,
		podInterface4,
	}
	testcases := []struct {
		name                      string
		updatedNS                 *v1.Namespace
		expectedCalls             func(mockOFClient *openflowtest.MockClient)
		expectedPodToDirectionMap map[string]v1alpha2.Direction
		expectedPodsCount         int
	}{
		{
			name:      "Update namespace to have annotations",
			updatedNS: newNamespaceObject("test-ns1", annotationsCorrectEgress),
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN), []uint32{uint32(podInterface1.OFPort)}, targetPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod2NN), []uint32{uint32(podInterface2.OFPort)}, targetPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod1NN: v1alpha2.DirectionEgress,
				pod2NN: v1alpha2.DirectionEgress,
			},
			expectedPodsCount: 2,
		}, {
			name:      "Update namespace to have annotations containing pod with annotation",
			updatedNS: newNamespaceObject("test-ns2", annotationsCorrectEgress),
			expectedCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod3NN), []uint32{uint32(podInterface3.OFPort)}, targetPort, v1alpha2.DirectionEgress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
			expectedPodToDirectionMap: map[string]v1alpha2.Direction{
				pod3NN: v1alpha2.DirectionEgress,
			},
			expectedPodsCount: 1,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeControllerAndWatcher(t, []runtime.Object{testNS1, testNS2, pod1, pod2, pod3, pod4}, interfaces)
			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)
			// Ignore Pod4 as that will be enqueued by addPod func
			waitEvents(t, 1, c)
			for i := 0; i < 1; i++ {
				item, _ := c.queue.Get()
				c.queue.Done(item)
			}

			// Update NS object
			_, err := c.client.CoreV1().Namespaces().Update(ctx, tt.updatedNS, metav1.UpdateOptions{})
			require.NoError(t, err)
			tt.expectedCalls(c.mockOFClient)
			waitEvents(t, tt.expectedPodsCount, c)
			for i := 0; i < tt.expectedPodsCount; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncPod(item.(string)))
				c.queue.Done(item)
			}
			assert.Equal(t, tt.expectedPodToDirectionMap, c.podToDirectionMap)
		})
	}
}

func TestNSUpdateRemoveFlows(t *testing.T) {
	var targetPort uint32
	testNS1 := newNamespaceObject("test-ns1", annotationsCorrectIngress)
	pod1 := newPodObject("test-pod1", "test-ns1", annotationsEmpty)
	pod2 := newPodObject("test-pod2", "test-ns1", annotationsCorrectIngress)
	interfaces := []*interfacestore.InterfaceConfig{
		podInterface1,
		podInterface2,
	}
	testcases := []struct {
		name                                  string
		Namespace                             *v1.Namespace
		expectedL7PodNNDirMapAfterFlowRemoved map[string]v1alpha2.Direction
		expectedInstallCalls                  func(mockOFClient *openflowtest.MockClient)
		expectedUninstallCalls                func(mockOFClient *openflowtest.MockClient)
		expectedQueueLen                      int
	}{
		{
			name:      "Remove flows for annotation removed",
			Namespace: newNamespaceObject("test-ns1", map[string]string{}),
			expectedInstallCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN), []uint32{uint32(podInterface1.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
				mockOFClient.EXPECT().InstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod2NN), []uint32{uint32(podInterface2.OFPort)}, targetPort, v1alpha2.DirectionIngress, v1alpha2.ActionMirror, types.TrafficControlFlowPriorityLow)
			},
			expectedL7PodNNDirMapAfterFlowRemoved: map[string]v1alpha2.Direction{
				pod2NN: v1alpha2.DirectionIngress,
			},
			expectedUninstallCalls: func(mockOFClient *openflowtest.MockClient) {
				mockOFClient.EXPECT().UninstallTrafficControlMarkFlows(fmt.Sprintf("tcl7:%s", pod1NN))
			},
			expectedQueueLen: 1,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeControllerAndWatcher(t, []runtime.Object{testNS1}, interfaces)
			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)
			_, err := c.client.CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{})
			require.NoError(t, err)
			_, err = c.client.CoreV1().Pods(pod1.Namespace).Create(ctx, pod2, metav1.CreateOptions{})
			require.NoError(t, err)
			assert.Eventuallyf(t, func() bool {
				ns, _ := c.namespaceLister.List(labels.Everything())
				return len(c.localPodInformer.GetIndexer().List()) == 2 && len(ns) == 1
			}, 1*time.Second, 10*time.Millisecond, "Pods and Namespaces should be added to Informers")

			tt.expectedInstallCalls(c.mockOFClient)
			waitEvents(t, 2, c)
			for i := 0; i < 2; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncPod(item.(string)))
				c.queue.Done(item)
			}
			// Update Pods with no annotations
			_, err = c.client.CoreV1().Namespaces().Update(ctx, tt.Namespace, metav1.UpdateOptions{})
			require.NoError(t, err)

			tt.expectedUninstallCalls(c.mockOFClient)
			waitEvents(t, tt.expectedQueueLen, c)
			for i := 0; i < tt.expectedQueueLen; i++ {
				item, _ := c.queue.Get()
				require.NoError(t, c.syncPod(item.(string)))
				c.queue.Done(item)
			}
			assert.Equal(t, tt.expectedL7PodNNDirMapAfterFlowRemoved, c.podToDirectionMap)
		})
	}
}

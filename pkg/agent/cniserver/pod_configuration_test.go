// Copyright 2024 Antrea Authors
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

package cniserver

import (
	"context"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"net"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	podIfName = "test"
)

func TestUpdateUnReadyPod(t *testing.T) {
	defer mockRetryInterval()()
	var fakeOFClient *openflowtest.MockClient

	podIPs := []net.IP{net.ParseIP("192.168.9.10")}
	podMac, _ := net.ParseMAC("00:15:5D:B2:6F:38")
	podInfraContainerID := "261a1970-5b6c-11ed-8caf-000c294e5d03"
	podIfaceConfig := &interfacestore.InterfaceConfig{
		InterfaceName: podIfName,
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodNamespace: testPodNamespace,
			PodName:      testPodNameA,
			ContainerID:  podInfraContainerID,
		},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			PortUUID: "test-port-uuid",
		},
		IPs: podIPs,
		MAC: podMac,
	}

	portStatusMsg := &openflow15.PortStatus{
		Reason: openflow15.PR_MODIFY,
		Desc: openflow15.Port{
			PortNo: 1,
			Length: 72,
			Name:   []byte("test"),
			State:  openflow15.PS_LIVE,
		},
	}

	for _, tc := range []struct {
		name               string
		podIfaceUnReady    bool
		podIfaceIsCached   bool
		installOpenFlowErr error
		expMsgRequeued     bool
	}{
		{
			name:             "updated Port is not in unready state",
			podIfaceUnReady:  false,
			podIfaceIsCached: true,
			expMsgRequeued:   false,
		}, {
			name:             "updated Port is not in interface store",
			podIfaceUnReady:  true,
			podIfaceIsCached: false,
			expMsgRequeued:   true,
		}, {
			name:               "failed to install OpenFlow entries for updated Port",
			podIfaceUnReady:    true,
			podIfaceIsCached:   true,
			installOpenFlowErr: fmt.Errorf("failure to install flow"),
			expMsgRequeued:     true,
		}, {
			name:               "succeeded",
			podIfaceUnReady:    true,
			podIfaceIsCached:   true,
			installOpenFlowErr: nil,
			expMsgRequeued:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			}
			fakeKubeClient := fakeclientset.NewClientset(pod)
			fakeOFClient = openflowtest.NewMockClient(controller)
			fakeIfaceStore := interfacestore.NewInterfaceStore()
			waiter := newAsyncWaiter(testPodNameA, podInfraContainerID)
			monitor := &podIfaceMonitor{
				kubeClient:        fakeKubeClient,
				ofClient:          fakeOFClient,
				ifaceStore:        fakeIfaceStore,
				podUpdateNotifier: waiter.notifier,
				unReadyInterfaces: make(map[string]*unReadyPodInfo),
				statusCh:          make(chan *openflow15.PortStatus),
			}

			flowInstalled := false
			ofPortUpdated := false

			if tc.podIfaceUnReady {
				monitor.addUnReadyPodInterface(podIfaceConfig)
			}
			if tc.podIfaceIsCached {
				fakeIfaceStore.AddInterface(podIfaceConfig)
			}
			if tc.podIfaceUnReady && tc.podIfaceIsCached {
				fakeOFClient.EXPECT().InstallPodFlows(podIfName, podIPs, podMac, portStatusMsg.Desc.PortNo, uint16(0), nil).Times(1).Return(tc.installOpenFlowErr)
				if tc.installOpenFlowErr == nil {
					flowInstalled = true
					ofPortUpdated = true
				}
			}

			monitor.updateUnReadyPod(portStatusMsg)

			podInfo, found := monitor.unReadyInterfaces[podIfName]
			if !tc.podIfaceUnReady {
				require.False(t, found)
				return
			}

			require.True(t, found)
			if ofPortUpdated {
				actCfg, found := fakeIfaceStore.GetContainerInterface(podIfaceConfig.ContainerID)
				require.True(t, found)
				assert.Equal(t, int32(portStatusMsg.Desc.PortNo), actCfg.OVSPortConfig.OFPort)
			}

			if flowInstalled {
				waiter.wait()
				assert.True(t, podInfo.flowInstalled)
			}

			if tc.expMsgRequeued {
				<-monitor.statusCh
			}
			waiter.close()
		})
	}
}

func TestCheckUnReadyPods(t *testing.T) {
	for _, tc := range []struct {
		name          string
		existingPod   *corev1.Pod
		k8sGetErr     error
		k8sPatchErr   error
		podInfo       *unReadyPodInfo
		expDeleted    bool
		expPatch      bool
		hasAnnotation bool
	}{
		{
			name: "Pod doesn't exist",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:      testPodNameA,
				podNamespace: testPodNamespace,
				createTime:   time.Now(),
			},
			k8sGetErr:     apierrors.NewNotFound(corev1.Resource("pods"), testPodNameA),
			expDeleted:    true,
			expPatch:      false,
			hasAnnotation: false,
		}, {
			name: "failed to get Pod",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:      testPodNameA,
				podNamespace: testPodNamespace,
				createTime:   time.Now(),
			},
			k8sGetErr:     fmt.Errorf("get error"),
			expDeleted:    false,
			expPatch:      false,
			hasAnnotation: false,
		}, {
			name: "unready Pod is already annotated",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				flowInstalled: false,
			},
			expPatch:      false,
			hasAnnotation: true,
			expDeleted:    false,
		}, {
			name: "unready Pod is not annotated and sync time is not up",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now(),
				flowInstalled: false,
			},
			expPatch:      false,
			hasAnnotation: false,
			expDeleted:    false,
		}, {
			name: "annotate unready Pod",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now().Add((-40) * time.Second),
				flowInstalled: false,
			},
			expPatch:      true,
			hasAnnotation: true,
			expDeleted:    false,
		}, {
			name: "failed to annotate unready Pod",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now().Add((-40) * time.Second),
				flowInstalled: false,
			},
			k8sPatchErr:   fmt.Errorf("patch error"),
			expPatch:      true,
			hasAnnotation: false,
			expDeleted:    false,
		}, {
			name: "remove annotation after Pod is ready",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now(),
				flowInstalled: true,
			},
			expPatch:      true,
			hasAnnotation: false,
			expDeleted:    true,
		}, {
			name: "failed to remove annotation after Pod is ready",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
					Annotations: map[string]string{
						types.PodNotReadyAnnotationKey: "",
					},
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now(),
				flowInstalled: true,
			},
			k8sPatchErr:   fmt.Errorf("patch error"),
			expPatch:      true,
			hasAnnotation: true,
			expDeleted:    false,
		}, {
			name: "annotation is removed after Pod is ready",
			existingPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testPodNameA,
					Namespace: testPodNamespace,
				},
			},
			podInfo: &unReadyPodInfo{
				podName:       testPodNameA,
				podNamespace:  testPodNamespace,
				createTime:    time.Now(),
				flowInstalled: true,
			},
			expPatch:      false,
			hasAnnotation: false,
			expDeleted:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			fakeKubeClient := fakeclientset.NewClientset(tc.existingPod)
			fakeKubeClient.PrependReactor("get", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				if tc.k8sGetErr != nil {
					return true, nil, tc.k8sGetErr
				}
				get := action.(k8stesting.GetActionImpl)
				return k8stesting.ObjectReaction(fakeKubeClient.Tracker())(get)
			})
			fakeKubeClient.PrependReactor("patch", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				if !tc.expPatch {
					require.FailNow(t, "Patch pod is not expected")
				}
				if tc.k8sPatchErr != nil {
					return true, nil, tc.k8sPatchErr
				}
				pa := action.(k8stesting.PatchActionImpl)
				return k8stesting.ObjectReaction(fakeKubeClient.Tracker())(pa)
			})
			fakeOFClient := openflowtest.NewMockClient(controller)
			fakeIfaceStore := interfacestore.NewInterfaceStore()
			monitor := &podIfaceMonitor{
				kubeClient:        fakeKubeClient,
				ofClient:          fakeOFClient,
				ifaceStore:        fakeIfaceStore,
				podUpdateNotifier: nil,
				unReadyInterfaces: map[string]*unReadyPodInfo{podIfName: tc.podInfo},
				statusCh:          make(chan *openflow15.PortStatus),
			}

			monitor.checkUnReadyPods()

			_, found := monitor.unReadyInterfaces[podIfName]
			if tc.expDeleted {
				require.False(t, found)
			} else {
				require.True(t, found)
			}
			if tc.k8sGetErr == nil {
				annotated, err := checkAnnotation(fakeKubeClient, tc.existingPod.Namespace, tc.existingPod.Name)
				require.NoError(t, err)
				assert.Equal(t, tc.hasAnnotation, annotated)
			}
		})
	}
}

func checkAnnotation(kubeClient *fakeclientset.Clientset, namespace, name string) (bool, error) {
	updatedPod, err := kubeClient.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(updatedPod.Annotations) == 0 {
		return false, nil
	}
	_, annotated := updatedPod.Annotations[types.PodNotReadyAnnotationKey]
	return annotated, nil
}

func mockRetryInterval() func() {
	oriRetryInterval := retryInterval
	retryInterval = time.Millisecond * 500
	return func() {
		retryInterval = oriRetryInterval
	}
}

type asyncWaiter struct {
	podName     string
	containerID string
	waitCh      chan struct{}
	stopCh      chan struct{}
	notifier    *channel.SubscribableChannel
}

func (w *asyncWaiter) notify(e interface{}) {
	podUpdate := e.(types.PodUpdate)
	if podUpdate.PodName == w.podName && podUpdate.ContainerID == w.containerID {
		w.waitCh <- struct{}{}
	}
}

func (w *asyncWaiter) wait() {
	<-w.waitCh
}

func (w *asyncWaiter) close() {
	close(w.waitCh)
	close(w.stopCh)
}

func newAsyncWaiter(podName, containerID string) *asyncWaiter {
	waiter := &asyncWaiter{
		podName:     podName,
		containerID: containerID,
		waitCh:      make(chan struct{}),
		stopCh:      make(chan struct{}),
		notifier:    channel.NewSubscribableChannel("PodUpdate", 100),
	}
	waiter.notifier.Subscribe(waiter.notify)
	go waiter.notifier.Run(waiter.stopCh)
	return waiter
}

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
	"fmt"
	"net"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/pkg/agent/interfacestore"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	podIfName           = "test"
	podIPs              = []net.IP{net.ParseIP("192.168.9.10")}
	podMac, _           = net.ParseMAC("00:15:5D:B2:6F:38")
	podInfraContainerID = "261a1970-5b6c-11ed-8caf-000c294e5d03"

	pod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodNameA,
			Namespace: testPodNamespace,
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}

	portStatusMsg = &openflow15.PortStatus{
		Reason: openflow15.PR_MODIFY,
		Desc: openflow15.Port{
			PortNo: 1,
			Length: 72,
			Name:   []byte(fmt.Sprintf("%s\x00", podIfName)),
			State:  openflow15.PS_LIVE,
		},
	}
)

type mockClients struct {
	kubeClient       *fakeclientset.Clientset
	localPodInformer cache.SharedIndexInformer
	podLister        corelisters.PodLister
	podListerSynced  cache.InformerSynced
	ofClient         *openflowtest.MockClient
	recorder         *record.FakeRecorder
}

func newMockClients(ctrl *gomock.Controller, nodeName string, objects ...runtime.Object) *mockClients {
	kubeClient := fakeclientset.NewClientset(objects...)

	localPodInformer := coreinformers.NewFilteredPodInformer(
		kubeClient,
		metav1.NamespaceAll,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
		},
	)
	podLister := corelisters.NewPodLister(localPodInformer.GetIndexer())
	ofClient := openflowtest.NewMockClient(ctrl)
	recorder := record.NewFakeRecorder(100)
	recorder.IncludeObject = false

	return &mockClients{
		kubeClient:       kubeClient,
		localPodInformer: localPodInformer,
		podLister:        podLister,
		podListerSynced:  localPodInformer.HasSynced,
		ofClient:         ofClient,
		recorder:         recorder,
	}
}

func (c *mockClients) startInformers(stopCh chan struct{}) {
	go c.localPodInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, c.localPodInformer.HasSynced)
}

type asyncWaiter struct {
	podName     string
	containerID string
	waitCh      chan struct{}
	notifier    *channel.SubscribableChannel
}

func (w *asyncWaiter) notify(e interface{}) {
	podUpdate := e.(types.PodUpdate)
	if podUpdate.PodName == w.podName && podUpdate.ContainerID == w.containerID {
		w.waitCh <- struct{}{}
	}
}

func (w *asyncWaiter) waitUntil(timeout time.Duration) bool {
	select {
	case <-w.waitCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func newAsyncWaiter(podName, containerID string, stopCh chan struct{}) *asyncWaiter {
	waiter := &asyncWaiter{
		podName:     podName,
		containerID: containerID,
		waitCh:      make(chan struct{}),
		notifier:    channel.NewSubscribableChannel("PodUpdate", 100),
	}
	waiter.notifier.Subscribe(waiter.notify)
	go waiter.notifier.Run(stopCh)
	return waiter
}

func mockRetryInterval(t *testing.T) {
	oriRetryInterval := retryInterval
	retryInterval = -1
	t.Cleanup(func() {
		retryInterval = oriRetryInterval
	})
}

func newTestPodConfigurator(testClients *mockClients, waiter *asyncWaiter) *podConfigurator {
	interfaceStore := interfacestore.NewInterfaceStore()
	eventBroadcaster := record.NewBroadcaster()
	queue := workqueue.NewTypedDelayingQueueWithConfig[string](
		workqueue.TypedDelayingQueueConfig[string]{
			Name: "podConfigurator",
		},
	)
	podCfg := &podConfigurator{
		kubeClient:       testClients.kubeClient,
		ofClient:         testClients.ofClient,
		podLister:        testClients.podLister,
		podListerSynced:  testClients.podListerSynced,
		ifaceStore:       interfaceStore,
		eventBroadcaster: eventBroadcaster,
		recorder:         testClients.recorder,
		unreadyPortQueue: queue,
		containerAccess:  newContainerAccessArbitrator(),
	}
	if waiter != nil {
		podCfg.podUpdateNotifier = waiter.notifier
	}
	return podCfg
}

func TestUpdateUnreadyPod(t *testing.T) {
	mockRetryInterval(t)

	for _, tc := range []struct {
		name               string
		ofPortAssigned     bool
		podIfaceIsCached   bool
		installFlow        bool
		flowInstalled      bool
		installOpenFlowErr error
		expErr             string
		expEvent           string
	}{
		{
			name:             "updated Port is not in interface store",
			podIfaceIsCached: false,
			installFlow:      false,
		}, {
			name:             "OpenFlow port is not assigned",
			podIfaceIsCached: true,
			ofPortAssigned:   false,
			installFlow:      false,
			expErr:           "pod's OpenFlow port is not ready yet",
			expEvent:         "Warning NetworkNotReady Pod network forwarding rules not installed",
		}, {
			name:               "failed to install OpenFlow entries for updated Port",
			podIfaceIsCached:   true,
			ofPortAssigned:     true,
			installFlow:        true,
			installOpenFlowErr: fmt.Errorf("failure to install flow"),
			expErr:             "failed to add Openflow entries for OVS port test: failure to install flow",
			expEvent:           "Warning NetworkNotReady Pod network forwarding rules not installed",
		}, {
			name:               "succeeded",
			podIfaceIsCached:   true,
			ofPortAssigned:     true,
			installFlow:        true,
			installOpenFlowErr: nil,
			expEvent:           "Normal NetworkReady Installed Pod network forwarding rules",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			stopCh := make(chan struct{})
			defer close(stopCh)

			waiter := newAsyncWaiter(testPodNameA, podInfraContainerID, stopCh)

			testClients := newMockClients(controller, nodeName, pod)
			testClients.startInformers(stopCh)
			fakeOFClient := testClients.ofClient

			configurator := newTestPodConfigurator(testClients, waiter)

			flowInstalled := false

			ifConfig := interfacestore.InterfaceConfig{
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

			if tc.ofPortAssigned {
				ifConfig.OVSPortConfig.OFPort = int32(1)
			}

			if tc.podIfaceIsCached {
				configurator.ifaceStore.AddInterface(&ifConfig)
			}

			if tc.installFlow {
				fakeOFClient.EXPECT().InstallPodFlows(podIfName, podIPs, podMac, portStatusMsg.Desc.PortNo, uint16(0), nil).Times(1).Return(tc.installOpenFlowErr)
				if tc.installOpenFlowErr == nil {
					flowInstalled = true
				}
			}

			err := configurator.updateUnreadyPod(podIfName)
			if tc.expErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expErr)
			}

			if flowInstalled {
				assert.True(t, waiter.waitUntil(5*time.Second))
			}

			var gotEvent string
			select {
			case gotEvent = <-testClients.recorder.Events:
			default:
			}
			require.Equal(t, tc.expEvent, gotEvent)
		})
	}
}

func TestProcessNextWorkItem(t *testing.T) {
	mockRetryInterval(t)

	for _, tc := range []struct {
		name               string
		installOpenFlowErr error
		expEvent           string
		expRequeue         bool
	}{
		{
			name:               "failed to install OpenFlow entries for updated Port",
			installOpenFlowErr: fmt.Errorf("failure to install flow"),
			expRequeue:         true,
		}, {
			name:               "succeeded",
			installOpenFlowErr: nil,
			expRequeue:         false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			stopCh := make(chan struct{})
			defer close(stopCh)

			waiter := newAsyncWaiter(testPodNameA, podInfraContainerID, stopCh)

			testClients := newMockClients(controller, nodeName, pod)
			testClients.startInformers(stopCh)
			fakeOFClient := testClients.ofClient

			configurator := newTestPodConfigurator(testClients, waiter)
			defer configurator.unreadyPortQueue.ShutDown()

			configurator.ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
				InterfaceName: podIfName,
				ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
					PodNamespace: testPodNamespace,
					PodName:      testPodNameA,
					ContainerID:  podInfraContainerID,
				},
				OVSPortConfig: &interfacestore.OVSPortConfig{
					PortUUID: "test-port-uuid",
					OFPort:   int32(1),
				},
				IPs: podIPs,
				MAC: podMac,
			})

			fakeOFClient.EXPECT().InstallPodFlows(podIfName, podIPs, podMac, portStatusMsg.Desc.PortNo, uint16(0), nil).Times(1).Return(tc.installOpenFlowErr)
			configurator.unreadyPortQueue.Add(podIfName)

			configurator.processNextWorkItem()

			if tc.installOpenFlowErr != nil {
				require.Equal(t, 1, configurator.unreadyPortQueue.Len())
				key, _ := configurator.unreadyPortQueue.Get()
				assert.Equal(t, key, podIfName)
			} else {
				require.Equal(t, 0, configurator.unreadyPortQueue.Len())
			}
		})
	}
}

func TestProcessPortStatusMessage(t *testing.T) {
	validOFPort := int32(1)
	invalidOFPort := int32(0)
	for _, tc := range []struct {
		name            string
		status          *openflow15.PortStatus
		ovsPortName     string
		ifaceInStore    bool
		expEnqueue      bool
		expOFportNumber *int32
	}{
		{
			name: "Add OF port if port status is live",
			status: &openflow15.PortStatus{
				Desc: openflow15.Port{
					PortNo: 1,
					Length: 72,
					Name:   []byte(podIfName),
					State:  openflow15.PS_LIVE,
				},
			},
			ovsPortName:     podIfName,
			ifaceInStore:    true,
			expEnqueue:      true,
			expOFportNumber: &validOFPort,
		}, {
			name: "Add OF port with suffix in name",
			status: &openflow15.PortStatus{
				Desc: openflow15.Port{
					PortNo: 1,
					Length: 72,
					Name:   []byte(fmt.Sprintf("%s\x00", podIfName)),
					State:  openflow15.PS_LIVE,
				},
			},
			ovsPortName:     podIfName,
			ifaceInStore:    true,
			expEnqueue:      true,
			expOFportNumber: &validOFPort,
		}, {
			name: "Ignore OF port if port is not live",
			status: &openflow15.PortStatus{
				Desc: openflow15.Port{
					PortNo: 1,
					Length: 72,
					Name:   []byte(fmt.Sprintf("%s\x00", podIfName)),
					State:  openflow15.PS_BLOCKED,
				},
			},
			ovsPortName:     podIfName,
			ifaceInStore:    true,
			expEnqueue:      false,
			expOFportNumber: &invalidOFPort,
		}, {
			name: "Not enqueue OF port status message if the interface config does not exist",
			status: &openflow15.PortStatus{
				Desc: openflow15.Port{
					PortNo: 1,
					Length: 72,
					Name:   []byte(podIfName),
					State:  openflow15.PS_LIVE,
				},
			},
			ovsPortName:     podIfName,
			ifaceInStore:    false,
			expEnqueue:      false,
			expOFportNumber: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue := workqueue.NewTypedDelayingQueueWithConfig[string](
				workqueue.TypedDelayingQueueConfig[string]{
					Name: "podMonitor",
				})
			podCfg := &podConfigurator{
				ifaceStore:       interfacestore.NewInterfaceStore(),
				statusCh:         make(chan *openflow15.PortStatus),
				unreadyPortQueue: queue,
				containerAccess:  newContainerAccessArbitrator(),
			}
			defer podCfg.unreadyPortQueue.ShutDown()

			if tc.ifaceInStore {
				podCfg.ifaceStore.AddInterface(&interfacestore.InterfaceConfig{
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
				})
			}

			podCfg.processPortStatusMessage(tc.status)
			if tc.expEnqueue {
				require.Equal(t, 1, queue.Len())
				key, _ := queue.Get()
				assert.Equal(t, tc.ovsPortName, key)
			} else {
				require.Equal(t, 0, queue.Len())
			}

			if tc.expOFportNumber != nil {
				ifaceCfg, ok := podCfg.ifaceStore.GetInterfaceByName(podIfName)
				require.True(t, ok)
				assert.Equal(t, *tc.expOFportNumber, ifaceCfg.OFPort)
			}
		})
	}
}

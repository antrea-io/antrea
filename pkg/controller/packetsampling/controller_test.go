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

package packetsampling

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

type packetSamplingController struct {
	*Controller
	kubeClient         clientset.Interface
	client             versioned.Interface
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
}

func newController(k8sObjects ...runtime.Object) *packetSamplingController {
	client := fake.NewSimpleClientset(k8sObjects...)
	crdClient := newCRDClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	controller := NewPacketSamplingController(crdClient,
		informerFactory.Core().V1().Pods(),
		crdInformerFactory.Crd().V1alpha1().PacketSamplings())
	controller.packetSamplingListerSynced = alwaysReady
	return &packetSamplingController{
		controller,
		client,
		crdClient,
		informerFactory,
		crdInformerFactory,
	}
}

func (psc *packetSamplingController) waitForPodInNamespace(ns string, name string, timeout time.Duration) (*corev1.Pod, error) {
	var pod *corev1.Pod
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		// Make sure dummy Pod is synced by informer
		pod, err = psc.podLister.Pods(ns).Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return pod, nil
}

func (psc *packetSamplingController) waitForPacketSampling(name string, phase crdv1alpha1.PacketSamplingPhase, timeout time.Duration) (*crdv1alpha1.PacketSampling, error) {
	var ps *crdv1alpha1.PacketSampling
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		ps, err = psc.client.CrdV1alpha1().PacketSamplings().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || ps.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return ps, nil
}

func TestPacketSampling(t *testing.T) {
	// Check timeout more frequently.
	timeoutCheckInterval = time.Second

	psc := newController()
	stopCh := make(chan struct{})
	psc.informerFactory.Start(stopCh)
	psc.crdInformerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	psc.informerFactory.WaitForCacheSync(stopCh)
	psc.crdInformerFactory.WaitForCacheSync(stopCh)
	go psc.Run(stopCh)

	numRunningPacketSamplings := func() int {
		psc.runningPacketSamplingsMutex.Lock()
		defer psc.runningPacketSamplingsMutex.Unlock()
		return len(psc.runningPacketSamplings)
	}

	ps1 := crdv1alpha1.PacketSampling{
		ObjectMeta: metav1.ObjectMeta{Name: "ps1", UID: "uid1"},
		Spec: crdv1alpha1.PacketSamplingSpec{
			Source:      crdv1alpha1.Source{Namespace: "ns1", Pod: "pod1"},
			Destination: crdv1alpha1.Destination{Namespace: "ns2", Pod: "pod2"},
			Timeout:     2, // 2 seconds timeout
			Type:        crdv1alpha1.FirstNSampling,
			FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
				Number: 5,
			},
		},
	}

	t.Run("normalPacketSampling", func(t *testing.T) {
		pod1 := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "ns1",
			},
		}

		psc.kubeClient.CoreV1().Pods("ns1").Create(context.TODO(), &pod1, metav1.CreateOptions{})
		createdPod, _ := psc.waitForPodInNamespace("ns1", "pod1", time.Second)
		require.NotNil(t, createdPod)
		psc.client.CrdV1alpha1().PacketSamplings().Create(context.TODO(), &ps1, metav1.CreateOptions{})
		res, _ := psc.waitForPacketSampling("ps1", crdv1alpha1.PacketSamplingRunning, time.Second)
		require.NotNil(t, res)
		// DataplaneTag should be allocated by Controller.
		assert.True(t, res.Status.DataplaneTag > 0)
		assert.Equal(t, numRunningPacketSamplings(), 1)
		assert.NoError(t, psc.occupyTag(res))

		// Test Controller handling of successful PacketSampling.
		res.Status.NumCapturedPackets = 5
		psc.client.CrdV1alpha1().PacketSamplings().Update(context.TODO(), res, metav1.UpdateOptions{})
		res, err := psc.waitForPacketSampling("ps1", crdv1alpha1.PacketSamplingSucceeded, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, res)
		// DataplaneTag should be deallocated by Controller.
		assert.True(t, res.Status.DataplaneTag == 0)
		assert.Equal(t, numRunningPacketSamplings(), 0)
		psc.client.CrdV1alpha1().PacketSamplings().Delete(context.TODO(), "ps1", metav1.DeleteOptions{})
	})

	t.Run("timeoutPacketSampling", func(t *testing.T) {
		startTime := time.Now()
		psc.client.CrdV1alpha1().PacketSamplings().Create(context.TODO(), &ps1, metav1.CreateOptions{})
		res, _ := psc.waitForPacketSampling("ps1", crdv1alpha1.PacketSamplingRunning, time.Second)
		assert.NotNil(t, res)
		res, _ = psc.waitForPacketSampling("ps1", crdv1alpha1.PacketSamplingFailed, defaultTimeoutDuration*2)
		assert.NotNil(t, res)
		assert.True(t, time.Now().Sub(startTime) >= time.Second*time.Duration(ps1.Spec.Timeout))
		assert.Equal(t, res.Status.Reason, samplingTimeoutReason)
		assert.True(t, res.Status.DataplaneTag == 0)
		assert.Equal(t, numRunningPacketSamplings(), 0)
	})

	close(stopCh)
}

func newCRDClientset() *fakeversioned.Clientset {
	client := fakeversioned.NewSimpleClientset()

	client.PrependReactor("create", "packetsamplings", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		ps := action.(k8stesting.CreateAction).GetObject().(*crdv1alpha1.PacketSampling)

		// Fake client does not set CreationTimestamp.
		if ps.ObjectMeta.CreationTimestamp == (metav1.Time{}) {
			ps.ObjectMeta.CreationTimestamp.Time = time.Now()
		}

		return false, ps, nil
	}))

	return client
}

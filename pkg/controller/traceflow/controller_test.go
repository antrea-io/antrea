// Copyright 2020 Antrea Authors
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

package traceflow

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

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

type traceflowController struct {
	*Controller
	kubeClient         clientset.Interface
	client             versioned.Interface
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
}

func newController(k8sObjects ...runtime.Object) *traceflowController {
	client := fake.NewSimpleClientset(k8sObjects...)
	crdClient := newCRDClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	controller := NewTraceflowController(crdClient,
		informerFactory.Core().V1().Pods(),
		crdInformerFactory.Crd().V1beta1().Traceflows())
	controller.traceflowListerSynced = alwaysReady
	return &traceflowController{
		controller,
		client,
		crdClient,
		informerFactory,
		crdInformerFactory,
	}
}

func TestTraceflow(t *testing.T) {
	// Check timeout more frequently.
	timeoutCheckInterval = time.Second

	tfc := newController()
	stopCh := make(chan struct{})
	tfc.informerFactory.Start(stopCh)
	tfc.crdInformerFactory.Start(stopCh)
	// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
	// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
	// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
	tfc.informerFactory.WaitForCacheSync(stopCh)
	tfc.crdInformerFactory.WaitForCacheSync(stopCh)
	go tfc.Run(stopCh)

	numRunningTraceflows := func() int {
		tfc.runningTraceflowsMutex.Lock()
		defer tfc.runningTraceflowsMutex.Unlock()
		return len(tfc.runningTraceflows)
	}

	tf1 := crdv1beta1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
		Spec: crdv1beta1.TraceflowSpec{
			Source:      crdv1beta1.Source{Namespace: "ns1", Pod: "pod1"},
			Destination: crdv1beta1.Destination{Namespace: "ns2", Pod: "pod2"},
			Timeout:     2, // 2 seconds timeout
		},
	}

	t.Run("normalTraceflow", func(t *testing.T) {
		pod1 := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod1",
				Namespace: "ns1",
			},
		}

		tfc.kubeClient.CoreV1().Pods("ns1").Create(context.TODO(), &pod1, metav1.CreateOptions{})
		createdPod, _ := tfc.waitForPodInNamespace("ns1", "pod1", time.Second)
		require.NotNil(t, createdPod)
		tfc.client.CrdV1beta1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
		res, _ := tfc.waitForTraceflow("tf1", crdv1beta1.Running, time.Second)
		require.NotNil(t, res)
		// DataplaneTag should be allocated by Controller.
		assert.True(t, res.Status.DataplaneTag > 0)
		assert.Equal(t, numRunningTraceflows(), 1)

		// Test Controller handling of successful Traceflow.
		res.Status.Results = []crdv1beta1.NodeResult{
			// Sender
			{
				Observations: []crdv1beta1.Observation{{Component: crdv1beta1.ComponentSpoofGuard}},
			},
			// Receiver
			{
				Observations: []crdv1beta1.Observation{{Action: crdv1beta1.ActionDelivered}},
			},
		}
		tfc.client.CrdV1beta1().Traceflows().Update(context.TODO(), res, metav1.UpdateOptions{})
		res, _ = tfc.waitForTraceflow("tf1", crdv1beta1.Succeeded, time.Second)
		assert.NotNil(t, res)
		// DataplaneTag should be deallocated by Controller.
		assert.True(t, res.Status.DataplaneTag == 0)
		assert.Equal(t, numRunningTraceflows(), 0)
		tfc.client.CrdV1beta1().Traceflows().Delete(context.TODO(), "tf1", metav1.DeleteOptions{})
	})

	t.Run("timeoutTraceflow", func(t *testing.T) {
		startTime := time.Now()
		tfc.client.CrdV1beta1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
		res, _ := tfc.waitForTraceflow("tf1", crdv1beta1.Running, time.Second)
		assert.NotNil(t, res)
		res, _ = tfc.waitForTraceflow("tf1", crdv1beta1.Failed, defaultTimeoutDuration*2)
		assert.NotNil(t, res)
		assert.True(t, time.Now().Sub(startTime) >= time.Second*time.Duration(tf1.Spec.Timeout))
		assert.Equal(t, res.Status.Reason, traceflowTimeout)
		assert.True(t, res.Status.DataplaneTag == 0)
		assert.Equal(t, numRunningTraceflows(), 0)
	})

	close(stopCh)
}

func (tfc *traceflowController) waitForPodInNamespace(ns string, name string, timeout time.Duration) (*corev1.Pod, error) {
	var pod *corev1.Pod
	var err error
	if err = wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		// Make sure dummy Pod is synced by informer
		pod, err = tfc.podLister.Pods(ns).Get(name)
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return pod, nil
}

func (tfc *traceflowController) waitForTraceflow(name string, phase crdv1beta1.TraceflowPhase, timeout time.Duration) (*crdv1beta1.Traceflow, error) {
	var tf *crdv1beta1.Traceflow
	var err error
	if err = wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, false, func(ctx context.Context) (bool, error) {
		tf, err = tfc.client.CrdV1beta1().Traceflows().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil || tf.Status.Phase != phase {
			return false, nil
		}
		return true, nil
	}); err != nil {
		return nil, err
	}
	return tf, nil
}

func newCRDClientset() *fakeversioned.Clientset {
	client := fakeversioned.NewSimpleClientset()

	client.PrependReactor("create", "traceflows", k8stesting.ReactionFunc(func(action k8stesting.Action) (bool, runtime.Object, error) {
		tf := action.(k8stesting.CreateAction).GetObject().(*crdv1beta1.Traceflow)

		// Fake client does not set CreationTimestamp.
		if tf.ObjectMeta.CreationTimestamp == (metav1.Time{}) {
			tf.ObjectMeta.CreationTimestamp.Time = time.Now()
		}

		return false, tf, nil
	}))

	return client
}

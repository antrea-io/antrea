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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	ops "github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	fakeversioned "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
)

var alwaysReady = func() bool { return true }

const informerDefaultResync time.Duration = 30 * time.Second

type traceflowController struct {
	*Controller
	client             versioned.Interface
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
}

func newController() *traceflowController {
	client := fake.NewSimpleClientset()
	crdClient := newCRDClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	controller := NewTraceflowController(crdClient,
		informerFactory.Core().V1().Pods(),
		crdInformerFactory.Ops().V1alpha1().Traceflows())
	controller.traceflowListerSynced = alwaysReady
	return &traceflowController{
		controller,
		crdClient,
		informerFactory,
		crdInformerFactory,
	}
}

func TestTraceflow(t *testing.T) {
	// Use shorter timeout.
	timeoutDuration = 2 * time.Second
	timeoutCheckInterval = timeoutDuration / 2

	tfc := newController()
	stopCh := make(chan struct{})
	tfc.crdInformerFactory.Start(stopCh)
	go tfc.Run(stopCh)

	numRunningTraceflows := func() int {
		tfc.runningTraceflowsMutex.Lock()
		defer tfc.runningTraceflowsMutex.Unlock()
		return len(tfc.runningTraceflows)
	}

	tf1 := ops.Traceflow{
		ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
		Spec: ops.TraceflowSpec{
			Source:      ops.Source{Namespace: "ns1", Pod: "pod1"},
			Destination: ops.Destination{Namespace: "ns2", Pod: "pod2"},
		},
	}

	tfc.client.OpsV1alpha1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
	res, _ := tfc.waitForTraceflow("tf1", ops.Running, time.Second)
	assert.NotNil(t, res)
	// DataplaneTag should be allocated by Controller.
	assert.True(t, res.Status.DataplaneTag > 0)
	assert.Equal(t, numRunningTraceflows(), 1)

	// Test Controller handling of successful Traceflow.
	res.Status.Results = []ops.NodeResult{
		// Sender
		{
			Observations: []ops.Observation{{Component: ops.SpoofGuard}},
		},
		// Receiver
		{
			Observations: []ops.Observation{{Action: ops.Delivered}},
		},
	}
	tfc.client.OpsV1alpha1().Traceflows().Update(context.TODO(), res, metav1.UpdateOptions{})
	res, _ = tfc.waitForTraceflow("tf1", ops.Succeeded, time.Second)
	assert.NotNil(t, res)
	// DataplaneTag should be deallocated by Controller.
	assert.True(t, res.Status.DataplaneTag == 0)
	assert.Equal(t, numRunningTraceflows(), 0)
	tfc.client.OpsV1alpha1().Traceflows().Delete(context.TODO(), "tf1", metav1.DeleteOptions{})

	// Test Traceflow timeout.
	startTime := time.Now()
	tfc.client.OpsV1alpha1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
	res, _ = tfc.waitForTraceflow("tf1", ops.Running, time.Second)
	assert.NotNil(t, res)
	res, _ = tfc.waitForTraceflow("tf1", ops.Failed, timeoutDuration*2)
	assert.NotNil(t, res)
	assert.True(t, time.Now().Sub(startTime) >= timeoutDuration)
	assert.Equal(t, res.Status.Reason, traceflowTimeout)
	assert.True(t, res.Status.DataplaneTag == 0)
	assert.Equal(t, numRunningTraceflows(), 0)

	close(stopCh)
}

func (tfc *traceflowController) waitForTraceflow(name string, phase ops.TraceflowPhase, timeout time.Duration) (*ops.Traceflow, error) {
	var tf *ops.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		tf, err = tfc.client.OpsV1alpha1().Traceflows().Get(context.TODO(), name, metav1.GetOptions{})
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
		tf := action.(k8stesting.CreateAction).GetObject().(*ops.Traceflow)

		// Fake client does not set CreationTimestamp.
		if tf.ObjectMeta.CreationTimestamp == (metav1.Time{}) {
			tf.ObjectMeta.CreationTimestamp.Time = time.Now()
		}

		return false, tf, nil
	}))

	return client
}

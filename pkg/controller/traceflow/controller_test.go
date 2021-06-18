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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
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
		crdInformerFactory.Crd().V1alpha1().Traceflows())
	controller.traceflowListerSynced = alwaysReady
	return &traceflowController{
		controller,
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
	tfc.crdInformerFactory.Start(stopCh)
	go tfc.Run(stopCh)

	numRunningTraceflows := func() int {
		tfc.runningTraceflowsMutex.Lock()
		defer tfc.runningTraceflowsMutex.Unlock()
		return len(tfc.runningTraceflows)
	}

	tf1 := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{Name: "tf1", UID: "uid1"},
		Spec: crdv1alpha1.TraceflowSpec{
			Source:      crdv1alpha1.Source{Namespace: "ns1", Pod: "pod1"},
			Destination: crdv1alpha1.Destination{Namespace: "ns2", Pod: "pod2"},
			Timeout:     2, // 2 seconds timeout
		},
	}

	tfc.client.CrdV1alpha1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
	res, _ := tfc.waitForTraceflow("tf1", crdv1alpha1.Running, time.Second)
	assert.NotNil(t, res)
	// DataplaneTag should be allocated by Controller.
	assert.True(t, res.Status.DataplaneTag > 0)
	assert.Equal(t, numRunningTraceflows(), 1)

	// Test Controller handling of successful Traceflow.
	res.Status.Results = []crdv1alpha1.NodeResult{
		// Sender
		{
			Observations: []crdv1alpha1.Observation{{Component: crdv1alpha1.ComponentSpoofGuard}},
		},
		// Receiver
		{
			Observations: []crdv1alpha1.Observation{{Action: crdv1alpha1.ActionDelivered}},
		},
	}
	tfc.client.CrdV1alpha1().Traceflows().Update(context.TODO(), res, metav1.UpdateOptions{})
	res, _ = tfc.waitForTraceflow("tf1", crdv1alpha1.Succeeded, time.Second)
	assert.NotNil(t, res)
	// DataplaneTag should be deallocated by Controller.
	assert.True(t, res.Status.DataplaneTag == 0)
	assert.Equal(t, numRunningTraceflows(), 0)
	tfc.client.CrdV1alpha1().Traceflows().Delete(context.TODO(), "tf1", metav1.DeleteOptions{})

	// Test Traceflow timeout.
	startTime := time.Now()
	tfc.client.CrdV1alpha1().Traceflows().Create(context.TODO(), &tf1, metav1.CreateOptions{})
	res, _ = tfc.waitForTraceflow("tf1", crdv1alpha1.Running, time.Second)
	assert.NotNil(t, res)
	res, _ = tfc.waitForTraceflow("tf1", crdv1alpha1.Failed, defaultTimeoutDuration*2)
	assert.NotNil(t, res)
	assert.True(t, time.Now().Sub(startTime) >= time.Second*time.Duration(tf1.Spec.Timeout))
	assert.Equal(t, res.Status.Reason, traceflowTimeout)
	assert.True(t, res.Status.DataplaneTag == 0)
	assert.Equal(t, numRunningTraceflows(), 0)

	close(stopCh)
}

func (tfc *traceflowController) waitForTraceflow(name string, phase crdv1alpha1.TraceflowPhase, timeout time.Duration) (*crdv1alpha1.Traceflow, error) {
	var tf *crdv1alpha1.Traceflow
	var err error
	if err = wait.Poll(100*time.Millisecond, timeout, func() (bool, error) {
		tf, err = tfc.client.CrdV1alpha1().Traceflows().Get(context.TODO(), name, metav1.GetOptions{})
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
		tf := action.(k8stesting.CreateAction).GetObject().(*crdv1alpha1.Traceflow)

		// Fake client does not set CreationTimestamp.
		if tf.ObjectMeta.CreationTimestamp == (metav1.Time{}) {
			tf.ObjectMeta.CreationTimestamp.Time = time.Now()
		}

		return false, tf, nil
	}))

	return client
}

func Test_podIPsIndexFunc(t *testing.T) {
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
			args:    args{obj: &corev1.Pod{}},
			want:    nil,
			wantErr: false,
		},
		{
			name:    "zero IPs",
			args:    args{obj: &corev1.Pod{Status: corev1.PodStatus{PodIPs: []corev1.PodIP{}}}},
			want:    nil,
			wantErr: false,
		},
		{
			name: "PodFailed with podIPs",
			args: args{
				obj: &corev1.Pod{
					Status: corev1.PodStatus{
						PodIPs: []corev1.PodIP{{IP: "1.2.3.4"}, {IP: "aaaa::bbbb"}},
						Phase:  corev1.PodFailed,
					},
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "PodRunning with podIPs",
			args: args{
				obj: &corev1.Pod{
					Status: corev1.PodStatus{
						PodIPs: []corev1.PodIP{{IP: "1.2.3.4"}, {IP: "aaaa::bbbb"}},
						Phase:  corev1.PodRunning,
					},
				},
			},
			want:    []string{"1.2.3.4", "aaaa::bbbb"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := podIPsIndexFunc(tt.args.obj)
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

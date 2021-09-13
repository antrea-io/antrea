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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeWatcher struct {
	*Watcher
	clientset       *fake.Clientset
	informerFactory informers.SharedInformerFactory
}

func newWatcher(t *testing.T) (*fakeWatcher, func()) {
	clientset := fake.NewSimpleClientset()
	ctrl := gomock.NewController(t)
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	w := NewWatcher(clientset, informerFactory)
	return &fakeWatcher{
		Watcher:         w,
		clientset:       clientset,
		informerFactory: informerFactory,
	}, ctrl.Finish
}

func TestConfigMapUpdateEvent(t *testing.T) {
	w, closeFn := newWatcher(t)
	defer closeFn()
	defer w.queue.ShutDown()

	stopCh := make(chan struct{})
	defer close(stopCh)
	w.informerFactory.Start(stopCh)
	w.informerFactory.WaitForCacheSync(stopCh)

	oldCm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-config",
		},
		Data: map[string]string{
			antreAgentConfigKey:      "agent.config",
			antreControllerConfigKey: "controller.config",
		},
	}
	newCm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-config",
		},
		Data: map[string]string{
			antreAgentConfigKey:      "agent.config.update",
			antreControllerConfigKey: "controller.config.update",
		},
	}
	agentds := &apps.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			UID:       uuid.NewUUID(),
			Name:      "antrea-agent",
			Namespace: "kube-system",
		},
		Spec: apps.DaemonSetSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: "foo/bar",
						},
					},
					DNSPolicy: v1.DNSDefault,
				},
			},
		},
	}

	controller := &apps.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			UID:         uuid.NewUUID(),
			Name:        "antrea-controller",
			Namespace:   "kube-system",
			Annotations: make(map[string]string),
		},
		Spec: apps.DeploymentSpec{
			Replicas: func() *int32 { i := int32(1); return &i }(),
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Image: "foo/bar",
						},
					},
				},
			},
		},
	}
	ctx := context.Background()
	_, err := w.clientset.CoreV1().ConfigMaps("kube-system").Create(ctx, oldCm, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.clientset.AppsV1().Deployments("kube-system").Create(ctx, controller, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.clientset.AppsV1().DaemonSets("kube-system").Create(ctx, agentds, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run(stopCh)

	_, err = w.clientset.CoreV1().ConfigMaps("kube-system").Update(ctx, newCm, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	newagent, err := w.clientset.AppsV1().DaemonSets("kube-system").Get(ctx, "antrea-agent", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations := newagent.Spec.Template.Annotations
	_, ok := annotations[fileChangeAnnotation]
	assert.Equal(t, true, ok)
	newcontroller, err := w.clientset.AppsV1().Deployments("kube-system").Get(ctx, "antrea-controller", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annotations = newcontroller.Spec.Template.Annotations
	_, ok = annotations[fileChangeAnnotation]
	assert.Equal(t, true, ok)
}

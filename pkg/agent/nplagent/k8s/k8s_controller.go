// +build !windows

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

package k8s

import (
	"sync"
	"time"

	nplutils "github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/portcache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

var ctrlonce sync.Once

const podResyncPeriod = 60 * time.Minute

type Controller struct {
	PortTable  *portcache.PortTable
	KubeClient clientset.Interface
}

func NewNPLController(kubeClient clientset.Interface) *Controller {
	return &Controller{KubeClient: kubeClient}
}

func (c *Controller) SetupEventHandlers(k8sinfo informers.SharedInformerFactory) {
	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addPod := obj.(*corev1.Pod).DeepCopy()
			if nplutils.GetHostname() == addPod.Spec.NodeName {
				c.HandleAddPod(addPod)
			}
		},

		DeleteFunc: func(obj interface{}) {
			deletePod, ok := obj.(*corev1.Pod)
			if !ok {
				// Pod was deleted but its final state is unrecorded.
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Warningf("couldn't get object from tombstone %#v", obj)
					return
				}
				deletePod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					klog.Warningf("Tombstone contained object that is not a Pod: %#v", obj)
					return
				}
			}
			if nplutils.GetHostname() == deletePod.Spec.NodeName {
				c.HandleDeletePod(deletePod)
			}
		},

		UpdateFunc: func(old, cur interface{}) {
			oldPod, newPod := old.(*corev1.Pod).DeepCopy(), cur.(*corev1.Pod).DeepCopy()
			if oldPod.ResourceVersion != newPod.ResourceVersion &&
				nplutils.GetHostname() == newPod.Spec.NodeName {
				c.HandleUpdatePod(oldPod, newPod)
			}
		},
	}
	podInformer := k8sinfo.Core().V1().Pods()
	podInformer.Informer().AddEventHandlerWithResyncPeriod(podEventHandler, podResyncPeriod)
}

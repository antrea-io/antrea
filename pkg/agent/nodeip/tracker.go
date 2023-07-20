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

package nodeip

import (
	"net"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	coreinformers "k8s.io/client-go/informers/core/v1"
)

type Checker interface {
	IsNodeIP(ip string) bool

	HasSynced() bool
}

type Tracker struct {
	nodeInformer coreinformers.NodeInformer
	nodeIPs      map[string]string
	mutex        sync.RWMutex
}

func NewTracker(nodeInformer coreinformers.NodeInformer) *Tracker {
	tracker := &Tracker{
		nodeInformer: nodeInformer,
		nodeIPs:      map[string]string{},
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    tracker.OnNodeAdd,
		UpdateFunc: tracker.OnNodeUpdate,
		DeleteFunc: tracker.OnNodeDelete,
	})
	return tracker
}

func (t *Tracker) OnNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.addNodeIPs(node)
}

func (t *Tracker) OnNodeUpdate(oldObj, obj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := obj.(*corev1.Node)
	if reflect.DeepEqual(oldNode.Status.Addresses, node.Status.Addresses) {
		return
	}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.deleteNodeIPs(oldNode)
	t.addNodeIPs(node)
}

func (t *Tracker) OnNodeDelete(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.deleteNodeIPs(node)
}

func (t *Tracker) addNodeIPs(node *corev1.Node) {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP || addr.Type == corev1.NodeExternalIP {
			if net.ParseIP(addr.Address) != nil {
				t.nodeIPs[addr.Address] = node.Name
			}
		}
	}
}

func (t *Tracker) deleteNodeIPs(node *corev1.Node) {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP || addr.Type == corev1.NodeExternalIP {
			if net.ParseIP(addr.Address) != nil {
				if t.nodeIPs[addr.Address] == node.Name {
					delete(t.nodeIPs, addr.Address)
				}
			}
		}
	}
}

func (t *Tracker) IsNodeIP(ip string) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	_, exists := t.nodeIPs[ip]
	return exists
}

func (t *Tracker) HasSynced() bool {
	return t.nodeInformer.Informer().HasSynced()
}

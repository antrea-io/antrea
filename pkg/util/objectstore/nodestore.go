// Copyright 2025 Antrea Authors
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

package objectstore

import (
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const (
	nodeNameIndex = "nodeName"
	nodeIPIndex   = "nodeIP"
)

// NodeStore interface provides Node-specific operations
type NodeStore interface {
	GetNodeByNameAndTime(name string, startTime time.Time) (*corev1.Node, bool)
	// GetNodeByIPAndTime returns the Node which had the given internal, external or transport IP
	// at the given time. ip must be in its canonical form, as returned by net.IP.String.
	GetNodeByIPAndTime(ip string, startTime time.Time) (*corev1.Node, bool)
	Run(stopCh <-chan struct{})
	HasSynced() bool
}

// nodeStore embeds ObjectStore[*corev1.Node] to provide Node-specific methods
type nodeStore struct {
	*ObjectStore[*corev1.Node]
}

// Validate that *nodeStore implements the NodeStore interface
var _ NodeStore = &nodeStore{}

func NewNodeStore(nodeInformer cache.SharedIndexInformer) *nodeStore {
	config := StoreConfig[*corev1.Node]{
		DeleteQueueName: "nodeStoreNodesToDelete",
		Indexers:        cache.Indexers{nodeNameIndex: nodeNameIndexFunc, nodeIPIndex: nodeIPIndexFunc},
		GetObjectCreationTimestamp: func(node *corev1.Node, now time.Time) time.Time {
			if node.Status.Phase == corev1.NodePending {
				return now
			}
			return node.GetCreationTimestamp().Time
		},
	}
	return &nodeStore{
		ObjectStore: NewObjectStore(nodeInformer, config),
	}
}

// GetNodeByNameAndTime provides a Node-specific method for getting Nodes by name and time
func (s *nodeStore) GetNodeByNameAndTime(name string, startTime time.Time) (*corev1.Node, bool) {
	return s.GetObjectByIndexAndTime(nodeNameIndex, name, startTime)
}

func nodeNameIndexFunc(obj interface{}) ([]string, error) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return nil, fmt.Errorf("obj is not Node: %+v", obj)
	}
	return []string{node.Name}, nil
}

// GetNodeByIPAndTime returns the Node which had the given IP at the given time (see nodeIPIndexFunc).
func (s *nodeStore) GetNodeByIPAndTime(ip string, startTime time.Time) (*corev1.Node, bool) {
	return s.GetObjectByIndexAndTime(nodeIPIndex, ip, startTime)
}

// nodeIPIndexFunc indexes a Node by its internal and external IPs, and by its transport IPs, which
// Antrea uses as the source address of the traffic that the Node forwards to the Pods running on
// other Nodes without tunneling it, when they are not its internal IPs. The IPs are indexed in
// their canonical form, as returned by net.IP.String.
func nodeIPIndexFunc(obj interface{}) ([]string, error) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return nil, fmt.Errorf("obj is not Node: %+v", obj)
	}
	ips := sets.New[string]()
	addIP := func(ip net.IP) {
		if ip != nil {
			ips.Insert(ip.String())
		}
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP || addr.Type == corev1.NodeExternalIP {
			addIP(net.ParseIP(addr.Address))
		}
	}
	// An invalid annotation is ignored, as the index function must not fail for a valid Node.
	if transportIPs, err := k8s.GetNodeAddrsFromAnnotations(node, types.NodeTransportAddressAnnotationKey); err == nil && transportIPs != nil {
		addIP(transportIPs.IPv4)
		addIP(transportIPs.IPv6)
	}
	return sets.List(ips), nil
}

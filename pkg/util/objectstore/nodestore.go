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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const nodeNameIndex = "nodeName"

// NodeStore interface provides Node-specific operations
type NodeStore interface {
	GetNodeByNameAndTime(name string, startTime time.Time) (*corev1.Node, bool)
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
		Indexers:        cache.Indexers{nodeNameIndex: nodeNameIndexFunc},
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

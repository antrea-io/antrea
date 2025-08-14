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

package nodemanager

import (
	"sync"

	v1 "k8s.io/api/core/v1"
)

type NodeManager struct {
	hostname string
	mu       sync.Mutex
	node     *v1.Node
}

func NewNodeManager(hostname string) *NodeManager {
	return &NodeManager{
		hostname: hostname,
	}
}

// Node returns a copy of the latest node object, or nil if the Node has not yet been seen.
func (n *NodeManager) Node() *v1.Node {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.node == nil {
		return nil
	}
	return n.node.DeepCopy()
}

// OnNodeChange is a handler for Node creation and update.
func (n *NodeManager) OnNodeChange(node *v1.Node) {
	if node.Name != n.hostname {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.node = node
}

// OnNodeDelete is a handler for Node deletes.
func (n *NodeManager) OnNodeDelete(_ *v1.Node) {
}

// OnNodeSynced is called after the cache is synced and all pre-existing Nodes have been reported
func (n *NodeManager) OnNodeSynced() {}

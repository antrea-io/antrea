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

// NodeManager is to replace the upstream implementation:
// https://raw.githubusercontent.com/kubernetes/kubernetes/refs/tags/v1.34.2/pkg/proxy/node.go.
// The upstream NodeManager starts its own informerFactory, which is undesirable for Antrea as we rely on a single
// shared informerFactory for all controllers. To avoid the overhead and duplication of running an additional
// informerFactory, Antrea provides a lightweight replacement NodeManager implementation instead.
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

// OnNodeChange handles Node add and update events. Only the Node matching the local hostname is stored.
func (n *NodeManager) OnNodeChange(node *v1.Node) {
	if node.Name != n.hostname {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.node = node
}

// OnNodeDelete handles Node delete events. No-op because Antrea does not need to track deletion state.
func (n *NodeManager) OnNodeDelete(_ *v1.Node) {
}

// OnNodeSynced is invoked after the shared informer cache has fully synced. No-op for this lightweight NodeManager.
func (n *NodeManager) OnNodeSynced() {}

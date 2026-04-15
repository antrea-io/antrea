// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	corev1 "k8s.io/api/core/v1"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

// Snapshot is an immutable view of the local Node and the AntreaNodeConfig that
// applies to this Node (nodeSelector match, oldest creationTimestamp wins), as
// computed by the AntreaNodeConfig controller. Subscribers use it together with
// feature-specific static configuration.
type Snapshot struct {
	Node *corev1.Node
	// AntreaNodeConfig is a deep copy of the effective AntreaNodeConfig for this
	// Node at snapshot build time, or nil when none matches or the list failed.
	AntreaNodeConfig *crdv1alpha1.AntreaNodeConfig
	// AntreaNodeConfigListError is err.Error() from the lister List call when non-empty.
	AntreaNodeConfigListError string
}

// NewSnapshot returns a snapshot with deep-copied API objects suitable for
// passing to subscribers and for reflect.DeepEqual deduplication.
func NewSnapshot(node *corev1.Node, antreaNodeConfig *crdv1alpha1.AntreaNodeConfig, listErr error) *Snapshot {
	s := &Snapshot{}
	if listErr != nil {
		s.AntreaNodeConfigListError = listErr.Error()
	}
	if node != nil {
		s.Node = node.DeepCopy()
	}
	if antreaNodeConfig != nil {
		s.AntreaNodeConfig = antreaNodeConfig.DeepCopy()
	}
	return s
}

// DeepCopy returns a deep copy of the snapshot.
func (s *Snapshot) DeepCopy() *Snapshot {
	if s == nil {
		return nil
	}
	out := &Snapshot{AntreaNodeConfigListError: s.AntreaNodeConfigListError}
	if s.Node != nil {
		out.Node = s.Node.DeepCopy()
	}
	if s.AntreaNodeConfig != nil {
		out.AntreaNodeConfig = s.AntreaNodeConfig.DeepCopy()
	}
	return out
}

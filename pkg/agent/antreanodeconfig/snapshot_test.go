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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

func TestSnapshotDeepCopy(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var s *Snapshot
		assert.Nil(t, s.DeepCopy())
	})

	t.Run("node and AntreaNodeConfig", func(t *testing.T) {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"k": "v"}}}
		anc := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: "a1"}}
		s := NewSnapshot(node, anc, nil)
		cp := s.DeepCopy()
		require.NotNil(t, cp)
		assert.NotSame(t, s.Node, cp.Node)
		assert.NotSame(t, s.AntreaNodeConfig, cp.AntreaNodeConfig)
		cp.Node.Labels["k"] = "mutated"
		assert.Equal(t, "v", s.Node.Labels["k"])
	})
}

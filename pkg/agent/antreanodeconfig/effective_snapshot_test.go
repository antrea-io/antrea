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

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
)

func TestEffectiveSnapshotDeepCopy(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var s *EffectiveSnapshot
		assert.Nil(t, s.DeepCopy())
	})

	t.Run("empty bridge", func(t *testing.T) {
		s := &EffectiveSnapshot{}
		cp := s.DeepCopy()
		require.NotNil(t, cp)
		assert.Nil(t, cp.SecondaryOVSBridge)
	})

	t.Run("with bridge", func(t *testing.T) {
		s := &EffectiveSnapshot{
			SecondaryOVSBridge: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: "eth0", AllowedVLANs: []string{"100"}},
				},
			},
		}
		cp := s.DeepCopy()
		require.NotNil(t, cp)
		require.NotNil(t, cp.SecondaryOVSBridge)
		assert.NotSame(t, s.SecondaryOVSBridge, cp.SecondaryOVSBridge)
		assert.Equal(t, s.SecondaryOVSBridge.BridgeName, cp.SecondaryOVSBridge.BridgeName)
		cp.SecondaryOVSBridge.BridgeName = "mutated"
		assert.Equal(t, "br1", s.SecondaryOVSBridge.BridgeName)
	})
}

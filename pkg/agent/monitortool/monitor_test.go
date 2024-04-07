// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitortool

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

var (
	nodeLatencyMonitor1 = &v1alpha2.NodeLatencyMonitor{
		Spec: v1alpha2.NodeLatencyMonitorSpec{
			PingInterval:        "1s",
			PingTimeout:         "1s",
			PingConcurrentLimit: 1,
		},
	}
	nodeLatencyMonitor2 = &v1alpha2.NodeLatencyMonitor{
		Spec: v1alpha2.NodeLatencyMonitorSpec{
			PingInterval:        "2s",
			PingTimeout:         "2s",
			PingConcurrentLimit: 2,
		},
	}
	latencyConfig1 = &LatencyConfig{
		Enable:   true,
		Interval: time.Second,
		Timeout:  time.Second,
		Limit:    1,
	}
	latencyConfig2 = &LatencyConfig{
		Enable:   true,
		Interval: 2 * time.Second,
		Timeout:  2 * time.Second,
		Limit:    2,
	}
	latencyConfig3 = &LatencyConfig{
		Enable: false,
	}
	monitorTool = &MonitorTool{
		// Buffer size is 10 to avoid blocking
		latencyConfigChanged: make(chan struct{}, 10),
		latencyConfig:        latencyConfig1,
	}
)

func TestMonitorTool_onNodeLatencyMonitorAdd(t *testing.T) {
	tests := []struct {
		nodeLatencyMonitor *v1alpha2.NodeLatencyMonitor
		expected           *LatencyConfig
	}{
		{
			nodeLatencyMonitor: nodeLatencyMonitor1,
			expected:           latencyConfig1,
		},
		{
			nodeLatencyMonitor: nodeLatencyMonitor2,
			expected:           latencyConfig2,
		},
	}

	for _, tt := range tests {
		monitorTool.onNodeLatencyMonitorAdd(tt.nodeLatencyMonitor)
		assert.Equal(t, tt.expected, monitorTool.latencyConfig)
	}
}

func TestMonitorTool_onNodeLatencyMonitorUpdate(t *testing.T) {
	tests := []struct {
		oldNodeLatencyMonitor *v1alpha2.NodeLatencyMonitor
		newNodeLatencyMonitor *v1alpha2.NodeLatencyMonitor
		expected              *LatencyConfig
	}{
		{
			oldNodeLatencyMonitor: nodeLatencyMonitor1,
			newNodeLatencyMonitor: nodeLatencyMonitor2,
			expected:              latencyConfig1, // Same generation
		},
	}

	for _, tt := range tests {
		monitorTool.onNodeLatencyMonitorUpdate(tt.oldNodeLatencyMonitor, tt.newNodeLatencyMonitor)
		assert.Equal(t, tt.expected, monitorTool.latencyConfig)
	}
}

func TestMonitorTool_onNodeLatencyMonitorDelete(t *testing.T) {
	tests := []struct {
		nodeLatencyMonitor *v1alpha2.NodeLatencyMonitor
		expected           *LatencyConfig
	}{
		{
			nodeLatencyMonitor: nodeLatencyMonitor1,
			expected:           latencyConfig3,
		},
	}

	for _, tt := range tests {
		monitorTool.onNodeLatencyMonitorDelete(tt.nodeLatencyMonitor)
		assert.Equal(t, tt.expected, monitorTool.latencyConfig)
	}
}

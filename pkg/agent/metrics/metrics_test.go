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

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetMetricCategoriesMap(t *testing.T) {
	testcases := []struct {
		// input
		metricsMap map[string]bool
		// expectations
		expMetricsMap    map[string]bool
		expEnableMetrics bool
	}{
		{metricsMap: map[string]bool{
			AllMetrics:           true,
			PodMetrics:           false,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}, expMetricsMap: map[string]bool{
			AllMetrics:           true,
			PodMetrics:           true,
			NetworkPolicyMetrics: true,
			OVSMetrics:           true,
		}, expEnableMetrics: true},
		{metricsMap: map[string]bool{
			AllMetrics:           false,
			PodMetrics:           true,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}, expMetricsMap: map[string]bool{
			AllMetrics:           false,
			PodMetrics:           true,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}, expEnableMetrics: true},
		{metricsMap: map[string]bool{
			AllMetrics:           false,
			PodMetrics:           false,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}, expMetricsMap: map[string]bool{
			AllMetrics:           false,
			PodMetrics:           false,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}, expEnableMetrics: false},
	}
	for _, tc := range testcases {
		// Reset the global MetricCategoriesMap
		MetricCategoriesMap = map[string]bool{
			AllMetrics:           false,
			PodMetrics:           false,
			NetworkPolicyMetrics: false,
			OVSMetrics:           false,
		}
		enableMetrics := SetMetricCategoriesMap(tc.metricsMap)
		assert.Equal(t, tc.expEnableMetrics, enableMetrics)
		assert.Equal(t, tc.expMetricsMap, MetricCategoriesMap)
	}
}

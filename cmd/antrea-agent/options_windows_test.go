// +build windows

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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

func TestCheckUnsupportedFeatures(t *testing.T) {
	testCases := []struct {
		desc   string
		config AgentConfig
		pass   bool
	}{
		{
			"default",
			AgentConfig{},
			true,
		},
		{
			"feature gates",
			AgentConfig{
				FeatureGates: map[string]bool{
					"AntreaProxy":        false,
					"AntreaPolicy":       true,
					"Traceflow":          false,
					"FlowExporter":       true,
					"NetworkPolicyStats": true,
				},
			},
			true,
		},
		{
			"netdev datapath",
			AgentConfig{OVSDatapathType: string(ovsconfig.OVSDatapathNetdev)},
			false,
		},
		{
			"noEncap mode",
			AgentConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap.String()},
			false,
		},
		{
			"GRE tunnel",
			AgentConfig{TunnelType: ovsconfig.GRETunnel},
			false,
		},
		{
			"IPsec tunnel",
			AgentConfig{EnableIPSecTunnel: true},
			false,
		},
		{
			"hybrid mode and GRE tunnel",
			AgentConfig{TrafficEncapMode: config.TrafficEncapModeHybrid.String(), TunnelType: ovsconfig.GRETunnel},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			o := &Options{config: &tc.config}
			err := o.complete(nil)
			assert.Nil(t, err, tc.desc)
			err = o.checkUnsupportedFeatures()
			if tc.pass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

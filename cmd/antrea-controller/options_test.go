// Copyright 2023 Antrea Authors
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

	"antrea.io/antrea/pkg/apis"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
)

func TestNewOptions(t *testing.T) {
	op := newOptions()
	op.setDefaults()
	assert.Equal(t, apis.AntreaControllerAPIPort, op.config.APIPort, "")
	assert.Equal(t, true, *op.config.EnablePrometheusMetrics)
	assert.Equal(t, true, *op.config.SelfSignedCert)
	assert.Equal(t, ipamIPv4MaskDefault, op.config.NodeIPAM.NodeCIDRMaskSizeIPv4)
	assert.Equal(t, ipamIPv6MaskDefault, op.config.NodeIPAM.NodeCIDRMaskSizeIPv6)
	assert.Equal(t, true, *op.config.IPsecCSRSignerConfig.SelfSignedCA)
	assert.Equal(t, true, *op.config.IPsecCSRSignerConfig.AutoApprove)
}

func TestValidateNodeIPAMControllerOptions(t *testing.T) {
	testCases := []struct {
		name           string
		nodeIPAMConfig controllerconfig.NodeIPAMConfig
		expectedErr    string
	}{
		{
			name: "valid config",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"172.100.0.0/20", "fd00:172:100::/60"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 64,
			},
			expectedErr: "",
		},
		{
			name: "invalid Node IPv6 CIDR size",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"172.100.0.0/20", "fd00:172:100::/60"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 100,
			},
			expectedErr: "the Node IPv6 CIDR size is too big, the cluster CIDR mask size cannot be greater than 16 more than the Node IPv6 CIDR mask size",
		},
		{
			name: "invalid ClusterCIDRs",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0", "a:b::0/64"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 70,
			},
			expectedErr: "cluster CIDRs [10.10.0.0 a:b::0/64] is invalid",
		},
		{
			name: "invalid empty ClusterCIDRs",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 780,
			},
			expectedErr: "at least one cluster CIDR must be specified",
		},
		{
			name: "too many ClusterCIDRs",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "a:b::0/64", "20.20.0.0/24"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 80,
			},
			expectedErr: "at most two cluster CIDRs may be specified",
		},
		{
			name: "at most one cluster CIDR of each type",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "20.20.0.0/24"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 80,
			},
			expectedErr: "at most one cluster CIDR may be specified for each IP family",
		},
		{
			name: "invalid Node IPv4 CIDR mask size",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "a:b::0/64"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 15,
				NodeCIDRMaskSizeIPv6: 80,
			},
			expectedErr: "Node IPv4 CIDR mask size 15 is invalid, should be between 16 and 30",
		},
		{
			name: "invalid Node IPv6 CIDR mask size",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "a:b::0/64"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 63,
			},
			expectedErr: "Node IPv6 CIDR mask size 63 is invalid, should be between 64 and 126",
		},
		{
			name: "invalid Service CIDR",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "a:b::0/64"},
				ServiceCIDR:          "1",
				ServiceCIDRv6:        "2620:124::0/64",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 80,
			},
			expectedErr: "Service CIDR 1 is invalid",
		},
		{
			name: "invalid secondary Service CIDR",
			nodeIPAMConfig: controllerconfig.NodeIPAMConfig{
				EnableNodeIPAM:       true,
				ClusterCIDRs:         []string{"10.10.0.0/16", "a:b::0/64"},
				ServiceCIDR:          "172.16.0.0/16",
				ServiceCIDRv6:        "2",
				NodeCIDRMaskSizeIPv4: 24,
				NodeCIDRMaskSizeIPv6: 80,
			},
			expectedErr: "secondary Service CIDR 2 is invalid",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := &Options{config: &controllerconfig.ControllerConfig{NodeIPAM: tc.nodeIPAMConfig}}
			err := o.validateNodeIPAMControllerOptions()
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}

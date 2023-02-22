//go:build windows
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
)

func TestCheckUnsupportedFeatures(t *testing.T) {
	testCases := []struct {
		desc   string
		config string
		pass   bool
	}{
		{
			"default",
			"",
			true,
		},
		{
			"feature gates",
			`
featureGates:
  AntreaProxy: false
  AntreaPolicy: true
  Traceflow: false
  FlowExporter: true
  NetworkPolicyStats: true
`,
			true,
		},
		{
			"noEncap mode",
			`
trafficEncapMode: noEncap
`,
			true,
		},
		{
			"GRE tunnel",
			`
tunnelType: gre
`,
			false,
		},
		{
			"IPsec encryption",
			`
trafficEncryptionMode: ipsec
`,
			false,
		},
		{
			"WireGuard encryption",
			`
trafficEncryptionMode: wireguard
`,
			false,
		},
		{
			"hybrid mode and GRE tunnel",
			`
trafficEncapMode: hybrid
tunnelType: gre
`,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			configFile, cleanup := createTempConfig(t, tc.config)
			defer cleanup()

			o := newOptions()
			o.configFile = configFile
			err := o.complete(nil)
			assert.Nil(t, err, tc.desc)
			err = o.validate(nil)
			if tc.pass {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

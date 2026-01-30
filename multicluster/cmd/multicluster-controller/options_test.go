// Copyright 2022 Antrea Authors
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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/yaml"

	"antrea.io/antrea/v2/multicluster"
	mcsv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
)

func TestComplete(t *testing.T) {
	testCases := []struct {
		name       string
		o          Options
		configFile string
		exceptdErr error
	}{
		{
			name: "options with valid PodCIDRs",
			o: Options{
				configFile:          "./testdata/antrea-mc-config-with-valid-podcidrs.yml",
				SelfSignedCert:      false,
				ServiceCIDR:         "",
				PodCIDRs:            nil,
				GatewayIPPrecedence: "",
				EndpointIPType:      "",
			},
			exceptdErr: nil,
		},
		{
			name: "options with empty PodCIDRs",
			o: Options{
				configFile:          "./testdata/antrea-mc-config-with-empty-podcidrs.yml",
				SelfSignedCert:      false,
				ServiceCIDR:         "",
				PodCIDRs:            nil,
				GatewayIPPrecedence: "",
				EndpointIPType:      "",
			},
			exceptdErr: nil,
		},
		{
			name: "options without PodCIDRs",
			o: Options{
				configFile:          "./testdata/antrea-mc-config-with-invalid-podcidrs.yml",
				SelfSignedCert:      false,
				ServiceCIDR:         "10.100.0.0/16",
				PodCIDRs:            nil,
				GatewayIPPrecedence: "",
				EndpointIPType:      "",
			},
			exceptdErr: fmt.Errorf("failed to parse podCIDRs, invalid CIDR string 10.10a.0.0/16"),
		},
		{
			name: "options with invalid endpointIPType",
			o: Options{
				configFile:          "./testdata/antrea-mc-config-with-invalid-endpointiptype.yml",
				SelfSignedCert:      false,
				ServiceCIDR:         "10.100.0.0/16",
				PodCIDRs:            nil,
				GatewayIPPrecedence: "",
				EndpointIPType:      "",
			},
			exceptdErr: fmt.Errorf("invalid endpointIPType: None, only 'PodIP' or 'ClusterIP' is allowed"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.o.complete(nil)
			assert.Equal(t, tt.exceptdErr, err)
		})
	}
}

func TestUnmarshalDefaultConfig(t *testing.T) {
	configBytes := multicluster.DefaultControllerManagerConfigBytes
	var multiclusterConfig mcsv1alpha1.MultiClusterConfig
	// Note that we use UnmarshalStrict from k8s.io/apimachinery/pkg/util/yaml, which will first
	// convert the YAML data to JSON. The mcsv1alpha1.MultiClusterConfig struct definition does
	// not have yaml tags.
	assert.NoError(t, yaml.UnmarshalStrict(configBytes, &multiclusterConfig), "Default config should unmarshal correctly")
}

func TestLoadConfig(t *testing.T) {
	configBytes := multicluster.DefaultControllerManagerConfigBytes
	var multiclusterConfig mcsv1alpha1.MultiClusterConfig
	o := newOptions()
	assert.NoError(t, o.loadConfig(configBytes, &multiclusterConfig))
}

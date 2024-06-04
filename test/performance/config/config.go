// Copyright 2024 Antrea Authors
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

package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	WaitInterval   = 5 * time.Second
	DefaultTimeout = 60 * time.Second
)

type ScaleConfiguration struct {
	TearDown           bool `yaml:"teardown"`             // TearDown specifies whether to tear down the test Pods after testing.
	IPv6               bool `yaml:"ipv6"`                 // IPv6 specifies whether to enable IPv6.
	RealNode           bool `yaml:"real_node"`            // RealNode specifies whether to use simulator Antrea agents in testing.
	RepeatTimes        int  `yaml:"repeat_times"`         // RepeatTimes specifies the number of times to repeat the test.
	PodsNumPerNs       int  `yaml:"pods_num_per_ns"`      // PodsNumPerNs specifies the number of Pods per Namespace.
	SvcNumPerNs        int  `yaml:"svc_num_per_ns"`       // SvcNumPerNs specifies the number of Services per Namespace.
	NpNumPerNs         int  `yaml:"np_num_per_ns"`        // NpNumPerNs specifies the number of Networkpolicies per Namespace.
	SkipDeployWorkload bool `yaml:"skip_deploy_workload"` // SkipDeployWorkload specifies whether to skip deploying workload test Pods during testing.
	NamespaceNum       int  `yaml:"namespace_num"`        // NamespaceNum specifies the number of Namespaces to create.
}

type Scale struct {
	Name        string `yaml:"name"`
	Package     string `yaml:"package"`
	RepeatTimes int    `yaml:"repeat_times"`
}

type ScaleList struct {
	ScaleConfiguration `yaml:",inline"`
	Scales             []Scale `yaml:"scales"`
}

func ParseConfigs(configPath string) (*ScaleList, error) {
	scaleList := &ScaleList{}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, scaleList)
	return scaleList, err
}

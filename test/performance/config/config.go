// Copyright 2021 Antrea Authors
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
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type ScaleConfiguration struct {
	TearDown         bool `yaml:"teardown"`
	IPv6             bool `yaml:"ipv6"`
	RealNode         bool `yaml:"real_node"`
	RepeatTimes      int  `yaml:"repeat_times"`
	PodsNumPerNode   int  `yaml:"pods_num_per_node"`
	SvcNumPerNode    int  `yaml:"svc_num_per_node"`
	NpNumPerNode     int  `yaml:"np_num_per_node"`
	RecordPrometheus bool `yaml:"record_prometheus"`
	PreWorkload      bool `yaml:"pre_workload"`
	NamespaceNum     int  `yaml:"namespace_num"`
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
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, scaleList)
	return scaleList, err
}

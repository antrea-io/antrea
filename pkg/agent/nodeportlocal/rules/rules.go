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

package rules

// PodPortRules is an interface to abstract operations on rules for Pods
type PodPortRules interface {
	Init() error
	AddRule(nodePort int, podIP string, podPort int, protocol string) error
	DeleteRule(nodePort int, podIP string, podPort int, protocol string) error
	DeleteAllRules() error
	AddAllRules(nplList []PodNodePort) error
}

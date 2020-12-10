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

type FlowAggregatorConfig struct {
	// Provide the flow collector address as string with format <IP>:<port>[:<proto>], where proto is tcp or udp.
	// If no L4 transport proto is given, we consider tcp as default.
	// Defaults to "".
	FlowCollectorAddr string `yaml:"flowCollectorAddr,omitempty"`
	// Provide flow export interval as a duration string. This determines how often the flow aggregator exports flow
	// records to the flow collector.
	// Flow export interval should be greater than or equal to 1s (one second).
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// Defaults to "60s".
	FlowExportInterval string `yaml:"flowExportInterval,omitempty"`
}

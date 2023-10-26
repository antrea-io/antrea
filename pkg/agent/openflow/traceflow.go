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

package openflow

import (
	"antrea.io/libOpenflow/openflow15"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureTraceflow struct {
	cachedFlows *flowCategoryCache
}

func (f *featureTraceflow) getFeatureName() string {
	return "Traceflow"
}

func newFeatureTraceflow() *featureTraceflow {
	return &featureTraceflow{
		cachedFlows: newFlowCategoryCache(),
	}
}

func (f *featureTraceflow) initFlows() []*openflow15.FlowMod {
	return []*openflow15.FlowMod{}
}

func (f *featureTraceflow) replayFlows() []*openflow15.FlowMod {
	return []*openflow15.FlowMod{}
}

func (f *featureTraceflow) initGroups() []binding.OFEntry {
	return nil
}

func (f *featureTraceflow) replayGroups() []binding.OFEntry {
	return nil
}

func (f *featureTraceflow) replayMeters() []binding.OFEntry {
	return nil
}

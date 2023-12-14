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

package types

// TrafficControlFlowPriority sets the priority for flows installed by OpenFlow client using InstallTrafficControlMarkFlows
// method.
type TrafficControlFlowPriority string

const (
	// TrafficControlFlowPriorityHigh is not used yet.
	TrafficControlFlowPriorityHigh TrafficControlFlowPriority = "high"
	// TrafficControlFlowPriorityMedium is for user-defined TrafficControl CRs.
	TrafficControlFlowPriorityMedium TrafficControlFlowPriority = "medium"
	// TrafficControlFlowPriorityLow is not used yet.
	TrafficControlFlowPriorityLow TrafficControlFlowPriority = "low"
)

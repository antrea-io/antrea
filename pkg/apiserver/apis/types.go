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

package apis

import "antrea.io/antrea/pkg/apis/controlplane/v1beta2"

// EndpointQueryResponse is the reply struct for anctl endpoint queries
type EndpointQueryResponse struct {
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

type Rule struct {
	PolicyRef v1beta2.NetworkPolicyReference `json:"policyref,omitempty"`
	Direction v1beta2.Direction              `json:"direction,omitempty"`
	RuleIndex int                            `json:"ruleindex,omitempty"`
}

type Endpoint struct {
	Namespace       string                           `json:"namespace,omitempty"`
	Name            string                           `json:"name,omitempty"`
	AppliedPolicies []v1beta2.NetworkPolicyReference `json:"policies,omitempty"`
	IngressSrcRules []Rule                           `json:"ingresssrcrules,omitempty"`
	EgressDstRules  []Rule                           `json:"egressdstrules,omitempty"`
}

type FeatureGateResponse struct {
	Component string `json:"component,omitempty"`
	Name      string `json:"name,omitempty"`
	Status    string `json:"status,omitempty"`
	Version   string `json:"version,omitempty"`
}

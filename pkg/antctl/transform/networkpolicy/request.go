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

package networkpolicy

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

// parsePeer parses Namespace/Pod name, empty string is returned if the argument is not of a
// valid Namespace/Pod reference (missing pod name or invalid format). Namespace will be set
// as default if missing, string without separator will be considered as pod name.
func parsePeer(str string) (string, string) {
	parts := strings.Split(str, "/")
	ns, pod := "", ""
	if len(parts) == 1 {
		ns, pod = "default", parts[0]
	} else if len(parts) == 2 {
		ns, pod = parts[0], parts[1]
	}
	return ns, pod
}

// NewNetworkPolicyEvaluation creates a new NetworkPolicyEvaluation resource
// request from the command-line arguments provided to antctl.
func NewNetworkPolicyEvaluation(args map[string]string) (runtime.Object, error) {
	var ns1, pod1, ns2, pod2 string
	if val, ok := args["source"]; ok {
		ns1, pod1 = parsePeer(val)
	}
	if val, ok := args["destination"]; ok {
		ns2, pod2 = parsePeer(val)
	}
	if pod1 == "" || pod2 == "" {
		return nil, fmt.Errorf("missing entities for NetworkPolicyEvaluation request: %v", args)
	}
	return &cpv1beta.NetworkPolicyEvaluation{
		Request: &cpv1beta.NetworkPolicyEvaluationRequest{
			Source:      cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: ns1, Name: pod1}},
			Destination: cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: ns2, Name: pod2}},
		},
	}, nil
}

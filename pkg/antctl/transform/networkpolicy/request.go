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

	cpv1beta "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
)

// parsePeer parses a Pod reference in the form [<Namespace>/]<name>.
// Namespace defaults to "default" when it is omitted.
func parsePeer(str string) (string, string, error) {
	parts := strings.Split(str, "/")
	if len(parts) == 1 && parts[0] != "" {
		return "default", parts[0], nil
	}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf("expected [<Namespace>/]<name>")
}

// NewNetworkPolicyEvaluation creates a new NetworkPolicyEvaluation resource
// request from the command-line arguments provided to antctl.
func NewNetworkPolicyEvaluation(args map[string]string) (runtime.Object, error) {
	source, ok := args["source"]
	if !ok {
		return nil, fmt.Errorf("--source (-S) must be specified")
	}
	ns1, pod1, err := parsePeer(source)
	if err != nil {
		return nil, fmt.Errorf("invalid source %q: %w", source, err)
	}

	destination, ok := args["destination"]
	if !ok {
		return nil, fmt.Errorf("--destination (-D) must be specified")
	}
	ns2, pod2, err := parsePeer(destination)
	if err != nil {
		return nil, fmt.Errorf("invalid destination %q: %w", destination, err)
	}
	return &cpv1beta.NetworkPolicyEvaluation{
		Request: &cpv1beta.NetworkPolicyEvaluationRequest{
			Source:      cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: ns1, Name: pod1}},
			Destination: cpv1beta.Entity{Pod: &cpv1beta.PodReference{Namespace: ns2, Name: pod2}},
		},
	}, nil
}

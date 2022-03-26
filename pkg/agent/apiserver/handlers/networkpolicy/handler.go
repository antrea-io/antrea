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

package networkpolicy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		npFilter, pod, err := newFilterFromURLQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var obj interface{}
		npq := aq.GetNetworkPolicyInfoQuerier()
		var nps []cpv1beta.NetworkPolicy

		if pod != "" {
			namespaceAndPodName := strings.Split(pod, "/")
			interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(namespaceAndPodName[1], namespaceAndPodName[0])
			if len(interfaces) > 0 {
				nps = npq.GetAppliedNetworkPolicies(namespaceAndPodName[1], namespaceAndPodName[0], npFilter)
			}
		} else {
			nps = npq.GetNetworkPolicies(npFilter)
		}
		obj = cpv1beta.NetworkPolicyList{Items: nps}

		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// From user shorthand input to cpv1beta1.NetworkPolicyType
var mapToNetworkPolicyType = map[string]cpv1beta.NetworkPolicyType{
	"NP":    cpv1beta.K8sNetworkPolicy,
	"K8SNP": cpv1beta.K8sNetworkPolicy,
	"ACNP":  cpv1beta.AntreaClusterNetworkPolicy,
	"ANP":   cpv1beta.AntreaNetworkPolicy,
}

// Create a Network Policy Filter from URL Query
func newFilterFromURLQuery(query url.Values) (*querier.NetworkPolicyQueryFilter, string, error) {
	namespace, pod := query.Get("namespace"), query.Get("pod")
	if pod != "" {
		if !strings.Contains(pod, "/") {
			return nil, "", fmt.Errorf("invalid pod option foramt. Expected format is podNamespace/podName")
		} else if namespace != "" {
			return nil, "", fmt.Errorf("namespace option should not be used with pod option")
		}
	}
	strSourceType := strings.ToUpper(query.Get("type"))
	npSourceType, ok := mapToNetworkPolicyType[strSourceType]
	if strSourceType != "" && !ok {
		return nil, "", fmt.Errorf("invalid policy source type. Valid values are K8sNP, ACNP and ANP")
	}
	source := query.Get("source")
	name := query.Get("name")
	if name != "" && (source != "" || namespace != "" || pod != "" || strSourceType != "") {
		return nil, "", fmt.Errorf("with a policy name, none of the other options should be set")
	}
	return &querier.NetworkPolicyQueryFilter{
		Name:       name,
		SourceName: source,
		Namespace:  namespace,
		SourceType: npSourceType,
	}, pod, nil
}

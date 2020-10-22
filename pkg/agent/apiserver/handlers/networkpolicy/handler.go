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

	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	cpv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		npFilter, err := newFilterFromURLQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var obj interface{}
		npq := aq.GetNetworkPolicyInfoQuerier()
		var nps []cpv1beta1.NetworkPolicy

		if npFilter.Pod != "" {
			interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(npFilter.Pod, npFilter.Namespace)
			if len(interfaces) > 0 {
				nps = npq.GetAppliedNetworkPolicies(npFilter.Pod, npFilter.Namespace, npFilter)
			}
		} else {
			nps = npq.GetNetworkPolicies(npFilter)
		}

		obj = cpv1beta1.NetworkPolicyList{Items: nps}

		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

// From user shorthand input to cpv1beta1.NetworkPolicyType
var mapToNetworkPolicyType = map[string]cpv1beta1.NetworkPolicyType{
	"NP":    cpv1beta1.K8sNetworkPolicy,
	"K8SNP": cpv1beta1.K8sNetworkPolicy,
	"ACNP":  cpv1beta1.AntreaClusterNetworkPolicy,
	"ANP":   cpv1beta1.AntreaNetworkPolicy,
}

// Create a Network Policy Filter from URL Query
func newFilterFromURLQuery(query url.Values) (*querier.NetworkPolicyQueryFilter, error) {
	namespace := query.Get("namespace")
	pod := query.Get("pod")
	if pod != "" && namespace == "" {
		return nil, fmt.Errorf("with a pod name, namespace must be provided")
	}

	strSourceType := strings.ToUpper(query.Get("type"))
	npSourceType, ok := mapToNetworkPolicyType[strSourceType]
	if strSourceType != "" && !ok {
		return nil, fmt.Errorf("invalid reference type. It should be K8sNP, ACNP or ANP")
	}

	return &querier.NetworkPolicyQueryFilter{
		Name:       query.Get("name"),
		Namespace:  namespace,
		Pod:        pod,
		SourceType: npSourceType,
	}, nil
}

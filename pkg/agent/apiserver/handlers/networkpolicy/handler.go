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
	"sort"
	"strings"

	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

// HandleFunc creates a http.HandlerFunc which uses an AgentNetworkPolicyInfoQuerier
// to query network policy rules in current agent.
func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		npFilter, err := parseURLQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var obj interface{}
		npq := aq.GetNetworkPolicyInfoQuerier()
		var nps []cpv1beta.NetworkPolicy

		if npFilter.Pod != "" {
			interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(npFilter.Pod, npFilter.Namespace)
			if len(interfaces) > 0 {
				nps = npq.GetAppliedNetworkPolicies(npFilter.Pod, npFilter.Namespace, npFilter)
			}
		} else {
			nps = npq.GetNetworkPolicies(npFilter)
		}
		npSorter := &NPSorter{
			networkPolicies: nps,
			sortBy:          r.URL.Query().Get("sort-by"),
		}
		sort.Sort(npSorter)
		obj = cpv1beta.NetworkPolicyList{Items: npSorter.networkPolicies}

		if err := json.NewEncoder(w).Encode(obj); err != nil {
			http.Error(w, "Failed to encode response: "+err.Error(), http.StatusInternalServerError)
		}
	}
}

var (
	sortByEffectivePriority = "effectivePriority"
	// Compute a tierPriority value in between the application tier and the baseline tier,
	// which can be used to sort policies by tier.
	effectiveTierPriorityK8sNP = (networkpolicy.DefaultTierPriority + networkpolicy.BaselineTierPriority) / 2
)

type NPSorter struct {
	networkPolicies []cpv1beta.NetworkPolicy
	sortBy          string
}

func (nps *NPSorter) Len() int { return len(nps.networkPolicies) }
func (nps *NPSorter) Swap(i, j int) {
	nps.networkPolicies[i], nps.networkPolicies[j] = nps.networkPolicies[j], nps.networkPolicies[i]
}
func (nps *NPSorter) Less(i, j int) bool {
	switch nps.sortBy {
	case sortByEffectivePriority:
		var ti, tj int32
		if nps.networkPolicies[i].TierPriority == nil {
			ti = effectiveTierPriorityK8sNP
		} else {
			ti = *nps.networkPolicies[i].TierPriority
		}
		if nps.networkPolicies[j].TierPriority == nil {
			tj = effectiveTierPriorityK8sNP
		} else {
			tj = *nps.networkPolicies[j].TierPriority
		}
		pi, pj := nps.networkPolicies[i].Priority, nps.networkPolicies[j].Priority
		if ti != tj {
			return ti < tj
		}
		if pi != nil && pj != nil && *pi != *pj {
			return *pi < *pj
		}
		fallthrough
	default:
		// Do not need a tie-breaker here since NetworkPolicy names are set as UID
		// of the source policy and will be unique.
		return nps.networkPolicies[i].Name < nps.networkPolicies[j].Name
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
func parseURLQuery(query url.Values) (*querier.NetworkPolicyQueryFilter, error) {
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

	source := query.Get("source")
	name := query.Get("name")
	if name != "" && (source != "" || namespace != "" || pod != "" || strSourceType != "") {
		return nil, fmt.Errorf("with a name, none of the other fields can be set")
	}

	sortBy := query.Get("sort-by")
	if sortBy != "" && sortBy != sortByEffectivePriority {
		return nil, fmt.Errorf("unsupported sort-by option. Supported value is %s", sortByEffectivePriority)
	}
	return &querier.NetworkPolicyQueryFilter{
		Name:       name,
		SourceName: source,
		Namespace:  namespace,
		Pod:        pod,
		SourceType: npSourceType,
	}, nil
}

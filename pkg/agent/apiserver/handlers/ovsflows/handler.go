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

package ovsflows

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	agentquerier "antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/antctl/transform/common"
	"antrea.io/antrea/pkg/features"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/querier"
)

// Response is the response struct of ovsflows command.
type Response struct {
	Flow string `json:"flow,omitempty"`
}

func dumpMatchedFlows(aq agentquerier.AgentQuerier, flowKeys []string) ([]Response, error) {
	resps := []Response{}
	for _, f := range flowKeys {
		flowStr, err := aq.GetOVSCtlClient().DumpMatchedFlow(f)
		if err != nil {
			klog.Errorf("Failed to dump flows %s: %v", f, err)
			return nil, err
		}
		if flowStr != "" {
			resps = append(resps, Response{flowStr})
		}
	}
	return resps, nil
}

func dumpFlows(aq agentquerier.AgentQuerier, table binding.TableIDType) ([]Response, error) {
	resps := []Response{}
	var flowStrs []string
	var err error
	if table != binding.TableIDAll {
		flowStrs, err = aq.GetOVSCtlClient().DumpTableFlows(uint8(table))
	} else {
		flowStrs, err = aq.GetOVSCtlClient().DumpFlows()
	}
	if err != nil {
		return nil, err
	}
	for _, s := range flowStrs {
		resps = append(resps, Response{s})
	}
	return resps, nil
}

func dumpMatchedGroups(aq agentquerier.AgentQuerier, groupIDs []binding.GroupIDType) ([]Response, error) {
	resps := []Response{}
	for _, g := range groupIDs {
		groupStr, err := aq.GetOVSCtlClient().DumpGroup(uint32(g))
		if err != nil {
			klog.Errorf("Failed to dump group %d: %v", g, err)
			return nil, err
		}
		if groupStr != "" {
			resps = append(resps, Response{groupStr})
		}
	}
	return resps, nil
}

// nil is returned if the flow table can not be found (the passed table name or
// number is invalid).
func getTableFlows(aq agentquerier.AgentQuerier, tables string) ([]Response, error) {
	var resps []Response
	for _, tableSeg := range strings.Split(tables, ",") {
		tableSeg = strings.TrimSpace(tableSeg)
		var tableNumber binding.TableIDType
		// Table nubmer is a 8-bit unsigned integer.
		n, err := strconv.ParseUint(tableSeg, 10, 8)
		if err == nil {
			tableNumber = binding.TableIDType(n)
			if openflow.GetFlowTableName(tableNumber) == "" {
				return nil, nil
			}
		} else {
			tableNumber = openflow.GetFlowTableNumber(tableSeg)
			if tableNumber == binding.TableIDAll {
				return nil, nil
			}
		}
		resp, err := dumpFlows(aq, tableNumber)
		if err != nil {
			return nil, err
		}
		resps = append(resps, resp...)
	}
	return resps, nil
}

// nil is returned if the passed group IDs are invalid.
func getGroups(aq agentquerier.AgentQuerier, groups string) ([]Response, error) {
	if strings.EqualFold(groups, "all") {
		groupStrs, err := aq.GetOVSCtlClient().DumpGroups()
		if err != nil {
			return nil, err
		}
		resps := make([]Response, 0, len(groupStrs))
		for _, s := range groupStrs {
			resps = append(resps, Response{s})
		}
		return resps, nil
	}

	var groupIDs []binding.GroupIDType
	for _, id := range strings.Split(groups, ",") {
		id = strings.TrimSpace(id)
		// Group ID is a 32-bit unsigned integer.
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, nil
		}
		groupIDs = append(groupIDs, binding.GroupIDType(n))
	}
	if groupIDs == nil {
		return nil, nil
	}
	return dumpMatchedGroups(aq, groupIDs)
}

func getPodFlows(aq agentquerier.AgentQuerier, podName, namespace string) ([]Response, error) {
	interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(podName, namespace)
	if len(interfaces) == 0 {
		return nil, nil
	}

	flowKeys := aq.GetOpenflowClient().GetPodFlowKeys(interfaces[0].InterfaceName)
	return dumpMatchedFlows(aq, flowKeys)

}

func getServiceFlows(aq agentquerier.AgentQuerier, serviceName, namespace string) ([]Response, error) {
	flowKeys, groupIDs, found := aq.GetProxier().GetServiceFlowKeys(serviceName, namespace)
	if !found {
		return nil, nil
	}
	resps, err := dumpMatchedFlows(aq, flowKeys)
	if err != nil {
		return nil, err
	}
	groupResps, err := dumpMatchedGroups(aq, groupIDs)
	if err != nil {
		return nil, err
	}
	return append(resps, groupResps...), nil
}

func getNetworkPolicyFlows(aq agentquerier.AgentQuerier, npName, namespace string) ([]Response, error) {
	if len(aq.GetNetworkPolicyInfoQuerier().GetNetworkPolicies(&querier.NetworkPolicyQueryFilter{SourceName: npName, Namespace: namespace})) == 0 {
		// NetworkPolicy not found.
		return nil, nil
	}

	flowKeys := aq.GetOpenflowClient().GetNetworkPolicyFlowKeys(npName, namespace)
	return dumpMatchedFlows(aq, flowKeys)
}

// HandleFunc returns the function which can handle API requests to "/ovsflows".
func HandleFunc(aq agentquerier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var resps []Response
		pod := r.URL.Query().Get("pod")
		service := r.URL.Query().Get("service")
		networkPolicy := r.URL.Query().Get("networkpolicy")
		namespace := r.URL.Query().Get("namespace")
		table := r.URL.Query().Get("table")
		groups := r.URL.Query().Get("groups")

		if (pod != "" || service != "" || networkPolicy != "") && namespace == "" {
			http.Error(w, "namespace must be provided", http.StatusBadRequest)
			return
		}

		if pod == "" && service == "" && networkPolicy == "" && namespace == "" && table == "" && groups == "" {
			resps, err = dumpFlows(aq, binding.TableIDAll)
		} else if pod != "" {
			// Pod Namespace must be provided to dump flows of a Pod.
			resps, err = getPodFlows(aq, pod, namespace)
		} else if service != "" {
			if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
				http.Error(w, "AntreaProxy is not enabled", http.StatusServiceUnavailable)
				return
			}
			resps, err = getServiceFlows(aq, service, namespace)
		} else if networkPolicy != "" {
			resps, err = getNetworkPolicyFlows(aq, networkPolicy, namespace)
		} else if table != "" {
			resps, err = getTableFlows(aq, table)
			if err == nil && resps == nil {
				http.Error(w, "invalid table name or number", http.StatusBadRequest)
				return
			}
		} else if groups != "" {
			resps, err = getGroups(aq, groups)
			if err == nil && resps == nil {
				http.Error(w, "invalid group ID", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "unsupported parameter combination", http.StatusBadRequest)
			return
		}

		if err != nil {
			klog.Errorf("Failed to dump flows: %v", err)
			http.Error(w, "OVS flow dumping failed", http.StatusInternalServerError)
			return
		}
		if resps == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		err = json.NewEncoder(w).Encode(resps)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"FLOW"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Flow}
}

func (r Response) SortRows() bool {
	return false
}

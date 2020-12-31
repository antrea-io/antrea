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

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	"github.com/vmware-tanzu/antrea/pkg/querier"
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

// nil is returned if the flow table can not be found (the passed table name or
// number is invalid).
func getTableFlows(aq agentquerier.AgentQuerier, table string) ([]Response, error) {
	var resps []Response
	for _, tableSeg := range strings.Split(strings.TrimSpace(table), ",") {
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

func getPodFlows(aq agentquerier.AgentQuerier, podName, namespace string) ([]Response, error) {
	interfaces := aq.GetInterfaceStore().GetContainerInterfacesByPod(podName, namespace)
	if len(interfaces) == 0 {
		return nil, nil
	}

	flowKeys := aq.GetOpenflowClient().GetPodFlowKeys(interfaces[0].InterfaceName)
	return dumpMatchedFlows(aq, flowKeys)

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
		networkPolicy := r.URL.Query().Get("networkpolicy")
		namespace := r.URL.Query().Get("namespace")
		table := r.URL.Query().Get("table")

		if (pod != "" || networkPolicy != "") && namespace == "" {
			http.Error(w, "namespace must be provided", http.StatusBadRequest)
			return
		}

		if pod == "" && networkPolicy == "" && namespace == "" && table == "" {
			resps, err = dumpFlows(aq, binding.TableIDAll)
		} else if pod != "" {
			// Pod Namespace must be provided to dump flows of a Pod.
			resps, err = getPodFlows(aq, pod, namespace)
		} else if networkPolicy != "" {
			resps, err = getNetworkPolicyFlows(aq, networkPolicy, namespace)
		} else if table != "" {
			resps, err = getTableFlows(aq, table)
			if err == nil && resps == nil {
				http.Error(w, "invalid table name or number", http.StatusBadRequest)
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

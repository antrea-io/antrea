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

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
)

// Response is the response struct of ovsflows command.
type Response struct {
	Flow string `json:"flow,omitempty"`
}

func getAllFlows(aq querier.AgentQuerier) ([]Response, error) {
	resps := []Response{}
	flowStrs, err := aq.GetOfctlClient().DumpFlows()
	if err != nil {
		klog.Errorf("Failed to dump flows: %v", err)
		return nil, err
	}
	for _, s := range flowStrs {
		resps = append(resps, Response{s})
	}
	return resps, nil
}

func getPodFlows(aq querier.AgentQuerier, podName, namespace string) ([]Response, error) {
	intf, ok := aq.GetInterfaceStore().GetContainerInterface(podName, namespace)
	if !ok {
		return nil, nil
	}

	flowKeys := aq.GetOpenflowClient().GetPodFlowKeys(intf.InterfaceName)
	resps := []Response{}
	for _, f := range flowKeys {
		flowStrs, err := aq.GetOfctlClient().DumpFlows(f)
		if err != nil {
			klog.Errorf("Failed to dump flows: %v", err)
			return nil, err
		}
		for _, s := range flowStrs {
			resps = append(resps, Response{s})
		}
	}
	return resps, nil
}

// HandleFunc returns the function which can handle API requests to "/ovsflows".
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var resps []Response
		podName := r.URL.Query().Get("pod")
		namespace := r.URL.Query().Get("namespace")

		if podName == "" && namespace == "" {
			resps, err = getAllFlows(aq)
		} else if podName != "" && namespace != "" {
			// Pod Namespace must be provided to dump flows of a Pod.
			resps, err = getPodFlows(aq, podName, namespace)
		} else {
			// Not supported.
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
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

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

package agentinfo

import (
	"encoding/json"
	"net/http"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// HandleFunc returns the function which can handle queries issued by agentinfo commands.
// The handler function populates Antrea agent information to the response.
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentInfo := new(v1beta1.AntreaAgentInfo)
		aq.GetAgentInfo(agentInfo, false)
		info := &apis.AntreaAgentInfoResponse{
			Version:                     agentInfo.Version,
			PodRef:                      agentInfo.PodRef,
			NodeRef:                     agentInfo.NodeRef,
			OVSInfo:                     agentInfo.OVSInfo,
			NetworkPolicyControllerInfo: agentInfo.NetworkPolicyControllerInfo,
			LocalPodNum:                 agentInfo.LocalPodNum,
			AgentConditions:             agentInfo.AgentConditions,
			NodeSubnets:                 agentInfo.NodeSubnets,
		}
		err := json.NewEncoder(w).Encode(info)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding AntreaAgentInfo to json: %v", err)
		}
	}
}

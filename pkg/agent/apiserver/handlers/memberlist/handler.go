// Copyright 2023 Antrea Authors
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

package memberlist

import (
	"encoding/json"
	"net/http"
	"reflect"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/querier"
)

func generateResponse(node *v1.Node, aliveNodes sets.Set[string]) apis.MemberlistResponse {
	status := "Dead"
	if aliveNodes.Has(node.Name) {
		status = "Alive"
	}
	return apis.MemberlistResponse{
		NodeName: node.Name,
		Status:   status,
		IP:       node.Status.Addresses[0].Address,
	}
}

// HandleFunc returns the function which can handle queries issued by the memberlist command.
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		memberlistCluster := aq.GetMemberlistCluster()
		if reflect.ValueOf(memberlistCluster).IsNil() {
			// The error message must match the "FOO is not enabled" pattern to pass antctl e2e tests.
			http.Error(w, "memberlist is not enabled", http.StatusServiceUnavailable)
			return
		}
		var memberlist []apis.MemberlistResponse
		allNodes, _ := aq.GetNodeLister().List(labels.Everything())
		aliveNodes := memberlistCluster.AliveNodes()
		for _, node := range allNodes {
			memberlist = append(memberlist, generateResponse(node, aliveNodes))
		}

		err := json.NewEncoder(w).Encode(memberlist)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding Memberlist to json: %v", err)
		}
	}
}

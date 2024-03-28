// Copyright 2022 Antrea Authors
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

package multicast

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/multicast"
	"antrea.io/antrea/pkg/querier"
)

func generateResponse(podName string, podNamespace string, trafficStats *multicast.PodTrafficStats) apis.MulticastResponse {
	return apis.MulticastResponse{
		PodName:      podName,
		PodNamespace: podNamespace,
		Inbound:      strconv.FormatUint(trafficStats.Inbound, 10),
		Outbound:     strconv.FormatUint(trafficStats.Outbound, 10),
	}
}

// HandleFunc returns the function which can handle queries issued by 'antctl get podmulticaststats' command.
// It will return Pod multicast traffic statistics for the local Node.
func HandleFunc(mq querier.AgentMulticastInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mq == nil || reflect.ValueOf(mq).IsNil() {
			http.Error(w, "Multicast is not enabled", http.StatusServiceUnavailable)
			return
		}
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")

		responses := []apis.MulticastResponse{}
		if name != "" && ns != "" {
			podStats := mq.GetPodStats(name, ns)
			if podStats == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			responses = append(responses, generateResponse(name, ns, podStats))
		} else if ns == "" && name != "" {
			http.Error(w, "name option should be used with namespace option", http.StatusServiceUnavailable)
			return
		} else {
			allPodStats := mq.GetAllPodsStats()
			for iface, trafficStats := range allPodStats {
				if ns == "" || ns == iface.PodNamespace {
					responses = append(responses, generateResponse(iface.PodName, iface.PodNamespace, trafficStats))
				}
			}
		}

		err := json.NewEncoder(w).Encode(responses)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

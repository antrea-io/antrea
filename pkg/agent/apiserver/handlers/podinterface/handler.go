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

package podinterface

import (
	"encoding/json"
	"net"
	"net/http"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/querier"
)

func generateResponse(i *interfacestore.InterfaceConfig) apis.PodInterfaceResponse {
	return apis.PodInterfaceResponse{
		PodName:       i.ContainerInterfaceConfig.PodName,
		PodNamespace:  i.ContainerInterfaceConfig.PodNamespace,
		InterfaceName: i.InterfaceName,
		IPs:           getPodIPs(i.IPs),
		MAC:           i.MAC.String(),
		PortUUID:      i.OVSPortConfig.PortUUID,
		OFPort:        i.OVSPortConfig.OFPort,
		ContainerID:   i.ContainerInterfaceConfig.ContainerID,
	}
}

func getPodIPs(ips []net.IP) []string {
	ipStrs := make([]string, len(ips))
	for i := range ips {
		ipStrs[i] = ips[i].String()
	}
	return ipStrs
}

// HandleFunc returns the function which can handle queries issued by the pod-interface command.
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")

		var pods []apis.PodInterfaceResponse
		for _, v := range aq.GetInterfaceStore().GetInterfacesByType(interfacestore.ContainerInterface) {
			podName := (*v.ContainerInterfaceConfig).PodName
			podNS := (*v.ContainerInterfaceConfig).PodNamespace
			if (len(name) == 0 || name == podName) && (len(ns) == 0 || ns == podNS) {
				pods = append(pods, generateResponse(v))
			}
		}

		if len(name) > 0 && len(pods) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		err := json.NewEncoder(w).Encode(pods)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

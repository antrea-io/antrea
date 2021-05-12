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
	"strings"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/antctl/transform/common"
)

// Response describes the response struct of pod-interface command.
type Response struct {
	PodName       string   `json:"name,omitempty" antctl:"name,Name of the Pod"`
	PodNamespace  string   `json:"podNamespace,omitempty"`
	InterfaceName string   `json:"interfaceName,omitempty"`
	IPs           []string `json:"ips,omitempty"`
	MAC           string   `json:"mac,omitempty"`
	PortUUID      string   `json:"portUUID,omitempty"`
	OFPort        int32    `json:"ofPort,omitempty"`
	ContainerID   string   `json:"containerID,omitempty"`
}

func generateResponse(i *interfacestore.InterfaceConfig) Response {
	return Response{
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

// HandleFunc returns the function which can handle queries issued by the pod-interface command,
func HandleFunc(aq querier.AgentQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		ns := r.URL.Query().Get("namespace")

		var pods []Response
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

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME", "INTERFACE-NAME", "IP", "MAC", "PORT-UUID", "OF-PORT", "CONTAINER-ID"}
}

func (r Response) GetContainerIDStr() string {
	if len(r.ContainerID) > 12 {
		return r.ContainerID[0:11]
	}
	return r.ContainerID
}

func (r Response) GetTableRow(_ int) []string {
	return []string{r.PodNamespace, r.PodName, r.InterfaceName, strings.Join(r.IPs, ", "), r.MAC, r.PortUUID, common.Int32ToString(r.OFPort), r.GetContainerIDStr()}
}

func (r Response) SortRows() bool {
	return true
}

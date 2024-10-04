// Copyright 2024 Antrea Authors
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

package bgppeer

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strconv"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/controller/bgp"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc returns the function which can handle queries issued by the bgppeers command.
func HandleFunc(bq querier.AgentBGPPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bq == nil || reflect.ValueOf(bq).IsNil() {
			// The error message must match the "FOO is not enabled" pattern to pass antctl e2e tests.
			http.Error(w, "bgp is not enabled", http.StatusServiceUnavailable)
			return
		}

		peers, err := bq.GetBGPPeerStatus(r.Context())
		if err != nil {
			if errors.Is(err, bgp.ErrBGPPolicyNotFound) {
				http.Error(w, "there is no effective bgp policy applied to the Node", http.StatusNotFound)
				return
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		var bgpPeersResp []apis.BGPPeerResponse
		for _, peer := range peers {
			bgpPeersResp = append(bgpPeersResp, apis.BGPPeerResponse{
				Peer:  net.JoinHostPort(peer.Address, strconv.Itoa(int(peer.Port))),
				ASN:   peer.ASN,
				State: string(peer.SessionState),
			})
		}

		if err := json.NewEncoder(w).Encode(bgpPeersResp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding BGPPeersResp to json")
		}
	}
}

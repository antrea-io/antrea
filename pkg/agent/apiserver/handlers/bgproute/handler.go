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

package bgproute

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/controller/bgp"
	"antrea.io/antrea/pkg/querier"
)

// HandleFunc returns the function which can handle queries issued by the bgproutes command.
func HandleFunc(bq querier.AgentBGPPolicyInfoQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if bq == nil || reflect.ValueOf(bq).IsNil() {
			// The error message must match the "FOO is not enabled" pattern to pass antctl e2e tests.
			http.Error(w, "bgp is not enabled", http.StatusServiceUnavailable)
			return
		}

		values := r.URL.Query()
		bgpRouteType := values.Get("type")
		var ipv4Only, ipv6Only bool
		if values.Has("ipv4-only") {
			if values.Get("ipv4-only") != "" {
				http.Error(w, "invalid query", http.StatusBadRequest)
				return
			}
			ipv4Only = true
		}
		if values.Has("ipv6-only") {
			if values.Get("ipv6-only") != "" {
				http.Error(w, "invalid query", http.StatusBadRequest)
				return
			}
			ipv6Only = true
		}
		if ipv4Only && ipv6Only {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}

		bgpRoutes, err := bq.GetBGPRoutes(r.Context())
		if err != nil {
			if errors.Is(err, bgp.ErrBGPPolicyNotFound) {
				http.Error(w, "there is no effective bgp policy applied to the Node", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var bgpRoutesResp []apis.BGPRouteResponse
		for bgpRoute, routeMetadata := range bgpRoutes {
			if ipv4Only && !utilnet.IsIPv4CIDRString(bgpRoute.Prefix) {
				continue
			}
			if ipv6Only && !utilnet.IsIPv6CIDRString(bgpRoute.Prefix) {
				continue
			}
			if bgpRouteType != "" && bgpRouteType != string(routeMetadata.Type) {
				continue
			}
			bgpRoutesResp = append(bgpRoutesResp, apis.BGPRouteResponse{
				Route:     bgpRoute.Prefix,
				Type:      string(routeMetadata.Type),
				K8sObjRef: routeMetadata.K8sObjRef,
			})
		}
		// make sure that we provide a stable order for the API response
		slices.SortFunc(bgpRoutesResp, func(a, b apis.BGPRouteResponse) int {
			pA, _ := netip.ParsePrefix(a.Route)
			pB, _ := netip.ParsePrefix(b.Route)
			// IPv4 routes first, then IPv6 routes
			if pA.Addr().Is4() && !pB.Addr().Is4() {
				return -1
			}
			if !pA.Addr().Is4() && pB.Addr().Is4() {
				return 1
			}
			// both routes are from the same IP family, now order based on route type
			if n := strings.Compare(a.Type, b.Type); n != 0 {
				return n
			}
			// finally, for routes of the same IP family and type, order based on prefix
			// shorter prefixes come first; if the length is the same we order by IP
			if n := pA.Bits() - pB.Bits(); n != 0 {
				return n
			}
			return pA.Addr().Compare(pB.Addr())
		})

		if err := json.NewEncoder(w).Encode(bgpRoutesResp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.ErrorS(err, "Error when encoding BGPRoutesResp to json")
		}
	}
}

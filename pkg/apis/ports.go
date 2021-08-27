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

package apis

const (
	// AntreaControllerAPIPort is the default port for the antrea-controller APIServer.
	AntreaControllerAPIPort = 10349
	// AntreaAgentAPIPort is the default port for the antrea-agent APIServer.
	AntreaAgentAPIPort = 10350
	// AntreaAgentClusterMembershipPort is the default port for the antrea-agent cluster.
	// A gossip-based cluster will be created in the background when the egress feature is turned on.
	AntreaAgentClusterMembershipPort = 10351
	// WireGuardListenPort is the default port for WireGuard encrypted traffic.
	WireGuardListenPort = 51820
)

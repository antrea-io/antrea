// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"antrea.io/antrea/pkg/agent/flowexporter"
)

// ConnTrackDumper is an interface that is used to dump connections from conntrack module. This supports dumping through
// netfilter socket (OVS kernel datapath) and ovs-appctl command (OVS userspace datapath).
// In future, support will be extended to Windows.
type ConnTrackDumper interface {
	// DumpFlows returns a list of filtered connections and the number of total connections.
	DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, int, error)
	// GetMaxConnections returns the size of the connection tracking table.
	GetMaxConnections() (int, error)
}

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
	"net"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

var _ ConnTrackDumper = new(connTrackDumper)

type connTrackDumper struct {
	connTrack    ConnTrackInterfacer
	nodeConfig   *config.NodeConfig
	serviceCIDR  *net.IPNet
	datapathType string
	ovsctlClient ovsctl.OVSCtlClient
}

func NewConnTrackDumper(connTrack ConnTrackInterfacer, nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, dpType string, ovsctlClient ovsctl.OVSCtlClient) *connTrackDumper {
	return &connTrackDumper{
		connTrack,
		nodeConfig,
		serviceCIDR,
		dpType,
		ovsctlClient,
	}
}

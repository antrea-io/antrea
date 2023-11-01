//go:build !linux
// +build !linux

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
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
)

type connTrackOvsCtlWindows struct {
	connTrackOvsCtl
}

func (ct *connTrackOvsCtlWindows) GetMaxConnections() (int, error) {
	var zoneID int
	if ct.serviceCIDRv4.IsValid() {
		zoneID = openflow.CtZone
	} else {
		zoneID = openflow.CtZoneV6
	}
	// dpctl/ct-get-maxconns returns operation not supported on Windows node, use dpctl/ct-get-limits intead.
	cmdOutput, execErr := ct.ovsctlClient.RunAppctlCmd("dpctl/ct-get-limits", false, fmt.Sprintf("zone=%d", zoneID))
	if execErr != nil {
		return 0, fmt.Errorf("error when executing dpctl/ct-get-limits command: %v", execErr)
	}
	flowSlice := strings.Split(string(cmdOutput), ",")
	for _, fs := range flowSlice {
		if strings.HasPrefix(fs, "limit") {
			fields := strings.Split(fs, "=")
			maxConns, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return 0, fmt.Errorf("error when converting '%s' to int", fields[len(fields)-1])
			}
			return maxConns, nil
		}
	}
	return 0, fmt.Errorf("couldn't find limit field in dpctl/ct-get-limits command output '%s'", cmdOutput)
}

func NewConnTrackSystem(nodeConfig *config.NodeConfig, serviceCIDRv4 netip.Prefix, serviceCIDRv6 netip.Prefix, isAntreaProxyEnabled bool) *connTrackOvsCtlWindows {
	return &connTrackOvsCtlWindows{*NewConnTrackOvsAppCtl(nodeConfig, serviceCIDRv4, serviceCIDRv6, isAntreaProxyEnabled)}
}

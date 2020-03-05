// +build windows

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

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

const (
	ovsServiceName = "ovs-vswitchd"
)

func getOVSServiceStatus() (svc.State, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ovsServiceName)
	if err != nil {
		return 0, fmt.Errorf("failed to open service with name %s", ovsServiceName)
	}
	status, err := s.Query()
	if err != nil {
		return 0, err
	}
	return status.State, nil
}

// monitorOVSState checks the status of Service ovs-vswitchd. It disables the OVS Extension once the Service is stopped,
// and then the host networking should be controlled by Windows. It enables the OVS Extension once the Service is running.
func monitorOVSState(stopCh chan struct{}) {
	var ovsDisabled bool = true
	for {
		select {
		// exit monitoring if the service is stopped.
		case <-stopCh:
			break
		case <-time.Tick(2 * time.Second):
			state, err := getOVSServiceStatus()
			if err != nil {
				logger.Errorf("Failed to check status: %v", err)
				return
			}
			switch state {
			case svc.Paused:
				fallthrough
			case svc.Stopped:
				if !ovsDisabled {
					err = changeHNSNetworkExtensionStaus(util.LocalHNSNetwork, OVSExtensionID, false)
					if err != nil {
						logger.Errorf("Failed to disable OVS Extension on HNSNetwork %s: %v", util.LocalHNSNetwork, err)
					} else {
						logger.Infof("Service ovs-vswitchd is stopped, disable OVS Extension on HNSNetwork %s", util.LocalHNSNetwork)
						ovsDisabled = true
					}
				}
			case svc.Running:
				if ovsDisabled {
					// Don't need to check HNSNetwork here. It is because the existence of HNSNetwork is the precondition
					// of running ovs-vswitchd.
					err = changeHNSNetworkExtensionStaus(util.LocalHNSNetwork, OVSExtensionID, true)
					if err != nil {
						logger.Errorf("Failed to enable OVS Extension on HNSNetwork %s: %v", util.LocalHNSNetwork, err)
					} else {
						logger.Infof("Service ovs-vswitchd is running, enable OVS Extension on HNSNetwork %s", util.LocalHNSNetwork)
						ovsDisabled = false
					}
				}
			}
		}
	}
}

// Copyright 2026 Antrea Authors
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

package util

import (
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
)

func ConnectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []string) error {
	var errs []error
	for i, phyInterface := range phyInterfaces {
		err := connectPhyInterfaceToOVSBridge(ovsBridgeClient, phyInterface, ovsconfig.FirstControllerOFPort+int32(i), false)
		errs = append(errs, err)
	}
	return errors.NewAggregate(errs)
}

func connectPhyInterfaceToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterface string, ofPortRequest int32, trunkMode bool) error {
	if _, err := interfaceByNameFn(phyInterface); err != nil {
		return fmt.Errorf("failed to get interface %s: %v", phyInterface, err)
	}

	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}

	if _, err := ovsBridgeClient.GetOFPort(phyInterface, false); err == nil {
		klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skip the configuration", "device", phyInterface)
		return nil
	}

	if _, err := ovsBridgeClient.CreateUplinkPort(phyInterface, ofPortRequest, externalIDs); err != nil {
		return fmt.Errorf("failed to create OVS uplink port %s: %v", phyInterface, err)
	}
	klog.InfoS("Physical interface added to secondary OVS bridge", "device", phyInterface)
	return nil
}

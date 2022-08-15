// Copyright 2022 Antrea Authors
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

package externalnode

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

func (c *ExternalNodeController) moveIFConfigurations(adapterConfig *config.AdapterNetConfig, src string, dst string) error {
	dstLink, err := netlink.LinkByName(dst)
	if err != nil {
		return fmt.Errorf("failed to find link for destination %s, err %v", dst, err)
	}
	if src != "" {
		srcLink, err := netlink.LinkByName(src)
		if err != nil {
			return fmt.Errorf("failed to find link for source %s, err %v", src, err)
		}
		if err := netlink.LinkSetMTU(dstLink, adapterConfig.MTU); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(dstLink); err != nil {
			return err
		}
		if err := util.RemoveLinkIPs(srcLink); err != nil {
			return err
		}
		if err := util.RemoveLinkRoutes(srcLink); err != nil {
			return err
		}
	}
	dstIndex := dstLink.Attrs().Index
	// Configure the source interface's IPs on the destination interface.
	if err := util.ConfigureLinkAddresses(dstIndex, adapterConfig.IPs); err != nil {
		return err
	}
	// Configure the source interface's routes on the destination interface.
	if err := util.ConfigureLinkRoutes(dstLink, adapterConfig.Routes); err != nil {
		return err
	}
	return nil
}

func (c *ExternalNodeController) removeExternalNodeConfig() error {
	return nil
}

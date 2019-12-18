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

package route

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"strings"

	"k8s.io/klog"

	"github.com/vishvananda/netlink"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/signals"
)

type Client struct {
	nodeConfig *types.NodeConfig
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Initialize(nodeConfig *types.NodeConfig) error {
	c.nodeConfig = nodeConfig
	if c.nodeConfig.ServiceRtTable.IsMainTable() {
		return nil
	}
	f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		klog.Fatalf("Unable to create service route table(open), err %v", err)
	}
	defer func() { _ = f.Close() }()

	oldTablesRaw := make([]byte, 1024)
	bLen, err := f.Read(oldTablesRaw)
	if err != nil {
		klog.Fatalf("Unable to create service route table(read), err %v", err)
	}
	oldTables := string(oldTablesRaw[:bLen])
	newTable := fmt.Sprintf("%d %s", c.nodeConfig.ServiceRtTable.Idx, c.nodeConfig.ServiceRtTable.Name)

	if strings.Index(oldTables, newTable) != -1 {
		oldTables = strings.Replace(oldTables, newTable, "", -1)
	} else {
		if _, err := f.WriteString(newTable); err != nil {
			klog.Fatalf("Failed to add antrea service route table, err=%v", err)
		}
	}

	signals.AddCleanup(func() error {
		klog.Infof("Cleaning up antrea service table")
		f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = f.WriteString(oldTables)
		return err
	})

	gwConfig := c.nodeConfig.GatewayConfig
	if gwConfig != nil && c.nodeConfig.PodCIDR != nil {
		// add local podCIDR if applicable to service rt table
		gw, err := netlink.LinkByName(gwConfig.Name)
		if err != nil {
			klog.Fatalf("Failed to find local gateway %s, err=%v", gwConfig, err)
		}
		route := &netlink.Route{
			LinkIndex: gw.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       c.nodeConfig.PodCIDR,
			Table:     c.nodeConfig.ServiceRtTable.Idx,
		}
		if err := netlink.RouteAdd(route); err != nil {
			if os.IsExist(err) {
				klog.Errorf("link route already created")
			} else {
				klog.Fatalf("Failed to add link route to service table, err=%v", err)
			}
		}
		signals.AddCleanup(func() error {
			klog.Infof("Cleaning up link route")
			return netlink.RouteDel(route)
		})

	}

	// create ip rule to select route table
	ipRule := netlink.NewRule()
	ipRule.IifName = c.nodeConfig.GatewayConfig.Name
	ipRule.Mark = iptables.RtTblSelectorValue
	ipRule.Mark = iptables.RtTblSelectorValue
	ipRule.Table = c.nodeConfig.ServiceRtTable.Idx

	err = netlink.RuleAdd(ipRule)
	if err != nil {
		if os.IsExist(err) {
			klog.Errorf("rule already created")
		} else {
			klog.Fatalf("Failed to create ip rule for service route table, err=%v", err)
		}
	}

	signals.AddCleanup(func() error {
		klog.Infof("Cleaning up ip rule %s", ipRule)
		return netlink.RuleDel(ipRule)
	})
	return nil
}

func (c *Client) AddPeerCIDRRoute(peerPodCIDR *net.IPNet, gwLinkIdx int, peerNodeIP, peerGwIP net.IP) ([]*netlink.Route, error) {
	if peerPodCIDR == nil {
		klog.Errorf("Empty peer pod CIDR")
		return nil, nil
	}

	// install routes
	routes := []*netlink.Route{
		{
			Dst:       peerPodCIDR,
			Flags:     int(netlink.FLAG_ONLINK),
			LinkIndex: gwLinkIdx,
			Gw:        peerGwIP,
			Table:     c.nodeConfig.ServiceRtTable.Idx,
		},
	}

	// route peer CIDR via main route table if not service
	if !c.nodeConfig.ServiceRtTable.IsMainTable() {
		if c.nodeConfig.PodEncapMode.UseTunnel(peerNodeIP, c.nodeConfig.NodeIPAddr) {
			// need overlay tunnel
			routes = append(routes, &netlink.Route{
				Dst:       peerPodCIDR,
				Flags:     int(netlink.FLAG_ONLINK),
				LinkIndex: gwLinkIdx,
				Gw:        peerGwIP,
			})
		} else {
			routes = append(routes, &netlink.Route{
				Dst:       peerPodCIDR,
				Flags:     int(netlink.FLAG_ONLINK),
				LinkIndex: c.nodeConfig.NodeDefaultDev.Attrs().Index,
				Gw:        peerNodeIP,
			})
		}
	}

	var err error = nil
	retIdx := 0
	for _, route := range routes {
		err = netlink.RouteAdd(route)
		// This is likely to be caused by an agent restart and so should not happen once we
		// handle state reconciliation on restart properly. However, it is probably better
		// to handle this case gracefully for the time being.
		if err == unix.EEXIST {
			klog.Warningf("Route to peer %s already exists, replacing it", peerNodeIP)
			err = netlink.RouteReplace(route)
		}
		if err != nil {
			err = fmt.Errorf("failed to install route to peer %s with netlink: %v", peerNodeIP, err)
			break
		}
		retIdx++
	}
	return routes[:retIdx], err
}

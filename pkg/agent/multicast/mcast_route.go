// Copyright 2021 Antrea Authors
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
package multicast

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

const (
	GroupNameIndexName      = "groupName"
	MulticastFlag           = "multicast"
	MulticastRecvBufferSize = 128
)

func newRouteClient(nodeconfig *config.NodeConfig, groupCache cache.Indexer, multicastSocket RouteInterface, multicastInterfaces sets.String) *MRouteClient {
	var m = &MRouteClient{
		igmpMsgChan:         make(chan []byte, workerCount),
		nodeConfig:          nodeconfig,
		groupCache:          groupCache,
		inboundRouteCache:   cache.NewIndexer(getMulticastInboundEntryKey, cache.Indexers{GroupNameIndexName: inboundGroupIndexFunc}),
		multicastInterfaces: multicastInterfaces.List(),
		socket:              multicastSocket,
	}
	return m
}

func (c *MRouteClient) Initialize() error {
	c.setMulticastInterfaces()
	// Allocate VIF for each interface in multicastInterfaceNames and gatewayInterface.
	// The VIFs will be later used for multicast route configuration.
	gatewayInterfaceVIF, err := c.socket.AllocateVIFs([]string{c.nodeConfig.GatewayConfig.Name}, 0)
	if err != nil {
		return err
	}
	c.internalInterfaceVIF = gatewayInterfaceVIF[0]
	multicastInterfaceNames := make([]string, len(c.multicastInterfaceConfigs))
	for i, config := range c.multicastInterfaceConfigs {
		multicastInterfaceNames[i] = config.Name
	}
	externalInterfaceVIFs, err := c.socket.AllocateVIFs(multicastInterfaceNames, c.internalInterfaceVIF+1)
	if err != nil {
		return err
	}
	c.externalInterfaceVIFs = externalInterfaceVIFs
	return nil
}

// MRouteClient configures static multicast route.
type MRouteClient struct {
	// igmpMsgChan is used for processing IGMPMsg reading from sockFD in parallel
	igmpMsgChan               chan []byte
	nodeConfig                *config.NodeConfig
	multicastInterfaces       []string
	inboundRouteCache         cache.Indexer
	groupCache                cache.Indexer
	socket                    RouteInterface
	multicastInterfaceConfigs []multicastInterfaceConfig
	internalInterfaceVIF      uint16
	externalInterfaceVIFs     []uint16
}

// multicastInterfacesJoinMgroup allows multicast interfaces to join multicast group,
// by making these interfaces accept multicast traffic with multicast ip:mgroup.
// https://tldp.org/HOWTO/Multicast-HOWTO-6.html#ss6.4
func (c *MRouteClient) multicastInterfacesJoinMgroup(mgroup net.IP) error {
	for _, config := range c.multicastInterfaceConfigs {
		addrIP := config.IPv4Addr.IP.To4()
		groupIP := mgroup.To4()
		err := c.socket.MulticastInterfaceJoinMgroup(groupIP, addrIP, config.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *MRouteClient) multicastInterfacesLeaveMgroup(mgroup net.IP) error {
	for _, config := range c.multicastInterfaceConfigs {
		addrIP := config.IPv4Addr.IP.To4()
		groupIP := mgroup.To4()
		err := c.socket.MulticastInterfaceLeaveMgroup(groupIP, addrIP, config.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

// processIGMPNocacheMsg reads igmpMsg from the multicast socket and configures
// multicast route based on VIF value in the message.
func (c *MRouteClient) processIGMPNocacheMsg(igmpMsg []byte) {
	klog.V(2).InfoS("Received igmpMsg", "igmpMsg", igmpMsg)
	msg, err := c.parseIGMPMsg(igmpMsg)
	if err != nil {
		klog.V(4).ErrorS(err, "Error parsing IGMP message")
		return
	}
	if msg.VIF != c.internalInterfaceVIF {
		// Skip inbound multicast traffic when there is no multicast receiver Pod
		// listening the msg.Dst group.
		status, ok, _ := c.groupCache.GetByKey(msg.Dst.String())
		if !ok {
			return
		}
		groupStatus := status.(*GroupMemberStatus)
		if len(groupStatus.localMembers) == 0 {
			return
		}
		// Prevent adding route entries for unrecognized VIF.
		if len(c.externalInterfaceVIFs) < int(msg.VIF) {
			klog.ErrorS(fmt.Errorf("error finding VIF"), "Adding inbound multicast route entry failed", "VIF", msg.VIF)
			return
		}
		err := c.addInboundMrouteEntry(msg.Src, msg.Dst, msg.VIF)
		if err != nil {
			klog.ErrorS(err, "Adding inbound multicast route entry failed")
		}
	} else {
		err = c.addOutboundMrouteEntry(msg.Src, msg.Dst)
		if err != nil {
			klog.ErrorS(err, "Adding outbound multicast route entry failed")
		}
	}
}

func (c *MRouteClient) deleteInboundMrouteEntryByGroup(group net.IP) (err error) {
	klog.V(2).InfoS("Deleting multicast group", "group", group)
	mEntries, _ := c.inboundRouteCache.ByIndex(GroupNameIndexName, group.String())
	for _, route := range mEntries {
		entry := route.(*inboundMulticastRouteEntry)
		err := c.socket.DelMrouteEntry(net.ParseIP(entry.src), net.ParseIP(entry.group), entry.vif)
		if err != nil {
			return err
		}
		c.inboundRouteCache.Delete(route)
	}
	return nil
}

// addOutboundMrouteEntry configures multicast route from Antrea gateway to all the multicast interfaces,
// allowing multicast sender Pods to send multicast traffic to external.
func (c *MRouteClient) addOutboundMrouteEntry(src net.IP, group net.IP) (err error) {
	klog.V(2).InfoS("Adding outbound multicast route entry", "src", src, "group", group, "outboundVIFs", c.externalInterfaceVIFs)
	err = c.socket.AddMrouteEntry(src, group, c.internalInterfaceVIF, c.externalInterfaceVIFs)
	if err != nil {
		return err
	}
	return nil
}

// addInboundMrouteEntry configures multicast route from multicast interface to Antrea gateway
// to allow multicast receiver Pods to receive multicast traffic from external.
func (c *MRouteClient) addInboundMrouteEntry(src net.IP, group net.IP, inboundVIF uint16) (err error) {
	klog.V(2).InfoS("Adding inbound multicast route entry", "src", src, "group", group, "inboundVIF", inboundVIF)
	err = c.socket.AddMrouteEntry(src, group, inboundVIF, []uint16{c.internalInterfaceVIF})
	if err != nil {
		return err
	}
	routeEntry := &inboundMulticastRouteEntry{
		group: group.String(),
		src:   src.String(),
		vif:   inboundVIF,
	}
	c.inboundRouteCache.Add(routeEntry)
	return nil
}

// inboundMulticastRouteEntry encodes the inbound multicast routing entry.
// For example,
// type inboundMulticastRouteEntry struct {
//	group "226.94.9.9"
//	src   "10.0.0.55"
//	vif   vif of wlan0
// } encodes the multicast route entry from wlan0 to Antrea gateway
// (10.0.0.55,226.94.9.9)           Iif: wlan0      Oifs: antrea-gw0.
// The oif is always Antrea gateway so we do not put it in the struct.
type inboundMulticastRouteEntry struct {
	group string
	src   string
	vif   uint16
}

func getMulticastInboundEntryKey(obj interface{}) (string, error) {
	entry := obj.(*inboundMulticastRouteEntry)
	return entry.group + "/" + entry.src + "/" + fmt.Sprint(entry.vif), nil
}

func inboundGroupIndexFunc(obj interface{}) ([]string, error) {
	entry, ok := obj.(*inboundMulticastRouteEntry)
	if !ok {
		return []string{}, nil
	}
	return []string{entry.group}, nil
}

// setMulticastInterfaces tries to compute all the multicast interfaces used to
// accept and send multicast traffic based on the provided multicastInterfaces.
func (c *MRouteClient) setMulticastInterfaces() {
	multicastInterfaceConfigs := make([]multicastInterfaceConfig, 0, len(c.multicastInterfaces))
	for _, ifaceName := range c.multicastInterfaces {
		ipv4Addr, ipv6Addr, iface, err := util.GetIPNetDeviceByName(ifaceName)
		if err != nil {
			klog.ErrorS(err, "Failed to get local IPNet device", "interface", ifaceName)
			continue
		}
		if !strings.Contains(iface.Flags.String(), MulticastFlag) {
			klog.ErrorS(fmt.Errorf("failed to get multicast flag for this interface"), "Not a multicast enabled interface", "interface", ifaceName)
			continue
		}
		config := multicastInterfaceConfig{
			Name:     iface.Name,
			IPv4Addr: ipv4Addr,
			IPv6Addr: ipv6Addr,
		}
		multicastInterfaceConfigs = append(multicastInterfaceConfigs, config)
	}
	c.multicastInterfaceConfigs = multicastInterfaceConfigs
}

func (c *MRouteClient) worker(stopCh <-chan struct{}) {
	for {
		select {
		case msg := <-c.igmpMsgChan:
			c.processIGMPNocacheMsg(msg)
		case <-stopCh:
			return
		}
	}
}

// This struct is result of parsing igmpmsg from the kernel
// with fields we interest.
type parsedIGMPMsg struct {
	VIF uint16
	Src net.IP
	Dst net.IP
}

type multicastInterfaceConfig struct {
	Name     string
	IPv4Addr *net.IPNet
	IPv6Addr *net.IPNet
}

type RouteInterface interface {
	// MulticastInterfaceJoinMgroup enables interface with name ifaceName and IP ifaceIP
	// joins multicast group IP mgroup.
	MulticastInterfaceJoinMgroup(mgroup net.IP, ifaceIP net.IP, ifaceName string) error
	// MulticastInterfaceLeaveMgroup enables interface with name ifaceName and IP ifaceIP
	// leaves multicast group IP mgroup.
	MulticastInterfaceLeaveMgroup(mgroup net.IP, ifaceIP net.IP, ifaceName string) error
	// AddMrouteEntry adds multicast route with specified source(src), multicast group IP(group),
	// inbound multicast interface(iif) and outbound multicast interfaces(oifs).
	AddMrouteEntry(src net.IP, group net.IP, iif uint16, oifs []uint16) (err error)
	// DelMrouteEntry deletes multicast route with specified source(src), multicast group IP(group),
	// inbound multicast interface(iif).
	DelMrouteEntry(src net.IP, group net.IP, iif uint16) (err error)
	// FlushMRoute flushes static multicast routing entries.
	FlushMRoute()
	// GetFD returns socket file descriptor.
	GetFD() int
	// AllocateVIFs allocate VIFs to interfaces, starting from startVIF.
	AllocateVIFs(interfaceNames []string, startVIF uint16) ([]uint16, error)
}

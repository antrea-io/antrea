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

package tc

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/tc/types"
)

const (
	// QdiscHandleIngress is Linux qdisc ingress handle ID.
	QdiscHandleIngress = uint32(0xffff)
	// QdiscHandleEgress is Linux TC qdisc egress handle ID.
	QdiscHandleEgress = uint32(0xa)

	ingress = "ingress"
	egress  = "egress"

	DevLoopback     = "lo"
	LoopbackIfIndex = 1

	defaultChain = 0

	protoIPv4Str = "ipv4"
	protoIPv6Str = "ipv6"
	protoTCPStr  = "tcp"
	protoUDPStr  = "udp"
	protoSCTPStr = "sctp"

	filterIPv4PriorityNormal = 104
	filterIPv6PriorityNormal = 106
	filterIPv4PriorityHigh   = 4
	filterIPv6PriorityHigh   = 6

	zeroMAC = "00:00:00:00:00:00"
)

type Client struct {
	handleGeneratorMap map[string]types.HandleGenerator
}

func getHandleGeneratorKey(ifIndex, priority int) string {
	return fmt.Sprintf("%d-%d", ifIndex, priority)
}

func NewTCClient() *Client {
	hgMap := make(map[string]types.HandleGenerator)
	priorities := []int{filterIPv4PriorityNormal, filterIPv6PriorityNormal, filterIPv4PriorityHigh, filterIPv6PriorityHigh}
	// Create a handle ID generator for every interface.
	interfaces, _ := net.Interfaces()
	// Antrea gateway interface is not in the list if this is a new machine. This function is called before creating Antrea
	// gateway interface, and the handle ID generator for Antrea gateway will be created later.
	for _, itf := range interfaces {
		if addrs, _ := itf.Addrs(); len(addrs) != 0 {
			for _, priority := range priorities {
				hgMap[getHandleGeneratorKey(itf.Index, priority)] = types.NewHandleGenerator()
			}
		}
	}
	return &Client{handleGeneratorMap: hgMap}
}

func getL3ProtocolStr(protocol int) string {
	var l3ProtocolStr string
	if protocol == unix.IPPROTO_IP {
		l3ProtocolStr = protoIPv4Str
	} else if protocol == unix.IPPROTO_IPV6 {
		l3ProtocolStr = protoIPv6Str
	}
	return l3ProtocolStr
}

func getL4ProtocolStr(protocol int) string {
	var l4ProtocolStr string
	if protocol == unix.IPPROTO_TCP {
		l4ProtocolStr = protoTCPStr
	} else if protocol == unix.IPPROTO_UDP {
		l4ProtocolStr = protoUDPStr
	} else if protocol == unix.IPPROTO_SCTP {
		l4ProtocolStr = protoSCTPStr
	}
	return l4ProtocolStr
}

func getPriority(l3Protocol int, high bool) int {
	var priority int
	if l3Protocol == unix.IPPROTO_IP {
		if high {
			return filterIPv4PriorityHigh
		} else {
			return filterIPv4PriorityNormal
		}
	} else if l3Protocol == unix.IPPROTO_IPV6 {
		if high {
			return filterIPv6PriorityHigh
		} else {
			return filterIPv6PriorityNormal
		}
	}
	return priority
}

func commandRun(argsStr string) (string, error) {
	klog.V(4).Infof("Run command \"%s\"\n", argsStr)
	args := strings.Split(argsStr, " ")
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec

	var stdout bytes.Buffer
	cmd.Stderr = &stdout
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return string(stdout.Bytes()), fmt.Errorf("run command \"%s\" with err: %v, %v", argsStr, err, string(stdout.Bytes()))
	}
	return string(stdout.Bytes()), nil
}

// QdiscAdd adds a qdisc to an interface.
func (c *Client) QdiscAdd(handle uint32, ifIndex int) error {
	dev := util.GetNameByIndex(ifIndex)

	var cmd string
	if handle == QdiscHandleIngress {
		cmd = fmt.Sprintf("tc qdisc add dev %s ingress", dev)
	} else {
		cmd = fmt.Sprintf("tc qdisc add dev %s root handle %x: htb", dev, handle)
	}

	_, err := commandRun(cmd)
	if err != nil {
		return err
	}
	return nil
}

// QdiscDel deletes a qdisc from an interface.
func (c *Client) QdiscDel(handle uint32, ifIndex int) error {
	var cmd string
	dev := util.GetNameByIndex(ifIndex)
	if handle == QdiscHandleIngress {
		cmd = fmt.Sprintf("tc qdisc del dev %s ingress", dev)
	} else {
		cmd = fmt.Sprintf("tc qdisc del dev %s root handle %x: htb", dev, handle)
	}
	_, err := commandRun(cmd)
	if err != nil {
		return err
	}
	return nil
}

// QdiscCheck checks that whether there is a demand qdisc and clears other unneeded qdiscs.
func (c *Client) QdiscCheck(handle uint32, ifIndex int) (bool, error) {
	var exist bool
	var keyWord string
	dev := util.GetNameByIndex(ifIndex)

	cmd := fmt.Sprintf("tc qdisc show dev %s", dev)
	output, err := commandRun(cmd)
	if err != nil {
		return false, err
	}

	if handle == QdiscHandleIngress {
		keyWord = fmt.Sprintf("ingress %x:", handle)
	} else {
		keyWord = fmt.Sprintf("htb %x:", handle)
	}

	qdiscs := strings.Split(strings.TrimRight(output, string('\n')), string('\n'))
	for _, qdisc := range qdiscs {
		if strings.Contains(qdisc, keyWord) {
			exist = true
			break
		}
	}

	return exist, nil
}

// LoopbackFiltersAdd creates Linux TC filter for loopback. Currently, a filter is created for every available NodePort IP
// address and NodePort protocol/port.
// TODO: Note that, this is not the best design. When a NodePort is added, assumed that there are 20 available NodePort
//  IP addresses, this function will be called 20 times. The better design is to add basic filters for matching NodePort
//  IP addresses as destination IP. The action of these filters is to go to a target chain. The target chain will match
//  NodePort protocol/port as destination protocol/port. The action of filters in target chain is to redirect traffic to
//  an interface.
func (c *Client) LoopbackFiltersAdd(l3ProtocolVal, l4ProtocolVal int, dstPort uint16, dstIPs []net.IP, dstDev, dstDevMAC string) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	l4ProtocolStr := getL4ProtocolStr(l4ProtocolVal)
	priority := getPriority(l3ProtocolVal, false)
	key := getHandleGeneratorKey(LoopbackIfIndex, priority)
	chain := defaultChain

	for _, dstIP := range dstIPs {
		handle := c.handleGeneratorMap[key].Get(chain, dstIP, dstPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", DevLoopback, QdiscHandleEgress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		cmd = fmt.Sprintf("%s ip_proto %s dst_ip %s dst_port %d", cmd, l4ProtocolStr, dstIP.String(), dstPort)
		cmd = fmt.Sprintf("%s action skbmod set smac %s pipe", cmd, dstDevMAC)
		cmd = fmt.Sprintf("%s action mirred egress redirect dev %s", cmd, dstDev)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoopbackFiltersDel deletes Linux TC filter for loopback.
func (c *Client) LoopbackFiltersDel(l3ProtocolVal, l4ProtocolVal int, dstPort uint16, dstIPs []net.IP) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	priority := getPriority(l3ProtocolVal, false)
	key := getHandleGeneratorKey(LoopbackIfIndex, priority)
	chain := defaultChain

	for _, dstIP := range dstIPs {
		handle := c.handleGeneratorMap[key].Get(chain, dstIP, dstPort, l4ProtocolVal)
		c.handleGeneratorMap[key].Recycle(chain, dstIP, dstPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", DevLoopback, QdiscHandleEgress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// InterfaceFiltersAdd creates Linux TC filter for general interfaces (not including Antrea gateway and loopback). The
// filter is used to match destination IP and protocol/port of Service traffic, then redirect the traffic to a target interface.
// TODO: as LoopbackFiltersAdd's TODO comment.
func (c *Client) InterfaceFiltersAdd(ifIndex int, l3ProtocolVal, l4ProtocolVal int, dstPort uint16, dstIPs []net.IP, dstDev string) error {
	if ifIndex == LoopbackIfIndex {
		return nil
	}
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	l4ProtocolStr := getL4ProtocolStr(l4ProtocolVal)
	priority := getPriority(l3ProtocolVal, false)
	key := getHandleGeneratorKey(ifIndex, priority)
	chain := defaultChain

	for _, dstIP := range dstIPs {
		handle := c.handleGeneratorMap[key].Get(chain, dstIP, dstPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", util.GetNameByIndex(ifIndex), QdiscHandleIngress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		cmd = fmt.Sprintf("%s ip_proto %s dst_ip %s dst_port %d", cmd, l4ProtocolStr, dstIP.String(), dstPort)
		cmd = fmt.Sprintf("%s action mirred egress redirect dev %s", cmd, dstDev)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// InterfaceFiltersDel deletes Linux TC filter for general interfaces (not including Antrea gateway and loopback).
func (c *Client) InterfaceFiltersDel(ifIndex int, l3ProtocolVal, l4ProtocolVal int, dstPort uint16, dstIPs []net.IP) error {
	if ifIndex == LoopbackIfIndex {
		return nil
	}
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	priority := getPriority(l3ProtocolVal, false)
	key := getHandleGeneratorKey(ifIndex, priority)
	chain := defaultChain

	for _, dstIP := range dstIPs {
		handle := c.handleGeneratorMap[key].Get(chain, dstIP, dstPort, l4ProtocolVal)
		c.handleGeneratorMap[key].Recycle(chain, dstIP, dstPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", util.GetNameByIndex(ifIndex), QdiscHandleIngress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// GatewayBasicFiltersAdd creates basic Linux TC filters for Antrea gateway to distribute response NodePort traffic to target
// chain according to source IP address and network layer protocol of Service traffic.
// Argument ifIndex is target interface's index, and argument srcIPs are target interfaces' available NodePort IP addresses.
// These addresses can be IPv4 addresses or IPv6 addresses. For IPv4, response traffic matching the filter will be sent to
// a target chain. The target chain number is decided by IPv4/IPv6 and interface's index and an offset 0x100.
// For example, if protocol is IPv4((unix.IPPROTO_IP is 0x0) and interface is ethx(assumed that index is 0x10), then
// chain num is 0x0 << 8 + 0x100 + 0x10 = 0x110. If IPv6, then chain num is 0x3910(unix.IPPROTO_IPV6 is 0x29).
// TODO: Note that, the of offset is used to avoid chain 1. There is something strange when using chain 1.
func (c *Client) GatewayBasicFiltersAdd(gatewayIfIndex, dstIfIndex int, l3ProtocolVal int, srcIPs []net.IP) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	gotoChainPrefix := l3ProtocolVal<<8 + 0x100
	priorityNormal := getPriority(l3ProtocolVal, false)
	priorityHigh := getPriority(l3ProtocolVal, true)
	gateway := util.GetNameByIndex(gatewayIfIndex)
	chain := defaultChain
	keyPriorityNormal := getHandleGeneratorKey(gatewayIfIndex, priorityNormal)
	if _, ok := c.handleGeneratorMap[keyPriorityNormal]; !ok {
		c.handleGeneratorMap[keyPriorityNormal] = types.NewHandleGenerator()
	}
	keyPriorityHigh := getHandleGeneratorKey(gatewayIfIndex, priorityHigh)
	if _, ok := c.handleGeneratorMap[keyPriorityHigh]; !ok {
		c.handleGeneratorMap[keyPriorityHigh] = types.NewHandleGenerator()
	}

	for _, srcIP := range srcIPs {
		handle := c.handleGeneratorMap[keyPriorityNormal].Get(chain, srcIP, 0, 0)
		cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, QdiscHandleIngress, priorityNormal)
		cmd = fmt.Sprintf("%s protocol %s handle %d flower src_ip %s action goto chain %d", cmd, l3ProtocolStr, handle, srcIP.String(), gotoChainPrefix|dstIfIndex)
		if _, err := commandRun(cmd); err != nil {
			return err
		}

		// Traffic which is from loopback should be also taken into consider. The feature of the traffic is that their
		// source and destination IP addresses are the same. The filter matching the traffic should have higher priority.
		if dstIfIndex != LoopbackIfIndex {
			handle = c.handleGeneratorMap[keyPriorityHigh].Get(chain, srcIP, 0, 0)
			cmd = fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, QdiscHandleIngress, priorityHigh)
			cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower src_ip %s dst_ip %s", cmd, l3ProtocolStr, chain, handle, srcIP.String(), srcIP.String())
			cmd = fmt.Sprintf("%s action goto chain %d", cmd, gotoChainPrefix|LoopbackIfIndex)
			if _, err := commandRun(cmd); err != nil {
				return err
			}
		}
	}
	return nil
}

// GatewayFilterAddOnSubChain creates Linux TC filter for gateway to redirect response NodePort traffic to the interface where
// request traffic is from. This filter matches NodePort protocol/port.
// Note that, if the target interface is loopback, the source and destination MAC address should be rewritten to all-zero.
// For loopback, the traffic should be redirected to loopback's egress. For general interfaces, traffic should be redirected
// to its ingress.
func (c *Client) GatewayFilterAddOnSubChain(dstIfIndex int, l3ProtocolVal, l4ProtocolVal int, srcPort uint16, gateway string) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	l4ProtocolStr := getL4ProtocolStr(l4ProtocolVal)
	priority := getPriority(l3ProtocolVal, false)
	dstDev := util.GetNameByIndex(dstIfIndex)
	handle := l4ProtocolVal<<16 | int(srcPort)
	chain := (l3ProtocolVal<<8 + 0x100) | dstIfIndex
	position := egress

	cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, QdiscHandleIngress, priority)
	cmd = fmt.Sprintf("%s chain %d handle %d protocol %s flower", cmd, chain, handle, l3ProtocolStr)
	cmd = fmt.Sprintf("%s ip_proto %s src_port %d", cmd, l4ProtocolStr, srcPort)
	if dstIfIndex == LoopbackIfIndex {
		cmd = fmt.Sprintf("%s action skbmod set dmac %s set smac %s pipe", cmd, zeroMAC, zeroMAC)
		position = ingress
	}
	cmd = fmt.Sprintf("%s action mirred %s redirect dev %s", cmd, position, dstDev)
	_, err := commandRun(cmd)
	if err != nil {
		return err
	}

	return nil
}

// GatewayFilterDelOnSubChain deletes Linux TC filter by index for Antrea gateway on a sub chain.
func (c *Client) GatewayFilterDelOnSubChain(dstIfIndex int, l3ProtocolVal, l4ProtocolVal int, srcPort uint16, dstDev string) error {
	priority := getPriority(l3ProtocolVal, false)
	handle := l4ProtocolVal<<16 | int(srcPort)
	chainPrefix := l3ProtocolVal<<8 + 0x100

	cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", dstDev, QdiscHandleIngress, priority)
	cmd = fmt.Sprintf("%s chain %d handle %d flower", cmd, chainPrefix|dstIfIndex, handle)
	_, err := commandRun(cmd)
	if err != nil {
		return err
	}

	return nil
}

// GatewayFiltersAdd creates Linux TC filters which are used to redirect LoadBalancer response traffic to the output interface of
// default route.
func (c *Client) GatewayFiltersAdd(gatewayIfIndex int, l3ProtocolVal, l4ProtocolVal int, srcPort uint16, srcIPs []net.IP, gatewayIP net.IP, dstDev string) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	l4ProtocolStr := getL4ProtocolStr(l4ProtocolVal)
	gateway := util.GetNameByIndex(gatewayIfIndex)
	chain := defaultChain
	priorityNormal := getPriority(l3ProtocolVal, false)
	priorityHigh := getPriority(l3ProtocolVal, true)
	keyPriorityNormal := getHandleGeneratorKey(gatewayIfIndex, priorityNormal)
	keyPriorityHigh := getHandleGeneratorKey(gatewayIfIndex, priorityHigh)

	// When adding a filter for LoadBalancer, use a different priority from the NodePort basic filter priority, otherwise
	// the filter may fail to be added. As a result, the priority should be priorityNormal+1 or priorityHigh+1.
	for _, srcIP := range srcIPs {
		handle := c.handleGeneratorMap[keyPriorityNormal].Get(chain, srcIP, srcPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, QdiscHandleIngress, priorityNormal+1)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		cmd = fmt.Sprintf("%s ip_proto %s src_ip %s src_port %d", cmd, l4ProtocolStr, srcIP.String(), srcPort)
		cmd = fmt.Sprintf("%s action mirred egress redirect dev %s", cmd, dstDev)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}

		handle = c.handleGeneratorMap[keyPriorityHigh].Get(chain, srcIP, srcPort, l4ProtocolVal)
		cmd = fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, QdiscHandleIngress, priorityHigh+1)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		cmd = fmt.Sprintf("%s ip_proto %s src_ip %s src_port %d dst_ip %s", cmd, l4ProtocolStr, srcIP.String(), srcPort, gatewayIP)
		cmd = fmt.Sprintf("%s action pass", cmd)
		_, err = commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// GatewayFiltersDel deletes Linux TC filters which are used to redirect LoadBalancer response traffic to the output interface of
// default route.
func (c *Client) GatewayFiltersDel(gatewayIfIndex int, l3ProtocolVal, l4ProtocolVal int, dstPort uint16, dstIPs []net.IP) error {
	l3ProtocolStr := getL3ProtocolStr(l3ProtocolVal)
	chain := defaultChain
	priorityNormal := getPriority(l3ProtocolVal, false)
	priorityHigh := getPriority(l3ProtocolVal, true)
	keyPriorityNormal := getHandleGeneratorKey(gatewayIfIndex, priorityNormal)
	keyPriorityHigh := getHandleGeneratorKey(gatewayIfIndex, priorityHigh)

	for _, dstIP := range dstIPs {
		handle := c.handleGeneratorMap[keyPriorityNormal].Get(chain, dstIP, dstPort, l4ProtocolVal)
		c.handleGeneratorMap[keyPriorityNormal].Recycle(chain, dstIP, dstPort, l4ProtocolVal)
		cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", util.GetNameByIndex(gatewayIfIndex), QdiscHandleIngress, priorityNormal+1)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}

		handle = c.handleGeneratorMap[keyPriorityHigh].Get(chain, dstIP, dstPort, l4ProtocolVal)
		c.handleGeneratorMap[keyPriorityHigh].Recycle(chain, dstIP, dstPort, l4ProtocolVal)
		cmd = fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", util.GetNameByIndex(gatewayIfIndex), QdiscHandleIngress, priorityHigh+1)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtocolStr, chain, handle)
		_, err = commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

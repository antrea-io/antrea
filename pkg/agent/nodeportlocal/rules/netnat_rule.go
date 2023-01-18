//go:build windows
// +build windows

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

package rules

import (
	"fmt"
	"net"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/util"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Use antrea-nat netnatstaticmapping rules as NPL implementation
var (
	antreaNatNPL = util.AntreaNatName
)

// InitRules initializes rules based on the netnatstaticmapping implementation on windows
func InitRules() PodPortRules {
	return NewNetNatRules()
}

type netnatRules struct {
	name string
}

// NewNetNatRules retruns a new instance of netnatRules.
func NewNetNatRules() *netnatRules {
	nnRule := netnatRules{
		name: antreaNatNPL,
	}
	return &nnRule
}

// Init initializes NetNat rules for NPL.
func (nn *netnatRules) Init() error {
	if err := nn.initRules(); err != nil {
		return fmt.Errorf("initialization of NPL netnat rules failed: %v", err)
	}
	return nil
}

// initRules creates or reuses NetNat table as NPL rule instance on Windows.
func (nn *netnatRules) initRules() error {
	nn.DeleteAllRules()
	if err := util.NewNetNat(antreaNatNPL, route.PodCIDRIPv4); err != nil {
		return err
	}
	klog.InfoS("Successfully created NetNat rule", "name", antreaNatNPL, "CIDR", route.PodCIDRIPv4)
	return nil
}

// AddRule appends a NetNatStaticMapping rule.
func (nn *netnatRules) AddRule(nodePort int, podIP string, podPort int, protocol string) error {
	netNatStaticMapping := &util.NetNatStaticMapping{
		Name:         antreaNatNPL,
		ExternalIP:   net.ParseIP("0.0.0.0"),
		ExternalPort: util.PortToUint16(nodePort),
		InternalIP:   net.ParseIP(podIP),
		InternalPort: util.PortToUint16(podPort),
		Protocol:     binding.Protocol(protocol),
	}
	if err := util.ReplaceNetNatStaticMapping(netNatStaticMapping); err != nil {
		return err
	}
	klog.InfoS("Successfully added NetNatStaticMapping", "NetNatStaticMapping", netNatStaticMapping)
	return nil
}

// AddAllRules constructs a list of NPL rules and performs NetNatStaticMapping replacement.
func (nn *netnatRules) AddAllRules(nplList []PodNodePort) error {
	for _, nplData := range nplList {
		if err := nn.AddRule(nplData.NodePort, nplData.PodIP, nplData.PodPort, nplData.Protocol); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRule deletes a specific NPL rule from NetNatStaticMapping table
func (nn *netnatRules) DeleteRule(nodePort int, podIP string, podPort int, protocol string) error {
	netNatStaticMapping := &util.NetNatStaticMapping{
		Name:         antreaNatNPL,
		ExternalIP:   net.ParseIP("0.0.0.0"),
		ExternalPort: util.PortToUint16(nodePort),
		InternalIP:   net.ParseIP(podIP),
		InternalPort: util.PortToUint16(podPort),
		Protocol:     binding.Protocol(protocol),
	}
	if err := util.RemoveNetNatStaticMappingByNPLTuples(netNatStaticMapping); err != nil {
		return err
	}
	klog.InfoS("Successfully deleted NetNatStaticMapping", "NetNatStaticMapping", netNatStaticMapping)
	return nil
}

// DeleteAllRules deletes the NetNatStaticMapping table in the node
func (nn *netnatRules) DeleteAllRules() error {
	if err := util.RemoveNetNatStaticMappingByNAME(antreaNatNPL); err != nil {
		return err
	}
	klog.InfoS("Successfully deleted all NPL NetNatStaticMapping rules", "NatName", antreaNatNPL)
	return nil
}

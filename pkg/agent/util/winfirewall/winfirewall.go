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

package winfirewall

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

type FWRuleDirection string

const (
	FWRuleIn  FWRuleDirection = "Inbound"
	FWRuleOut FWRuleDirection = "Outbound"
)

type fwRuleAction string

const (
	fwRuleAllow fwRuleAction = "Allow"
	fwRuleDeny  fwRuleAction = "Block"
)

type fwRuleProtocol string

const (
	fwRuleIPProtocol  fwRuleProtocol = "Any"
	fwRuleTCPProtocol fwRuleProtocol = "TCP" //nolint: deadcode
	fwRuleUDPProtocol fwRuleProtocol = "UDP" //nolint: deadcode
)

const (
	fwRuleGroup string = "Antrea"
)

type winFirewallRule struct {
	name          string
	action        fwRuleAction
	direction     FWRuleDirection
	protocol      fwRuleProtocol
	localAddress  *net.IPNet
	remoteAddress *net.IPNet
	localPorts    []uint16
	remotePorts   []uint16
}

// add adds Firewall rule on the Windows host. The name and display name of the firewall rule are the same.
func (r *winFirewallRule) add() error {
	cmd := fmt.Sprintf("New-NetFirewallRule -Enabled True -Group %s %s", fwRuleGroup, r.getCommandString())
	return util.InvokePSCommand(cmd)
}

func (r *winFirewallRule) getCommandString() string {
	cmd := fmt.Sprintf("-Name '%s' -DisplayName '%s' -Direction %s -Action %s -Protocol %s", r.name, r.name, r.direction, r.action, r.protocol)
	if r.localAddress != nil {
		cmd = fmt.Sprintf("%s -LocalAddress %s", cmd, r.localAddress.String())
	}
	if r.remoteAddress != nil {
		cmd = fmt.Sprintf("%s -RemoteAddress %s", cmd, r.remoteAddress.String())
	}
	if len(r.localPorts) > 0 {
		cmd = fmt.Sprintf("%s -LocalPort %s", cmd, getPortsString(r.localPorts))
	}
	if len(r.remotePorts) > 0 {
		cmd = fmt.Sprintf("%s -RemotePort %s", cmd, getPortsString(r.remotePorts))
	}
	return cmd
}

func getPortsString(ports []uint16) string {
	portStr := []string{}
	for _, port := range ports {
		portStr = append(portStr, fmt.Sprintf("%d", port))
	}
	return strings.Join(portStr, ",")
}

type Client struct {
}

// AddRuleAllowIP adds Windows firewall rule to accept IP packets
func (c *Client) AddRuleAllowIP(name string, direction FWRuleDirection, ipNet *net.IPNet) error {
	return c.addIPRule(name, direction, ipNet, fwRuleAllow)
}

// AddRuleBlockIP adds Windows firewall rule to block IP packets
func (c *Client) AddRuleBlockIP(name string, direction FWRuleDirection, ipNet *net.IPNet) error {
	return c.addIPRule(name, direction, ipNet, fwRuleDeny)
}

func (c *Client) FirewallRuleExists(name string) (bool, error) {
	cmd := fmt.Sprintf("Get-NetfirewallRule -DisplayName '%s'", name)
	result, err := util.CallPSCommand(cmd)
	if err != nil {
		if strings.Contains(err.Error(), "No MSFT_NetFirewallRule objects found") {
			return false, nil
		}
		return false, err
	}
	return result != "", nil
}

func checkDeletionError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "No MSFT_NetFirewallRule objects found") {
		return nil
	}
	return err
}

func (c *Client) DelFirewallRuleByName(name string) error {
	cmd := fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s'", name)
	err := util.InvokePSCommand(cmd)
	return checkDeletionError(err)
}

func (c *Client) DelAllFirewallRules() error {
	cmd := fmt.Sprintf("Remove-NetFirewallRule -Group '%s'", fwRuleGroup)
	err := util.InvokePSCommand(cmd)
	return checkDeletionError(err)
}

func (c *Client) addIPRule(name string, direction FWRuleDirection, ipNet *net.IPNet, action fwRuleAction) error {
	exist, err := c.FirewallRuleExists(name)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	rule := &winFirewallRule{
		name:      name,
		action:    fwRuleAllow,
		direction: direction,
		protocol:  fwRuleIPProtocol,
	}
	switch direction {
	case FWRuleIn:
		rule.remoteAddress = ipNet
	case FWRuleOut:
		rule.localAddress = ipNet
	}
	if err := rule.add(); err != nil {
		klog.Errorf("Failed to add firewall rule %s", rule.getCommandString())
		return err
	}
	klog.V(2).Infof("Added firewall rule %s", rule.getCommandString())
	return nil
}

func NewClient() *Client {
	return &Client{}
}

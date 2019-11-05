// Copyright 2019 Antrea Authors
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

package openflow

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

const maxRetryForOFSwitch = 5

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.raw.txt -destination testing/mock_client.go -package=testing github.com/vmware-tanzu/antrea/pkg/agent/openflow Client

// Client is the interface to program OVS flows for entity connectivity of Antrea.
// TODO: flow sync (e.g. at agent restart), retry at failure, garbage collection mechanisms
type Client interface {
	// Initialize sets up all basic flows on the specific OVS bridge.
	Initialize() error

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallTunnelFlows sets up flows related to an OVS tunnel port, the tunnel port must exist.
	InstallTunnelFlows(tunnelOFPort uint32) error

	// InstallNodeFlows should be invoked when a connection to a remote Node is going to be set
	// up. The hostname is used to identify the added flows. Calls to InstallNodeFlows are
	// idempotent.
	InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error

	// UninstallNodeFlows removes the connection to the remote Node specified with the
	// hostname. UninstallNodeFlows will do nothing if no connection to the host was established.
	UninstallNodeFlows(hostname string) error

	// InstallPodFlows should be invoked when a connection to a Pod on current Node. The
	// containerID is used to identify the added flows. Calls to InstallPodFlows are idempotent.
	InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error

	// UninstallPodFlows removes the connection to the local Pod specified with the
	// containerID. UninstallPodFlows will do nothing if no connection to the Pod was established.
	UninstallPodFlows(containerID string) error

	// InstallServiceFlows should be invoked when a connection to a Kubernetes service is going
	// to be connected, all arguments should be filled. The serviceName is used to identify the
	// added flows. Calls to InstallServiceFlows are idempotent.
	InstallServiceFlows(serviceName string, serviceNet *net.IPNet, gatewayOFPort uint32) error

	// UninstallServiceFlows removes the connection to the Service specified with the
	// serviceName. UninstallServiceFlows will do nothing if no connection to the service was established.
	UninstallServiceFlows(serviceName string) error

	// GetFlowTableStatus should return an array of flow table status, all existing flow tables should be included in the list.
	GetFlowTableStatus() []binding.TableStatus

	// InstallPolicyRuleFlows installs flows for a new NetworkPolicy rule. Rule should include all fields in the
	// NetworkPolicy rule. Each ingress/egress policy rule installs Openflow entries on two tables, one for
	// ruleTable and the other for dropTable. If a packet does not pass the ruleTable, it will be dropped by the
	// dropTable.
	InstallPolicyRuleFlows(rule *types.PolicyRule) error

	// UninstallPolicyRuleFlows removes the Openflow entry relevant to the specified NetworkPolicy rule.
	// UninstallPolicyRuleFlows will do nothing if no Openflow entry for the rule is installed.
	UninstallPolicyRuleFlows(ruleID uint32) error

	// AddPolicyRuleAddress adds one or multiple addresses to the specified NetworkPolicy rule. If addrType is true, the
	// addresses are added to PolicyRule.From, else to PolicyRule.To.
	AddPolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error

	// DeletePolicyRuleAddress removes addresses from the specified NetworkPolicy rule. If addrType is true, the addresses
	// are removed from PolicyRule.From, else from PolicyRule.To.
	DeletePolicyRuleAddress(ruleID uint32, addrType types.AddressType, addresses []types.Address) error
}

// GetFlowTableStatus returns an array of flow table status.
func (c *client) GetFlowTableStatus() []binding.TableStatus {
	return c.bridge.DumpTableStatus()
}

// addMissingFlows adds any flow from flows which is not currently in the flow cache. The function
// returns immediately in case of error when adding a flow. If a flow is added succesfully, it is
// added to the flow cache. If the flow cache has not been initialized yet (i.e. there is no
// cacheKey key in the cache map), we create it first.
func (c *client) addMissingFlows(cache map[string]flowCache, cacheKey string, flows []binding.Flow) error {
	// initialize flow cache if needed
	if _, ok := cache[cacheKey]; !ok {
		cache[cacheKey] = flowCache{}
	}
	flowCache := cache[cacheKey]
	for _, flow := range flows {
		flowKey := flow.MatchString()
		if _, ok := flowCache[flowKey]; ok {
			continue
		}
		if err := c.flowOperations.Add(flow); err != nil {
			return err
		}
		flowCache[flow.MatchString()] = flow
	}
	return nil
}

func (c *client) InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error {
	flows := []binding.Flow{
		c.arpResponderFlow(peerGatewayIP.String()),
		c.l3FwdFlowToRemote(localGatewayMAC.String(), peerPodCIDR.String(), peerTunnelName),
	}

	return c.addMissingFlows(c.nodeFlowCache, hostname, flows)
}

func (c *client) UninstallNodeFlows(hostname string) error {
	defer delete(c.nodeFlowCache, hostname)
	for _, flow := range c.nodeFlowCache[hostname] {
		if err := c.flowOperations.Delete(flow); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error {
	flows := []binding.Flow{
		c.podClassifierFlow(ofPort),
		c.podIPSpoofGuardFlow(podInterfaceIP.String(), podInterfaceMAC.String(), ofPort),
		c.arpSpoofGuardFlow(podInterfaceIP.String(), podInterfaceMAC.String(), ofPort),
		c.l2ForwardCalcFlow(podInterfaceMAC.String(), ofPort),
		c.l3FlowsToPod(gatewayMAC.String(), podInterfaceIP.String(), podInterfaceMAC.String()),
	}

	return c.addMissingFlows(c.podFlowCache, containerID, flows)
}

func (c *client) UninstallPodFlows(containerID string) error {
	defer delete(c.podFlowCache, containerID)
	for _, flow := range c.podFlowCache[containerID] {
		if err := c.flowOperations.Delete(flow); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallServiceFlows(serviceName string, serviceNet *net.IPNet, gatewayOFPort uint32) error {
	flows := []binding.Flow{
		c.serviceCIDRDNATFlow(serviceNet, gatewayOFPort),
	}

	return c.addMissingFlows(c.serviceCache, serviceName, flows)
}

func (c *client) UninstallServiceFlows(serviceName string) error {
	defer delete(c.serviceCache, serviceName)
	for _, flow := range c.serviceCache[serviceName] {
		if err := c.flowOperations.Delete(flow); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	if err := c.flowOperations.Add(c.gatewayClassifierFlow(gatewayOFPort)); err != nil {
		return err
	} else if err := c.flowOperations.Add(c.gatewayIPSpoofGuardFlow(gatewayOFPort)); err != nil {
		return err
	} else if err := c.flowOperations.Add(c.gatewayARPSpoofGuardFlow(gatewayOFPort)); err != nil {
		return err
	} else if err := c.flowOperations.Add(c.l3ToGatewayFlow(gatewayAddr.String(), gatewayMAC.String())); err != nil {
		return err
	} else if err := c.flowOperations.Add(c.l2ForwardCalcFlow(gatewayMAC.String(), gatewayOFPort)); err != nil {
		return err
	}
	return nil
}

func (c *client) InstallTunnelFlows(tunnelOFPort uint32) error {
	if err := c.flowOperations.Add(c.tunnelClassifierFlow(tunnelOFPort)); err != nil {
		return err
	} else if err := c.flowOperations.Add(c.l2ForwardCalcFlow(globalVirtualMAC, tunnelOFPort)); err != nil {
		return err
	}
	return nil
}

func waitForBridge(bridgeName string) error {
	for retry := 0; retry < maxRetryForOFSwitch; retry++ {
		klog.V(2).Infof("Trying to connect to OpenFlow switch...")
		cmd := exec.Command("ovs-ofctl", "show", bridgeName)
		if err := cmd.Run(); err != nil {
			time.Sleep(1 * time.Second)
		} else {
			return nil
		}
	}
	return fmt.Errorf("failed to connect to OpenFlow switch after %d tries", maxRetryForOFSwitch)
}

func (c *client) Initialize() error {
	// Wait for the OpenFlow switch to be ready.
	// Without this, the rest of the steps can fail with "<bridge> is not a bridge or a socket".
	// TODO: this may not be needed any more after we transition to libopenflow and stop using
	// ovs-ofctl directly
	if err := waitForBridge(c.bridge.GetName()); err != nil {
		return err
	}

	for _, flow := range c.defaultFlows() {
		if err := c.flowOperations.Add(flow); err != nil {
			return fmt.Errorf("failed to install default flows: %v", err)
		}
	}
	if err := c.flowOperations.Add(c.arpNormalFlow()); err != nil {
		return fmt.Errorf("failed to install arp normal flow: %v", err)
	}
	if err := c.flowOperations.Add(c.l2ForwardOutputFlow()); err != nil {
		return fmt.Errorf("failed to install l2 forward output flows: %v", err)
	}
	for _, flow := range c.connectionTrackFlows() {
		if err := c.flowOperations.Add(flow); err != nil {
			return fmt.Errorf("failed to install connection track flows: %v", err)
		}
	}
	return nil
}

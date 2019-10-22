// Copyright 2019 OKN Authors
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

	binding "okn/pkg/ovs/openflow"
)

const maxRetryForOFSwitch = 5

//go:generate mockgen -copyright_file ../../../hack/boilerplate/license_header.go.txt -destination testing/mock_client.go -package=testing okn/pkg/agent/openflow Client

// Client is the interface to program OVS flows for entity connectivity of OKN.
// TODO: flow sync (e.g. at agent restart), retry at failure, garbage collection mechanisms
type Client interface {
	// Initialize sets up all basic flows on the specific OVS bridge.
	Initialize() error

	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallTunnelFlows sets up flows related to an OVS tunnel port, the tunnel port must exist.
	InstallTunnelFlows(tunnelOFPort uint32) error

	// InstallNodeFlows should be invoked when a connection to a remote node is going to be set up.
	// The hostname is used to identify the added flows.
	InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error

	// UninstallNodeFlows removes the connection to the remote node specified with the hostname. UninstallNodeFlows will
	// do nothing if no connection to the host was established.
	UninstallNodeFlows(hostname string) error

	// InstallPodFlows should be invoked when a connection to a pod on current node.
	// The containerID is used to identify the added flows.
	InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error

	// UninstallPodFlows removes the connection to the local pod specified with the containerID. UninstallPodFlows will
	// do nothing if no connection to the pod was established.
	UninstallPodFlows(containerID string) error

	// InstallServiceFlows should be invoked when a connection to a kubernetes service is going to be connected, all
	// arguments should be filled. The serviceName is used to identify the added flows.
	InstallServiceFlows(serviceName string, serviceNet *net.IPNet, gatewayOFPort uint32) error

	// UninstallServiceFlows removes the connection to the service specified with the serviceName. UninstallServiceFlows
	// will do nothing if no connection to the service was established.
	UninstallServiceFlows(serviceName string) error

	// GetFlowTableStatus should return an array of flow table status, all existing flow tables should be included in the list.
	GetFlowTableStatus() []binding.TableStatus
}

// GetFlowTableStatus returns an array of flow table status.
func (c *client) GetFlowTableStatus() []binding.TableStatus {
	return c.bridge.DumpTableStatus()
}

func (c *client) InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error {
	flow := c.arpResponderFlow(peerGatewayIP.String())
	if err := flow.Add(); err != nil {
		return err
	}
	c.nodeFlowCache[hostname] = append(c.nodeFlowCache[hostname], flow)

	flow = c.l3FwdFlowToRemote(localGatewayMAC.String(), peerPodCIDR.String(), peerTunnelName)
	if err := flow.Add(); err != nil {
		return err
	}
	c.nodeFlowCache[hostname] = append(c.nodeFlowCache[hostname], flow)
	return nil
}

func (c *client) UninstallNodeFlows(hostname string) error {
	defer delete(c.nodeFlowCache, hostname)
	for _, flow := range c.nodeFlowCache[hostname] {
		if err := flow.Delete(); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallPodFlows(containerID string, podInterfaceIP net.IP, podInterfaceMAC, gatewayMAC net.HardwareAddr, ofPort uint32) error {
	flow := c.podClassifierFlow(ofPort)
	if err := flow.Add(); err != nil {
		return err
	}
	c.podFlowCache[containerID] = append(c.podFlowCache[containerID], flow)

	flow = c.podIPSpoofGuardFlow(podInterfaceIP.String(), podInterfaceMAC.String(), ofPort)
	if err := flow.Add(); err != nil {
		return err
	}
	c.podFlowCache[containerID] = append(c.podFlowCache[containerID], flow)

	flow = c.arpSpoofGuardFlow(podInterfaceIP.String(), podInterfaceMAC.String(), ofPort)
	if err := flow.Add(); err != nil {
		return err
	}
	c.podFlowCache[containerID] = append(c.podFlowCache[containerID], flow)

	flow = c.l2ForwardCalcFlow(podInterfaceMAC.String(), ofPort)
	if err := flow.Add(); err != nil {
		return err
	}
	c.podFlowCache[containerID] = append(c.podFlowCache[containerID], flow)

	flow = c.l3FlowsToPod(gatewayMAC.String(), podInterfaceIP.String(), podInterfaceMAC.String())
	if err := flow.Add(); err != nil {
		return err
	}
	c.podFlowCache[containerID] = append(c.podFlowCache[containerID], flow)

	return nil
}

func (c *client) UninstallPodFlows(containerID string) error {
	defer delete(c.podFlowCache, containerID)
	for _, flow := range c.podFlowCache[containerID] {
		if err := flow.Delete(); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallServiceFlows(serviceName string, serviceNet *net.IPNet, gatewayOFPort uint32) error {
	flow := c.serviceCIDRDNATFlow(serviceNet, gatewayOFPort)
	if err := flow.Add(); err != nil {
		return err
	}
	c.serviceCache[serviceName] = append(c.serviceCache[serviceName], flow)
	return nil
}

func (c *client) UninstallServiceFlows(serviceName string) error {
	defer delete(c.serviceCache, serviceName)
	for _, flow := range c.serviceCache[serviceName] {
		if err := flow.Delete(); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error {
	if err := c.gatewayClassifierFlow(gatewayOFPort).Add(); err != nil {
		return err
	} else if err := c.gatewayIPSpoofGuardFlow(gatewayOFPort).Add(); err != nil {
		return err
	} else if err := c.gatewayARPSpoofGuardFlow(gatewayOFPort).Add(); err != nil {
		return err
	} else if err := c.l3ToGatewayFlow(gatewayAddr.String(), gatewayMAC.String()).Add(); err != nil {
		return err
	} else if err := c.l2ForwardCalcFlow(gatewayMAC.String(), gatewayOFPort).Add(); err != nil {
		return err
	}
	return nil
}

func (c *client) InstallTunnelFlows(tunnelOFPort uint32) error {
	if err := c.tunnelClassifierFlow(tunnelOFPort).Add(); err != nil {
		return err
	} else if err := c.l2ForwardCalcFlow(globalVirtualMAC, tunnelOFPort).Add(); err != nil {
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
		if err := flow.Add(); err != nil {
			return fmt.Errorf("failed to install default flows: %v", err)
		}
	}
	if err := c.arpNormalFlow().Add(); err != nil {
		return fmt.Errorf("failed to install arp normal flow: %v", err)
	}
	if err := c.l2ForwardOutputFlow().Add(); err != nil {
		return fmt.Errorf("failed to install l2 forward output flows: %v", err)
	}
	for _, flow := range c.connectionTrackFlows() {
		if err := flow.Add(); err != nil {
			return fmt.Errorf("failed to install connection track flows: %v", err)
		}
	}
	return nil
}

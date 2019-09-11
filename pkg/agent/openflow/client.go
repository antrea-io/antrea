package openflow

import (
	"net"
)

// Client is the interface to program OVS flows for entity connectivity of OKN.
// TODO: flow sync (e.g. at agent restart), retry at failure, garbage collection mechanisms
type Client interface {
	// InstallGatewayFlows sets up flows related to an OVS gateway port, the gateway must exist.
	InstallGatewayFlows(gatewayAddr net.IP, gatewayMAC net.HardwareAddr, gatewayOFPort uint32) error

	// InstallTunnelFlows sets up flows related to an OVS tunnel port, the tunnel port must exist.
	InstallTunnelFlows(tunnelOFPort uint32) error

	// InstallNodeFlows should be invoked when a connection to a remote node is going to be set up.
	// The hostname is used to identify the added flows.
	InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerNodeIP, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error

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
}

func (c *client) InstallNodeFlows(hostname string, localGatewayMAC net.HardwareAddr, peerNodeIP, peerGatewayIP net.IP, peerPodCIDR net.IPNet, peerTunnelName string) error {
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

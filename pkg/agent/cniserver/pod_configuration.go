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

package cniserver

import (
	"encoding/json"
	"fmt"
	"net"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

type k8sArgs struct {
	cnitypes.CommonArgs
	K8S_POD_NAME               cnitypes.UnmarshallableString
	K8S_POD_NAMESPACE          cnitypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cnitypes.UnmarshallableString
}

const (
	ovsExternalIDMAC          = "attached-mac"
	ovsExternalIDIP           = "ip-address"
	ovsExternalIDContainerID  = "container-id"
	ovsExternalIDPodName      = "pod-name"
	ovsExternalIDPodNamespace = "pod-namespace"
)

const (
	defaultOVSInterfaceType int = iota
	internalOVSInterfaceType
)

type interfaceConfigurator interface {
	configureContainerLink(podName, podNameSpace, containerID, containerNetNS, containerIFDev string, mtu int, result *current.Result) error
	advertiseContainerAddr(containerNetNS string, containerIfaceName string, result *current.Result) error
	removeContainerLink(containerID, hostInterfaceName string) error
	checkContainerInterface(containerNetns, containerID string, containerIface *current.Interface, containerIPs []*current.IPConfig, containerRoutes []*cnitypes.Route) (*vethPair, error)
	validateContainerPeerInterface(interfaces []*current.Interface, containerVeth *vethPair) (*vethPair, error)
	getOVSInterfaceType() int
	getInterceptedInterfaces(sandbox, containerNS, containerIFDev string) (*current.Interface, *current.Interface, error)
}

type podConfigurator struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	ofClient        openflow.Client
	routeClient     route.Interface
	ifaceStore      interfacestore.InterfaceStore
	gatewayMAC      net.HardwareAddr
	ifConfigurator  interfaceConfigurator
}

func newPodConfigurator(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	routeClient route.Interface,
	ifaceStore interfacestore.InterfaceStore,
	gatewayMAC net.HardwareAddr,
	ovsDatapathType string,
) (*podConfigurator, error) {
	ifConfigurator, err := newInterfaceConfigurator(ovsDatapathType)
	if err != nil {
		return nil, err
	}
	return &podConfigurator{
		ovsBridgeClient: ovsBridgeClient,
		ofClient:        ofClient,
		routeClient:     routeClient,
		ifaceStore:      ifaceStore,
		gatewayMAC:      gatewayMAC,
		ifConfigurator:  ifConfigurator,
	}, nil
}

func findContainerIPConfig(ips []*current.IPConfig) (*current.IPConfig, error) {
	for _, ipc := range ips {
		if ipc.Version == "4" {
			return ipc, nil
		}
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func parseContainerIP(ips []*current.IPConfig) (net.IP, error) {
	ipc, err := findContainerIPConfig(ips)
	if err == nil {
		return ipc.Address.IP, nil
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func buildContainerConfig(
	interfaceName, containerID, podName, podNamespace string,
	containerIface *current.Interface,
	ips []*current.IPConfig) *interfacestore.InterfaceConfig {
	containerIP, err := parseContainerIP(ips)
	if err != nil {
		klog.Errorf("Failed to find container %s IP", containerID)
	}
	// containerIface.Mac should be a valid MAC string, otherwise it should throw error before
	containerMAC, _ := net.ParseMAC(containerIface.Mac)
	return interfacestore.NewContainerInterface(
		interfaceName,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
}

// BuildOVSPortExternalIDs parses OVS port external_ids from InterfaceConfig.
// external_ids are used to compare and sync container interface configuration.
func BuildOVSPortExternalIDs(containerConfig *interfacestore.InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[ovsExternalIDMAC] = containerConfig.MAC.String()
	externalIDs[ovsExternalIDContainerID] = containerConfig.ContainerID
	externalIDs[ovsExternalIDIP] = containerConfig.IP.String()
	externalIDs[ovsExternalIDPodName] = containerConfig.PodName
	externalIDs[ovsExternalIDPodNamespace] = containerConfig.PodNamespace
	return externalIDs
}

// ParseOVSPortInterfaceConfig reads the Pod properties saved in the OVS port
// external_ids, initializes and returns an InterfaceConfig struct.
// nill will be returned, if the OVS port does not have external IDs or it is
// not created for a Pod interface.
func ParseOVSPortInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	if portData.ExternalIDs == nil {
		klog.V(2).Infof("OVS port %s has no external_ids", portData.Name)
		return nil
	}

	containerID, found := portData.ExternalIDs[ovsExternalIDContainerID]
	if !found {
		klog.V(2).Infof("OVS port %s has no %s in external_ids", portData.Name, ovsExternalIDContainerID)
		return nil
	}
	containerIP := net.ParseIP(portData.ExternalIDs[ovsExternalIDIP])
	containerMAC, err := net.ParseMAC(portData.ExternalIDs[ovsExternalIDMAC])
	if err != nil {
		klog.Errorf("Failed to parse MAC address from OVS external config %s: %v",
			portData.ExternalIDs[ovsExternalIDMAC], err)
	}
	podName, _ := portData.ExternalIDs[ovsExternalIDPodName]
	podNamespace, _ := portData.ExternalIDs[ovsExternalIDPodNamespace]

	interfaceConfig := interfacestore.NewContainerInterface(
		portData.Name,
		containerID,
		podName,
		podNamespace,
		containerMAC,
		containerIP)
	interfaceConfig.OVSPortConfig = portConfig
	return interfaceConfig
}

func (pc *podConfigurator) configureInterfaces(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	mtu int,
	result *current.Result,
) error {
	err := pc.ifConfigurator.configureContainerLink(podName, podNameSpace, containerID, containerNetNS, containerIFDev, mtu, result)
	if err != nil {
		return err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	// Delete veth pair if any failure occurs in later manipulation.
	success := false
	defer func() {
		if !success {
			_ = pc.ifConfigurator.removeContainerLink(containerID, hostIface.Name)
		}
	}()

	// Check if the OVS configurations for the container exists or not. If yes, return immediately. This check is
	// used on Windows, for Kubelet on Windows will call CNI Add for both the infrastructure container and the workload
	// container. But there should be only one OVS port created for the same Pod. And if the OVS port is added more than
	// once, OVS will return an error.
	_, found := pc.ifaceStore.GetContainerInterface(podName, podNameSpace)
	if found {
		klog.V(2).Infof("Found an existed OVS port with podName %s podNamespace %s, returning", podName, podNameSpace)
		// Mark the operation as successful, otherwise the container link might be removed by mistake.
		success = true
		return nil
	}

	var containerConfig *interfacestore.InterfaceConfig
	if containerConfig, err = pc.connectInterfaceToOVS(podName, podNameSpace, containerID, hostIface, containerIface, result.IPs); err != nil {
		return fmt.Errorf("failed to connect to ovs for container %s: %v", containerID, err)
	}
	defer func() {
		if !success {
			_ = pc.disconnectInterfaceFromOVS(containerConfig)
		}
	}()

	// Note that the IP address should be advertised after Pod OpenFlow entries are installed, otherwise the packet might
	// be dropped by OVS.
	if err = pc.ifConfigurator.advertiseContainerAddr(containerNetNS, containerIface.Name, result); err != nil {
		klog.Errorf("Failed to advertise IP address for container %s: %v", containerID, err)
	}
	// Mark the manipulation as success to cancel deferred operations.
	success = true
	klog.Infof("Configured interfaces for container %s", containerID)
	return nil
}

func (pc *podConfigurator) createOVSPort(ovsPortName string, ovsAttachInfo map[string]interface{}) (string, error) {
	var portUUID string
	var err error
	switch pc.ifConfigurator.getOVSInterfaceType() {
	case internalOVSInterfaceType:
		portUUID, err = pc.ovsBridgeClient.CreateInternalPort(ovsPortName, 0, ovsAttachInfo)
	default:
		portUUID, err = pc.ovsBridgeClient.CreatePort(ovsPortName, ovsPortName, ovsAttachInfo)
	}
	if err != nil {
		klog.Errorf("Failed to add OVS port %s, remove from local cache: %v", ovsPortName, err)
		return "", err
	} else {
		return portUUID, nil
	}
}

func (pc *podConfigurator) removeInterfaces(podName, podNamespace, containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace)
	if !found {
		klog.V(2).Infof("Did not find the port for container %s in local cache", containerID)
		return nil
	}

	// Deleting veth devices and OVS port must be called after Openflows are uninstalled.
	// Otherwise there could be a race condition:
	// 1. Pod A's ofport was released
	// 2. Pod B got the ofport released above
	// 3. Flows for Pod B were installed
	// 4. Flows for Pod A were uninstalled
	// Because Pod A and Pod B had same ofport, they had overlapping flows, e.g. the
	// classifier flow in table 0 which has only in_port as the match condition, then
	// step 4 can remove flows owned by Pod B by mistake.
	// Note that deleting the interface attached to an OVS port can release the ofport.
	if err := pc.disconnectInterfaceFromOVS(containerConfig); err != nil {
		return err
	}

	if err := pc.ifConfigurator.removeContainerLink(containerID, containerConfig.InterfaceName); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkInterfaces(
	containerID, containerNetNS, podName, podNamespace string,
	containerIface *current.Interface,
	prevResult *current.Result) error {
	if containerVeth, err := pc.ifConfigurator.checkContainerInterface(
		containerNetNS,
		containerID,
		containerIface,
		prevResult.IPs,
		prevResult.Routes); err != nil {
		return err
	} else if err := pc.checkHostInterface(
		containerID,
		podName,
		podNamespace,
		containerIface,
		containerVeth,
		prevResult.IPs,
		prevResult.Interfaces); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkHostInterface(
	containerID, podName, podNamespace string,
	containerIntf *current.Interface,
	containerVeth *vethPair,
	containerIPs []*current.IPConfig,
	interfaces []*current.Interface) error {
	hostVeth, errlink := pc.ifConfigurator.validateContainerPeerInterface(interfaces, containerVeth)
	if errlink != nil {
		klog.Errorf("Failed to check container %s interface on the host: %v",
			containerID, errlink)
		return errlink
	}
	if err := pc.validateOVSInterfaceConfig(containerID,
		podName,
		podNamespace,
		containerIntf.Mac,
		containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			hostVeth.name, containerID, err)
		return err
	}
	return nil
}

func (pc *podConfigurator) validateOVSInterfaceConfig(
	containerID, podName, podNamespace string,
	containerMAC string,
	ips []*current.IPConfig) error {
	if containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace); found {
		if containerConfig.MAC.String() != containerMAC {
			return fmt.Errorf("interface MAC %s does not match container %s MAC",
				containerConfig.MAC.String(), containerID)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				if containerConfig.IP.Equal(ipc.Address.IP) {
					return nil
				}
			}
		}
		return fmt.Errorf("interface IP %s does not match container %s IP",
			containerConfig.IP.String(), containerID)
	} else {
		return fmt.Errorf("container %s interface not found from local cache", containerID)
	}
}

func parsePrevResult(conf *NetworkConfig) error {
	if conf.RawPrevResult == nil {
		return nil
	}

	resultBytes, err := json.Marshal(conf.RawPrevResult)
	if err != nil {
		return fmt.Errorf("could not serialize prevResult: %v", err)
	}
	conf.RawPrevResult = nil
	conf.PrevResult, err = version.NewResult(conf.CNIVersion, resultBytes)
	if err != nil {
		return fmt.Errorf("could not parse prevResult: %v", err)
	}
	return nil
}

func (pc *podConfigurator) reconcile(pods []corev1.Pod) error {
	// desiredInterfaces is the exact set of interfaces that should be present, based on the
	// current list of Pods.
	desiredInterfaces := make(map[string]bool)
	// knownInterfaces is the list of interfaces currently in the local cache.
	knownInterfaces := pc.ifaceStore.GetInterfaceKeysByType(interfacestore.ContainerInterface)

	for _, pod := range pods {
		// Skip Pods for which we are not in charge of the networking.
		if pod.Spec.HostNetwork {
			continue
		}

		// We rely on the interface cache / store - which is initialized from the persistent
		// OVSDB - to map the Pod to its interface configuration. The interface
		// configuration includes the parameters we need to replay the flows.
		containerConfig, found := pc.ifaceStore.GetContainerInterface(pod.Name, pod.Namespace)
		if !found {
			// This should not happen since OVSDB is persisted on the Node.
			// TODO: is there anything else we should be doing? Assuming that the Pod's
			// interface still exists, we can repair the interface store since we can
			// retrieve the name of the host interface for the Pod by calling
			// GenerateContainerInterfaceName. One thing we would not be able to
			// retrieve is the container ID which is part of the container configuration
			// we store in the cache, but this ID is not used for anything at the
			// moment. However, if the interface does not exist, there is nothing we can
			// do since we do not have the original CNI parameters.
			klog.Warningf("Interface for Pod %s/%s not found in the interface store", pod.Namespace, pod.Name)
			continue
		}
		klog.V(4).Infof("Syncing interface %s for Pod %s/%s", containerConfig.InterfaceName, pod.Namespace, pod.Name)
		if err := pc.ofClient.InstallPodFlows(
			containerConfig.InterfaceName,
			containerConfig.IP,
			containerConfig.MAC,
			pc.gatewayMAC,
			uint32(containerConfig.OFPort),
		); err != nil {
			klog.Errorf("Error when re-installing flows for Pod %s/%s", pod.Namespace, pod.Name)
			continue
		}
		desiredInterfaces[util.GenerateContainerInterfaceKey(pod.Name, pod.Namespace)] = true
	}

	for _, ifaceID := range knownInterfaces {
		if _, found := desiredInterfaces[ifaceID]; found {
			// this interface matches an existing Pod.
			continue
		}
		// clean-up and delete interface
		containerConfig, found := pc.ifaceStore.GetInterface(ifaceID)
		if !found {
			// should not happen, nothing should have concurrent access to the interface
			// store.
			klog.Errorf("Interface %s can no longer be found in the interface store", ifaceID)
			continue
		}
		klog.V(4).Infof("Deleting interface %s", ifaceID)
		if err := pc.removeInterfaces(
			containerConfig.PodName,
			containerConfig.PodNamespace,
			containerConfig.ContainerID,
		); err != nil {
			klog.Errorf("Failed to delete interface %s: %v", ifaceID, err)
		}
		// interface should no longer be in store after the call to removeInterfaces
	}
	return nil
}

// connectInterfaceToOVS connects an existing interface to ovs br-int.
func (pc *podConfigurator) connectInterfaceToOVS(
	podName string,
	podNameSpace string,
	containerID string,
	hostIface *current.Interface,
	containerIface *current.Interface,
	ips []*current.IPConfig,
) (*interfacestore.InterfaceConfig, error) {
	// Use the outer veth interface name as the OVS port name.
	ovsPortName := hostIface.Name
	containerConfig := buildContainerConfig(ovsPortName, containerID, podName, podNameSpace, containerIface, ips)

	// create OVS Port and add attach container configuration into external_ids
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
	}
	// Remove OVS port if any failure occurs in later manipulation.
	defer func() {
		if err != nil {
			_ = pc.ovsBridgeClient.DeletePort(portUUID)
		}
	}()

	// GetOFPort will wait for up to 1 second for OVSDB to report the OFPort number.
	ofPort, err := pc.ovsBridgeClient.GetOFPort(ovsPortName)
	if err != nil {
		return nil, fmt.Errorf("failed to get of_port of OVS port %s: %v", ovsPortName, err)
	}

	klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
	err = pc.ofClient.InstallPodFlows(ovsPortName, containerConfig.IP, containerConfig.MAC, pc.gatewayMAC, uint32(ofPort))
	if err != nil {
		return nil, fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
	}
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	return containerConfig, nil
}

// disconnectInterfaceFromOVS disconnects an existing interface from ovs br-int.
func (pc *podConfigurator) disconnectInterfaceFromOVS(containerConfig *interfacestore.InterfaceConfig) error {
	containerID := containerConfig.ContainerID
	klog.V(2).Infof("Deleting Openflow entries for container %s", containerID)
	if err := pc.ofClient.UninstallPodFlows(containerConfig.InterfaceName); err != nil {
		return fmt.Errorf("failed to delete Openflow entries for container %s: %v", containerID, err)
		// We should not delete OVS port if Pod flows deletion fails, otherwise
		// it is possible a new Pod will reuse the reclaimed ofport number, and
		// the OVS flows added for the new Pod can conflict with the stale
		// flows of the deleted Pod.
	}

	klog.V(2).Infof("Deleting OVS port %s for container %s", containerConfig.PortUUID, containerID)
	// TODO: handle error and introduce garbage collection for failure on deletion
	if err := pc.ovsBridgeClient.DeletePort(containerConfig.PortUUID); err != nil {
		return fmt.Errorf("failed to delete OVS port for container %s: %v", containerID, err)
	}
	// Remove container configuration from cache.
	pc.ifaceStore.DeleteInterface(containerConfig)
	klog.Infof("Removed interfaces for container %s", containerID)
	return nil
}

// connectInterceptedInterface connects intercepted interface to ovs br-int.
func (pc *podConfigurator) connectInterceptedInterface(
	podName string,
	podNameSpace string,
	containerID string,
	containerNetNS string,
	containerIFDev string,
	containerIPs []*current.IPConfig,
) error {
	sandbox, err := util.GetNSPath(containerNetNS)
	if err != nil {
		return err
	}
	containerIface, hostIface, err := pc.ifConfigurator.getInterceptedInterfaces(sandbox, containerNetNS, containerIFDev)
	if err != nil {
		return err
	}
	if err = pc.routeClient.MigrateRoutesToGw(hostIface.Name); err != nil {
		return fmt.Errorf("connectInterceptedInterface failed to migrate: %w", err)
	}
	_, err = pc.connectInterfaceToOVS(podName, podNameSpace, containerID, hostIface,
		containerIface, containerIPs)
	return err
}

// disconnectInterceptedInterface disconnects intercepted interface from ovs br-int.
func (pc *podConfigurator) disconnectInterceptedInterface(podName, podNamespace, containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(podName, podNamespace)
	if !found {
		klog.V(2).Infof("Did not find the port for container %s in local cache", containerID)
		return nil
	}
	if err := pc.routeClient.UnMigrateRoutesFromGw(&net.IPNet{
		IP:   containerConfig.IP,
		Mask: net.CIDRMask(32, 32),
	}, ""); err != nil {
		return fmt.Errorf("connectInterceptedInterface failed to migrate: %w", err)
	}
	return pc.disconnectInterfaceFromOVS(containerConfig)
	// TODO recover pre-connect state? repatch vethpair to original bridge etc ?? to make first CNI happy??
}

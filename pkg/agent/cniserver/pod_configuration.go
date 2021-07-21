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
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/k8s"
)

type vethPair struct {
	name      string
	ifIndex   int
	peerIndex int
}

const (
	ovsExternalIDMAC          = "attached-mac"
	ovsExternalIDIP           = "ip-address"
	ovsExternalIDContainerID  = "container-id"
	ovsExternalIDPodName      = "pod-name"
	ovsExternalIDPodNamespace = "pod-namespace"
)

const (
	defaultOVSInterfaceType int = iota //nolint suppress deadcode check for windows
	internalOVSInterfaceType
)

type podConfigurator struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	ofClient        openflow.Client
	routeClient     route.Interface
	ifaceStore      interfacestore.InterfaceStore
	gatewayMAC      net.HardwareAddr
	ifConfigurator  *ifConfigurator
	// entityUpdates is a channel for notifying updates of local endpoints / entities (most notably Pod)
	// to other components which may benefit from this information, i.e NetworkPolicyController.
	entityUpdates chan<- types.EntityReference
}

func newPodConfigurator(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	routeClient route.Interface,
	ifaceStore interfacestore.InterfaceStore,
	gatewayMAC net.HardwareAddr,
	ovsDatapathType ovsconfig.OVSDatapathType,
	isOvsHardwareOffloadEnabled bool,
	entityUpdates chan<- types.EntityReference,
) (*podConfigurator, error) {
	ifConfigurator, err := newInterfaceConfigurator(ovsDatapathType, isOvsHardwareOffloadEnabled)
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
		entityUpdates:   entityUpdates,
	}, nil
}

func parseContainerIPs(ipcs []*current.IPConfig) ([]net.IP, error) {
	var ips []net.IP
	for _, ipc := range ipcs {
		ips = append(ips, ipc.Address.IP)
	}
	if len(ips) > 0 {
		return ips, nil
	}
	return nil, fmt.Errorf("failed to find a valid IP address")
}

func buildContainerConfig(
	interfaceName, containerID, podName, podNamespace string,
	containerIface *current.Interface,
	ips []*current.IPConfig) *interfacestore.InterfaceConfig {
	containerIPs, err := parseContainerIPs(ips)
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
		containerIPs)
}

// BuildOVSPortExternalIDs parses OVS port external_ids from InterfaceConfig.
// external_ids are used to compare and sync container interface configuration.
func BuildOVSPortExternalIDs(containerConfig *interfacestore.InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[ovsExternalIDMAC] = containerConfig.MAC.String()
	externalIDs[ovsExternalIDContainerID] = containerConfig.ContainerID
	externalIDs[ovsExternalIDIP] = getContainerIPsString(containerConfig.IPs)
	externalIDs[ovsExternalIDPodName] = containerConfig.PodName
	externalIDs[ovsExternalIDPodNamespace] = containerConfig.PodNamespace
	return externalIDs
}

func getContainerIPsString(ips []net.IP) string {
	var containerIPs []string
	for _, ip := range ips {
		containerIPs = append(containerIPs, ip.String())
	}
	return strings.Join(containerIPs, ",")
}

// ParseOVSPortInterfaceConfig reads the Pod properties saved in the OVS port
// external_ids, initializes and returns an InterfaceConfig struct.
// nill will be returned, if the OVS port does not have external IDs or it is
// not created for a Pod interface.
// If "checkMac" param is set as true the ovsExternalIDMAC of portData should be
// a valid MAC string, otherwise it will print error.
func ParseOVSPortInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig, checkMac bool) *interfacestore.InterfaceConfig {
	if portData.ExternalIDs == nil {
		klog.V(2).Infof("OVS port %s has no external_ids", portData.Name)
		return nil
	}

	containerID, found := portData.ExternalIDs[ovsExternalIDContainerID]
	if !found {
		klog.V(2).Infof("OVS port %s has no %s in external_ids", portData.Name, ovsExternalIDContainerID)
		return nil
	}
	containerIPStrs := strings.Split(portData.ExternalIDs[ovsExternalIDIP], ",")
	var containerIPs []net.IP
	for _, ipStr := range containerIPStrs {
		containerIPs = append(containerIPs, net.ParseIP(ipStr))
	}

	containerMAC, err := net.ParseMAC(portData.ExternalIDs[ovsExternalIDMAC])
	if err != nil && checkMac {
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
		containerIPs)
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
	sriovVFDeviceID string,
	result *current.Result,
	createOVSPort bool,
	containerAccess *containerAccessArbitrator,
) error {
	err := pc.ifConfigurator.configureContainerLink(podName, podNameSpace, containerID, containerNetNS, containerIFDev, mtu, sriovVFDeviceID, "", result, containerAccess)
	if err != nil {
		return err
	}
	hostIface := result.Interfaces[0]
	containerIface := result.Interfaces[1]

	if !createOVSPort {
		return nil
	}

	// Delete veth pair if any failure occurs in later manipulation.
	success := false
	defer func() {
		if !success {
			_ = pc.ifConfigurator.removeContainerLink(containerID, hostIface.Name)
		}
	}()

	// Check if the OVS configurations for the container exists or not. If yes, return immediately. This check is
	// used on Windows, as kubelet on Windows will call CNI Add for infrastructure container for multiple times
	// to query IP of Pod. But there should be only one OVS port created for the same Pod (identified by its sandbox
	// container ID). And if the OVS port is added more than once, OVS will return an error.
	// See https://github.com/kubernetes/kubernetes/issues/57253#issuecomment-358897721.
	_, found := pc.ifaceStore.GetContainerInterface(containerID)
	if found {
		klog.V(2).Infof("Found an existing OVS port for container %s, returning", containerID)
		// Mark the operation as successful, otherwise the container link might be removed by mistake.
		success = true
		return nil
	}

	var containerConfig *interfacestore.InterfaceConfig
	if containerConfig, err = pc.connectInterfaceToOVS(podName, podNameSpace, containerID, hostIface, containerIface, result.IPs, containerAccess); err != nil {
		return fmt.Errorf("failed to connect to ovs for container %s: %v", containerID, err)
	}
	success = true
	defer func() {
		if !success {
			_ = pc.disconnectInterfaceFromOVS(containerConfig)
		}
	}()

	if err := pc.routeClient.AddLocalAntreaFlexibleIPAMPodRule(containerConfig.IPs); err != nil {
		return err
	}

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
	}
	return portUUID, nil
}

func (pc *podConfigurator) removeInterfaces(containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(containerID)
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

	if err := pc.routeClient.DeleteLocalAntreaFlexibleIPAMPodRule(containerConfig.IPs); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkInterfaces(
	containerID, containerNetNS string,
	containerIface *current.Interface,
	prevResult *current.Result, sriovVFDeviceID string) error {
	if link, err := pc.ifConfigurator.checkContainerInterface(
		containerNetNS,
		containerID,
		containerIface,
		prevResult.IPs,
		prevResult.Routes,
		sriovVFDeviceID); err != nil {
		return err
	} else if err := pc.checkHostInterface(
		containerID,
		containerIface,
		link,
		prevResult.IPs,
		prevResult.Interfaces,
		sriovVFDeviceID); err != nil {
		return err
	}
	return nil
}

func (pc *podConfigurator) checkHostInterface(
	containerID string,
	containerIntf *current.Interface,
	containerIfKind interface{},
	containerIPs []*current.IPConfig,
	interfaces []*current.Interface,
	sriovVFDeviceID string,
) error {
	var ifname string
	if sriovVFDeviceID != "" {
		vfRep, errlink := pc.ifConfigurator.validateVFRepInterface(sriovVFDeviceID)
		if errlink != nil {
			klog.Errorf("Failed to check container %s interface on the host: %v",
				containerID, errlink)
			return errlink
		}
		ifname = vfRep
	} else {
		containerVeth := containerIfKind.(*vethPair)
		hostVeth, errlink := pc.ifConfigurator.validateContainerPeerInterface(interfaces, containerVeth)
		if errlink != nil {
			klog.Errorf("Failed to check container %s interface on the host: %v",
				containerID, errlink)
			return errlink
		}
		ifname = hostVeth.name
	}
	if err := pc.validateOVSInterfaceConfig(containerID, containerIntf.Mac, containerIPs); err != nil {
		klog.Errorf("Failed to check host link %s for container %s attaching status on ovs. err: %v",
			ifname, containerID, err)
		return err
	}
	return nil
}

func (pc *podConfigurator) validateOVSInterfaceConfig(containerID string, containerMAC string, ips []*current.IPConfig) error {
	if containerConfig, found := pc.ifaceStore.GetContainerInterface(containerID); found {
		if containerConfig.MAC.String() != containerMAC {
			return fmt.Errorf("interface MAC %s does not match container %s MAC",
				containerConfig.MAC.String(), containerID)
		}

		for _, ipc := range ips {
			if ipc.Version == "4" {
				ipv4Addr := util.GetIPv4Addr(containerConfig.IPs)
				if ipv4Addr != nil && ipv4Addr.Equal(ipc.Address.IP) {
					return nil
				}
			}
		}
		return fmt.Errorf("interface IP %s does not match container %s IP",
			getContainerIPsString(containerConfig.IPs), containerID)
	}
	return fmt.Errorf("container %s interface not found from local cache", containerID)
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

func (pc *podConfigurator) reconcile(pods []corev1.Pod, containerAccess *containerAccessArbitrator) error {
	// desiredPods is the set of Pods that should be present, based on the
	// current list of Pods got from the Kubernetes API.
	desiredPods := sets.NewString()
	// actualPods is the set of Pods that are present, based on the container
	// interfaces got from the OVSDB.
	actualPods := sets.NewString()
	// knownInterfaces is the list of interfaces currently in the local cache.
	knownInterfaces := pc.ifaceStore.GetInterfacesByType(interfacestore.ContainerInterface)

	for _, pod := range pods {
		// Skip Pods for which we are not in charge of the networking.
		if pod.Spec.HostNetwork {
			continue
		}
		desiredPods.Insert(k8s.NamespacedName(pod.Namespace, pod.Name))
	}

	for _, containerConfig := range knownInterfaces {
		namespacedName := k8s.NamespacedName(containerConfig.PodNamespace, containerConfig.PodName)
		actualPods.Insert(namespacedName)
		if desiredPods.Has(namespacedName) {
			// This interface matches an existing Pod.
			// We rely on the interface cache / store - which is initialized from the persistent
			// OVSDB - to map the Pod to its interface configuration. The interface
			// configuration includes the parameters we need to replay the flows.
			klog.V(4).Infof("Syncing interface %s for Pod %s", containerConfig.InterfaceName, namespacedName)
			if err := pc.ofClient.InstallPodFlows(
				containerConfig.InterfaceName,
				containerConfig.IPs,
				containerConfig.MAC,
				uint32(containerConfig.OFPort),
			); err != nil {
				klog.Errorf("Error when re-installing flows for Pod %s", namespacedName)
			}
		} else {
			// clean-up and delete interface
			klog.V(4).Infof("Deleting interface %s", containerConfig.InterfaceName)
			if err := pc.removeInterfaces(containerConfig.ContainerID); err != nil {
				klog.Errorf("Failed to delete interface %s: %v", containerConfig.InterfaceName, err)
			}
			// interface should no longer be in store after the call to removeInterfaces
		}
	}

	missingPods := desiredPods.Difference(actualPods)
	pc.reconcileMissingPods(missingPods, containerAccess)
	return nil
}

func (pc *podConfigurator) connectInterfaceToOVSCommon(ovsPortName string, containerConfig *interfacestore.InterfaceConfig) error {
	// create OVS Port and add attach container configuration into external_ids
	containerID := containerConfig.ContainerID
	klog.V(2).Infof("Adding OVS port %s for container %s", ovsPortName, containerID)
	ovsAttachInfo := BuildOVSPortExternalIDs(containerConfig)
	portUUID, err := pc.createOVSPort(ovsPortName, ovsAttachInfo)
	if err != nil {
		return fmt.Errorf("failed to add OVS port for container %s: %v", containerID, err)
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
		return fmt.Errorf("failed to get of_port of OVS port %s: %v", ovsPortName, err)
	}

	klog.V(2).Infof("Setting up Openflow entries for container %s", containerID)
	err = pc.ofClient.InstallPodFlows(ovsPortName, containerConfig.IPs, containerConfig.MAC, uint32(ofPort))
	if err != nil {
		return fmt.Errorf("failed to add Openflow entries for container %s: %v", containerID, err)
	}
	containerConfig.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	// Add containerConfig into local cache
	pc.ifaceStore.AddInterface(containerConfig)
	// Notify the Pod update event to required components.
	pc.entityUpdates <- types.EntityReference{
		Pod: &v1beta2.PodReference{Name: containerConfig.PodName, Namespace: containerConfig.PodNamespace},
	}
	return nil
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
	containerAccess *containerAccessArbitrator,
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
		containerIface, containerIPs, containerAccess)
	return err
}

// disconnectInterceptedInterface disconnects intercepted interface from ovs br-int.
func (pc *podConfigurator) disconnectInterceptedInterface(podName, podNamespace, containerID string) error {
	containerConfig, found := pc.ifaceStore.GetContainerInterface(containerID)
	if !found {
		klog.V(2).Infof("Did not find the port for container %s in local cache", containerID)
		return nil
	}
	for _, ip := range containerConfig.IPs {
		ipNet := util.NewIPNet(ip)
		if err := pc.routeClient.UnMigrateRoutesFromGw(ipNet, ""); err != nil {
			return fmt.Errorf("connectInterceptedInterface failed to migrate: %w", err)
		}
	}
	return pc.disconnectInterfaceFromOVS(containerConfig)
	// TODO recover pre-connect state? repatch vethpair to original bridge etc ?? to make first CNI happy??
}

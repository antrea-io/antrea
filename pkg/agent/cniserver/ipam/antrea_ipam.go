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

package ipam

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/poolallocator"
)

const (
	AntreaIPAMType = "antrea"
)

// Antrea IPAM driver would allocate IP addresses according to object IPAM annotation,
// if present. If annotation is not present, the driver will delegate functionality
// to traditional IPAM driver.
type AntreaIPAM struct {
	controller      *AntreaIPAMController
	controllerMutex sync.RWMutex
}

// Global variable is needed to work around order of initialization
// Controller will be assigned to the driver after it is initialized
// by agent init.
var antreaIPAMDriver *AntreaIPAM

type mineType uint8

const (
	mineUnknown mineType = iota
	mineFalse
	mineTrue
)

// Resource needs to be unique since it is used as identifier in Del.
// Therefore Container ID is used, while Pod/Namespace are shown for visibility.
func getAllocationPodOwner(args *invoke.Args, k8sArgs *types.K8sArgs, reservedOwner *crdv1a2.IPAddressOwner, secondary bool) *crdv1a2.PodOwner {
	podOwner := crdv1a2.PodOwner{
		Name:        string(k8sArgs.K8S_POD_NAME),
		Namespace:   string(k8sArgs.K8S_POD_NAMESPACE),
		ContainerID: args.ContainerID,
	}
	if secondary {
		// Add interface name for secondary network to uniquely identify
		// the secondary network interface.
		podOwner.IFName = args.IfName
	}
	return &podOwner
}

func getAllocationOwner(args *invoke.Args, k8sArgs *types.K8sArgs, reservedOwner *crdv1a2.IPAddressOwner, secondary bool) *crdv1a2.IPAddressOwner {
	podOwner := getAllocationPodOwner(args, k8sArgs, nil, secondary)
	if reservedOwner != nil {
		owner := *reservedOwner
		owner.Pod = podOwner
		return &owner
	}
	return &crdv1a2.IPAddressOwner{Pod: podOwner}
}

// Helper to generate IP config and default route, taking IP version into account
func generateIPConfig(ip net.IP, prefixLength int, gwIP net.IP) (*current.IPConfig, *cnitypes.Route) {
	ipAddrBits := 32
	dstNet := net.IPNet{
		IP:   net.ParseIP("0.0.0.0"),
		Mask: net.CIDRMask(0, ipAddrBits),
	}

	if ip.To4() == nil {
		ipAddrBits = 128

		dstNet = net.IPNet{
			IP:   net.ParseIP("::0"),
			Mask: net.CIDRMask(0, ipAddrBits),
		}
	}

	defaultRoute := cnitypes.Route{
		Dst: dstNet,
		GW:  gwIP,
	}
	ipConfig := current.IPConfig{
		Address: net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefixLength), ipAddrBits)},
		Gateway: gwIP,
	}

	return &ipConfig, &defaultRoute
}

func parseStaticAddresses(ipamConfig *types.IPAMConfig) error {
	for i := range ipamConfig.Addresses {
		ip, addr, err := net.ParseCIDR(ipamConfig.Addresses[i].Address)
		if err != nil {
			return fmt.Errorf("invalid address %s", ipamConfig.Addresses[i].Address)
		}
		ipamConfig.Addresses[i].IPNet = *addr
		ipamConfig.Addresses[i].IPNet.IP = ip
		if ip.To4() != nil {
			ipamConfig.Addresses[i].Version = "4"
		} else {
			ipamConfig.Addresses[i].Version = "6"
		}
	}
	return nil
}

func (d *AntreaIPAM) setController(controller *AntreaIPAMController) {
	d.controllerMutex.Lock()
	defer d.controllerMutex.Unlock()
	d.controller = controller
}

// Add allocates the next available IP address from the associated IP Pool. The
// allocated IP and associated resource will be stored in the IP Pool status.
func (d *AntreaIPAM) Add(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, *IPAMResult, error) {
	mine, allocator, ips, reservedOwner, err := d.owns(k8sArgs)
	if err != nil {
		return true, nil, err
	}
	if mine == mineFalse {
		// pass this request to next driver
		return false, nil, nil
	}

	owner := *getAllocationOwner(args, k8sArgs, reservedOwner, false)
	var ip net.IP
	var subnetInfo *crdv1a2.SubnetInfo
	if reservedOwner != nil {
		ip, subnetInfo, err = allocator.AllocateReservedOrNext(crdv1a2.IPAddressPhaseAllocated, owner)
	} else if len(ips) == 0 {
		ip, subnetInfo, err = allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, owner)
	} else {
		ip = ips[0]
		subnetInfo, err = allocator.AllocateIP(ip, crdv1a2.IPAddressPhaseAllocated, owner)
	}
	if err != nil {
		return true, nil, err
	}

	klog.V(4).InfoS("IP allocation successful", "IP", ip.String(), "Pod", string(k8sArgs.K8S_POD_NAME))

	result := IPAMResult{Result: current.Result{CNIVersion: current.ImplementedSpecVersion}, VLANID: subnetInfo.VLAN}
	gwIP := net.ParseIP(subnetInfo.Gateway)

	ipConfig, defaultRoute := generateIPConfig(ip, int(subnetInfo.PrefixLength), gwIP)

	result.Routes = append(result.Routes, defaultRoute)
	result.IPs = append(result.IPs, ipConfig)
	return true, &result, nil
}

// Del releases the IP associated with the resource from the IP Pool status.
func (d *AntreaIPAM) Del(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, error) {
	podOwner := getAllocationPodOwner(args, k8sArgs, nil, false)
	foundAllocation, err := d.del(podOwner)
	if err != nil {
		// Let the invoker retry at error.
		return true, err
	}

	// If no allocation found, pass CNI DEL to the next driver.
	return foundAllocation, nil
}

// Check verifies the IP associated with the resource is tracked in the IP Pool status.
func (d *AntreaIPAM) Check(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig []byte) (bool, error) {
	mine, allocator, _, _, err := d.owns(k8sArgs)
	if err != nil {
		return true, err
	}
	if mine == mineFalse {
		// pass this request to next driver
		return false, nil
	}

	ip, err := allocator.GetContainerIP(args.ContainerID, "")
	if err != nil {
		return true, err
	}

	if ip == nil {
		return true, fmt.Errorf("no IP Address association found for container %s", string(k8sArgs.K8S_POD_NAME))
	}
	return true, nil
}

// SecondaryNetworkAllocate allocates IP addresses for a Pod secondary network interface, based on
// the IPAM configuration of the passed CNI network configuration.
// It supports IPAM for both Antrea-managed secondary networks and Multus-managed secondary
// networks.
func (d *AntreaIPAM) SecondaryNetworkAllocate(podOwner *crdv1a2.PodOwner, networkConfig *types.NetworkConfig) (*IPAMResult, error) {
	ipamConf := networkConfig.IPAM
	numPools := len(ipamConf.IPPools)

	if err := parseStaticAddresses(ipamConf); err != nil {
		return nil, fmt.Errorf("failed to parse static addresses in the IPAM config: %v", err)
	}
	if numPools == 0 && len(ipamConf.Addresses) == 0 {
		return nil, fmt.Errorf("at least one Antrea IPPool or static address must be specified")
	}

	result := IPAMResult{}
	if numPools > 0 {
		if err := d.waitForControllerReady(); err != nil {
			// Return error to let the invoker retry.
			return nil, err
		}

		var allocatorsToRelease []*poolallocator.IPPoolAllocator
		defer func() {
			for _, allocator := range allocatorsToRelease {
				// Try to release the allocated IPs after an error.
				allocator.ReleaseContainer(podOwner.ContainerID, podOwner.IFName)
			}
		}()

		for _, p := range ipamConf.IPPools {
			allocator, err := d.controller.getPoolAllocatorByName(p)
			if err != nil {
				return nil, err
			}

			var ip net.IP
			var subnetInfo *crdv1a2.SubnetInfo
			owner := crdv1a2.IPAddressOwner{Pod: podOwner}
			ip, subnetInfo, err = allocator.AllocateNext(crdv1a2.IPAddressPhaseAllocated, owner)
			if err != nil {
				return nil, err
			}
			if numPools > 1 {
				allocatorsToRelease = append(allocatorsToRelease, allocator)
			}

			gwIP := net.ParseIP(subnetInfo.Gateway)
			ipConfig, _ := generateIPConfig(ip, int(subnetInfo.PrefixLength), gwIP)
			// CNI spec 0.2.0 and below support only one v4 and one v6 address. But we
			// assume the CNI version >= 0.3.0, and so do not check the number of
			// addresses.
			result.IPs = append(result.IPs, ipConfig)
			if result.VLANID == 0 {
				// Return the first non-zero VLAN.
				result.VLANID = subnetInfo.VLAN
			}
		}
		// No failed allocation, so do not release allocated IPs.
		allocatorsToRelease = nil
	}

	// Add static addresses.
	for _, a := range ipamConf.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Address: a.IPNet,
			Gateway: a.Gateway})
	}

	// Copy routes and DNS from the input IPAM configuration.
	result.Routes = ipamConf.Routes
	result.DNS = ipamConf.DNS
	return &result, nil
}

// SecondaryNetworkRelease releases the IP addresses allocated for a Pod secondary network interface.
func (d *AntreaIPAM) SecondaryNetworkRelease(owner *crdv1a2.PodOwner) error {
	_, err := d.del(owner)
	return err
}

func (d *AntreaIPAM) secondaryNetworkAdd(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) (*IPAMResult, error) {
	return d.SecondaryNetworkAllocate(getAllocationPodOwner(args, k8sArgs, nil, true), networkConfig)
}

func (d *AntreaIPAM) secondaryNetworkDel(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
	return d.SecondaryNetworkRelease(getAllocationPodOwner(args, k8sArgs, nil, true))
}

func (d *AntreaIPAM) secondaryNetworkCheck(args *invoke.Args, k8sArgs *types.K8sArgs, networkConfig *types.NetworkConfig) error {
	return fmt.Errorf("CNI CHECK is not implemented for secondary network")
}

func (d *AntreaIPAM) del(podOwner *crdv1a2.PodOwner) (foundAllocation bool, err error) {
	if err := d.waitForControllerReady(); err != nil {
		// Return error to let the invoker retry.
		return false, err
	}
	// The Pod resource might have been removed; and for a secondary we
	// would rely on the passed IPPool for CNI DEL. So, search IPPools with
	// the matched PodOwner.
	allocators, err := d.controller.getPoolAllocatorsByOwner(podOwner)
	if err != nil {
		return false, err
	}

	if len(allocators) == 0 {
		return false, nil
	}
	// Multiple allocators can be returned if the network interface has IPs
	// allocated from more than one IPPools.
	for _, a := range allocators {
		err = a.ReleaseContainer(podOwner.ContainerID, podOwner.IFName)
		if err != nil {
			return true, err
		}
	}
	return true, nil
}

// owns checks whether this driver owns the coming IPAM request. This decision is based on Antrea
// IPAM annotation for the resource (Pod or Namespace). If an annotation is not present, or the
// annotated IP Pool not found, the driver should not own the request and will fall back to the next
// IPAM driver.
// return:
// mineUnknown + PodNotFound error
// mineUnknown + InvalidIPAnnotation error
// mineFalse + nil error
// mineTrue + timeout error
// mineTrue + IPPoolNotFound error
// mineTrue + nil error
func (d *AntreaIPAM) owns(k8sArgs *types.K8sArgs) (mineType, *poolallocator.IPPoolAllocator, []net.IP, *crdv1a2.IPAddressOwner, error) {
	// Wait controller ready to avoid inappropriate behaviors on the CNI request.
	if err := d.waitForControllerReady(); err != nil {
		// Return mineTrue to make this request fail and kubelet will retry.
		return mineTrue, nil, nil, nil, err
	}

	namespace := string(k8sArgs.K8S_POD_NAMESPACE)
	podName := string(k8sArgs.K8S_POD_NAME)
	klog.V(2).InfoS("Inspecting IPAM annotation", "Namespace", namespace, "Pod", podName)
	return d.controller.getPoolAllocatorByPod(namespace, podName)
}

func (d *AntreaIPAM) waitForControllerReady() error {
	err := wait.PollUntilContextTimeout(context.TODO(), 500*time.Millisecond, 5*time.Second, true, func(ctx context.Context) (bool, error) {
		d.controllerMutex.RLock()
		defer d.controllerMutex.RUnlock()
		if d.controller == nil {
			klog.Warningf("Antrea IPAM driver is not ready.")
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		return fmt.Errorf("Antrea IPAM driver not ready: %v", err)
	}
	return nil
}

func init() {
	// Antrea driver must come first.
	// NOTE: this is global variable that requires follow-up setup post agent initialization.
	antreaIPAMDriver = &AntreaIPAM{}
	RegisterIPAMDriver(AntreaIPAMType, antreaIPAMDriver)

	// Host local plugin is fallback driver
	RegisterIPAMDriver(AntreaIPAMType, &IPAMDelegator{pluginType: ipamHostLocal})
}

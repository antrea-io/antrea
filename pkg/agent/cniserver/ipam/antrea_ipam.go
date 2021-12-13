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
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/invoke"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/poolallocator"
)

const (
	AntreaIPAMType = "antrea-ipam"
)

// Antrea IPAM driver would allocate IP addresses according to object IPAM annotation,
// if present. If annotation is not present, the driver will delegate functionality
// to traditional IPAM driver.
type AntreaIPAM struct {
	controller *AntreaIPAMController
}

// Global variable is needed to work around order of initialization
// Controller will be assigned to the driver after it is initialized
// by agent init.
var antreaIPAMDriver *AntreaIPAM

// Resource needs to be unique since it is used as identifier in Del.
// Therefore Container ID is used, while Pod/Namespace are shown for visibility.
// TODO: Consider multi-interface case
func getAllocationOwner(args *invoke.Args, k8sArgs *argtypes.K8sArgs, preallocateOwner *crdv1a2.IPAddressOwner) crdv1a2.IPAddressOwner {
	podOwner := &crdv1a2.PodOwner{
		Name:        string(k8sArgs.K8S_POD_NAME),
		Namespace:   string(k8sArgs.K8S_POD_NAMESPACE),
		ContainerID: args.ContainerID,
	}
	if preallocateOwner != nil {
		owner := *preallocateOwner.DeepCopy()
		owner.Pod = podOwner
		return owner
	}
	return crdv1a2.IPAddressOwner{
		Pod: podOwner,
	}
}

// Helper to generate IP config and default route, taking IP version into account
func generateIPConfig(ip net.IP, prefixLength int, gwIP net.IP) (*current.IPConfig, *cnitypes.Route) {
	ipVersion := "4"
	ipAddrBits := 32
	dstNet := net.IPNet{
		IP:   net.ParseIP("0.0.0.0"),
		Mask: net.CIDRMask(0, ipAddrBits),
	}

	if ip.To4() == nil {
		ipVersion = "6"
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
		Version: ipVersion,
		Address: net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefixLength), ipAddrBits)},
		Gateway: gwIP,
	}

	return &ipConfig, &defaultRoute
}

func (d *AntreaIPAM) setController(controller *AntreaIPAMController) {
	d.controller = controller
}

// Add allocates next available IP address from associated IP Pool
// Allocated IP and associated resource are stored in IP Pool status
func (d *AntreaIPAM) Add(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, *current.Result, error) {
	mine, allocator, ips, preallocateOwner, err := d.owns(k8sArgs)
	if err != nil {
		return mine, nil, err
	}
	if !mine {
		// pass this request to next driver
		return false, nil, nil
	}

	owner := getAllocationOwner(args, k8sArgs, preallocateOwner)
	var ip net.IP
	var subnetInfo crdv1a2.SubnetInfo
	if preallocateOwner != nil {
		ip, subnetInfo, err = allocator.AllocatePreallocated(crdv1a2.IPAddressPhaseAllocated, owner)
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

	result := current.Result{CNIVersion: current.ImplementedSpecVersion}
	gwIP := net.ParseIP(subnetInfo.Gateway)

	ipConfig, defaultRoute := generateIPConfig(ip, int(subnetInfo.PrefixLength), gwIP)

	result.Routes = append(result.Routes, defaultRoute)
	result.IPs = append(result.IPs, ipConfig)
	return true, &result, nil
}

// Del deletes IP associated with resource from IP Pool status
func (d *AntreaIPAM) Del(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error) {
	swallowNotFoundError := func(err error) error {
		if errors.IsNotFound(err) {
			// The specified IP Pool does not exist, swallow the error
			// because it is not recoverable
			klog.Warningf("Antrea IPAM Del failed: %+v", err)
			return nil
		}

		return err
	}

	mine, allocator, _, _, err := d.owns(k8sArgs)
	if !mine {
		// pass this request to next driver
		return false, nil
	}
	if err != nil {
		return true, swallowNotFoundError(err)
	}

	owner := getAllocationOwner(args, k8sArgs, nil)
	err = allocator.ReleaseContainerIfPresent(owner.Pod.ContainerID)
	return true, swallowNotFoundError(err)
}

// Check verifues IP associated with resource is tracked in IP Pool status
func (d *AntreaIPAM) Check(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, error) {
	mine, allocator, _, _, err := d.owns(k8sArgs)
	if err != nil {
		return mine, err
	}
	if !mine {
		// pass this request to next driver
		return false, nil
	}

	owner := getAllocationOwner(args, k8sArgs, nil)
	found, err := allocator.HasContainer(owner.Pod.ContainerID)
	if err != nil {
		return true, err
	}

	if !found {
		return true, fmt.Errorf("no IP Address association found for container %s", string(k8sArgs.K8S_POD_NAME))
	}

	return true, nil
}

// owns checks whether this driver owns coming IPAM request. This decision is based on
// Antrea IPAM annotation for the resource (only Namespace annotation is supported as
// of today). If annotation is not present, or annotated IP Pool not found, the driver
// will not own the request and fall back to next IPAM driver.
func (d *AntreaIPAM) owns(k8sArgs *argtypes.K8sArgs) (bool, *poolallocator.IPPoolAllocator, []net.IP, *crdv1a2.IPAddressOwner, error) {
	if d.controller == nil {
		klog.Warningf("Antrea IPAM driver failed to initialize due to inconsistent configuration. Falling back to default IPAM")
		return false, nil, nil, nil, nil
	}

	// As of today, only Namespace annotation is supported
	// In future, Deployment, Statefulset and Pod annotations will be
	// supported as well
	namespace := string(k8sArgs.K8S_POD_NAMESPACE)
	podName := string(k8sArgs.K8S_POD_NAME)
	klog.V(2).InfoS("Inspecting IPAM annotation", "Namespace", namespace, "Pod", podName)
	allocator, ips, preallocatedOwner, err := d.controller.getPoolAllocatorByPod(namespace, podName)
	if err != nil {
		// Failed to find pool - error should be returned from this driver
		return true, nil, nil, nil, err
	}
	if allocator == nil {
		// No pool annotation for this namespace
		return false, nil, nil, nil, nil
	}
	return true, allocator, ips, preallocatedOwner, nil
}

func init() {
	// Antrea driver must come first
	// NOTE: this is global variable that requires follow-up setup post agent Init
	antreaIPAMDriver = &AntreaIPAM{}

	if err := RegisterIPAMDriver(AntreaIPAMType, antreaIPAMDriver); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", AntreaIPAMType)
	}

	// Host local plugin is fallback driver
	if err := RegisterIPAMDriver(AntreaIPAMType, &IPAMDelegator{pluginType: ipamHostLocal}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", ipamHostLocal)
	}
}

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
	"k8s.io/klog/v2"

	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"
	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/poolallocator"
	"antrea.io/antrea/pkg/util/k8s"
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

type antreaIPAMRequest struct {
	// TODO: Support two allocators for IPv4 and IPv6 pools
	// TODO: Consider multiple interface case
	allocator   *poolallocator.IPPoolAllocator
	namespace   string
	podName     string
	containerID string
}

// Resource needs to be unique since it is used as identifier in Del.
// Therefore Container ID is used, while Pod/Namespace are shown for visibility.
func (d *antreaIPAMRequest) getResource() string {
	return fmt.Sprintf("Container:%s Pod:%s", d.containerID, k8s.NamespacedName(d.namespace, d.podName))
}

func (d *AntreaIPAM) newAntreaIPAMRequest(poolName string, namespace string, podName string, containerID string) (antreaIPAMRequest, error) {
	allocator, err := poolallocator.NewIPPoolAllocator(poolName, d.controller.crdClient)
	if err != nil {
		return antreaIPAMRequest{}, err
	}

	klog.V(2).Infof("Pod %s in namespace %s associated with IP Pool %s", podName, namespace, poolName)
	return antreaIPAMRequest{
		allocator:   allocator,
		namespace:   namespace,
		podName:     podName,
		containerID: containerID,
	}, nil
}

func (d *AntreaIPAM) setController(controller *AntreaIPAMController) {
	d.controller = controller
}

func (d *AntreaIPAM) validateRequest(data interface{}) (*antreaIPAMRequest, error) {
	request, ok := data.(antreaIPAMRequest)
	if !ok {
		// Should never happen since we expect Owns to return
		// data consistent with current driver
		panic(fmt.Errorf("unexpected data type received in Antrea IPAM driver"))
	}

	if request.allocator == nil {
		return nil, fmt.Errorf("failed to initialize pool allocator")
	}

	return &request, nil
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

// Add allocates next available IP address from associated IP Pool
// Allocated IP and associated resource are stored in IP Pool status
func (d *AntreaIPAM) Add(args *invoke.Args, networkConfig []byte, data interface{}) (*current.Result, error) {

	request, err := d.validateRequest(data)
	if err != nil {
		// Should never happen
		return nil, err
	}

	ip, subnetInfo, err := request.allocator.AllocateNext(crdv1a2.IPPoolUsageStateAllocated, request.getResource())
	if err != nil {
		return nil, err
	}

	klog.V(4).Infof("IP %s (GW %s) allocated for pod %s", ip.String(), subnetInfo.Gateway, request.podName)

	result := current.Result{CNIVersion: current.ImplementedSpecVersion}
	gwIP := net.ParseIP(subnetInfo.Gateway)

	ipConfig, defaultRoute := generateIPConfig(ip, int(subnetInfo.PrefixLength), gwIP)

	result.Routes = append(result.Routes, defaultRoute)
	result.IPs = append(result.IPs, ipConfig)
	return &result, nil
}

// Del deletes IP associated with resource from IP Pool status
func (d *AntreaIPAM) Del(args *invoke.Args, networkConfig []byte, data interface{}) error {

	request, err := d.validateRequest(data)
	if err != nil {
		return err
	}

	err = request.allocator.ReleaseResource(request.getResource())
	if err != nil {
		// Don't fail Del due to state inconsistency, otherwise agent will retry
		klog.Warningf("Antrea IPAM Del failed: %v", err)
	}

	return nil
}

// Check verifues IP associated with resource is tracked in IP Pool status
func (d *AntreaIPAM) Check(args *invoke.Args, networkConfig []byte, data interface{}) error {

	request, err := d.validateRequest(data)
	if err != nil {
		return err
	}
	found, err := request.allocator.HasResource(request.getResource())
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("no IP Address is associated with pod %s", request.podName)
	}

	return nil
}

// Owns checks whether this driver owns coming IPAM request. This decision is based on
// Antrea IPAM annotation for the resource (only Namespace annotation is supported as
// of today). If annotation is not present, or annotated IP Pool not found, the driver
// will not own the request and fall back to next IPAM driver.
func (d *AntreaIPAM) Owns(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, interface{}, error) {
	if d.controller == nil {
		klog.Warningf("Antrea IPAM driver failed to initialize due to inconsistent configuration. Falling back to default IPAM")
		return false, nil, nil
	}

	// As of today, only Namespace annotation is supported
	// In future, Deployment, Statefulset and Pod annotations will be
	// supported as well
	namespace := string(k8sArgs.K8S_POD_NAMESPACE)
	klog.V(2).Infof("Inspecting IPAM annotation for namespace %s", namespace)
	poolNames, shouldOwn := d.controller.getIPPoolsByNamespace(namespace)
	if shouldOwn {
		// Only one pool is supported as of today
		// TODO - support a pool for each IP version
		ipPool := poolNames[0]
		request, err := d.newAntreaIPAMRequest(ipPool, namespace, string(k8sArgs.K8S_POD_NAME), args.ContainerID)
		if err != nil {
			return true, nil, fmt.Errorf("Antrea IPAM driver failed to initialize IP allocator for pool %s", ipPool)
		}
		return true, request, nil
	}
	return false, nil, nil
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

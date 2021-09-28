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
// to traditional IPAM driver specified in pluginType
type AntreaIPAM struct {
}

func generateCIDRMask(ip net.IP, prefixLength int) net.IPMask {
	ipAddrBits := 32
	if ip.To4() == nil {
		ipAddrBits = 128
	}

	return net.CIDRMask(int(prefixLength), ipAddrBits)
}

type antreaIPAMRequest struct {
	// TODO: Support two allocators for IPv4 and IPv6 pools
	allocator *poolallocator.IPPoolAllocator
	namespace string
	podName   string
}

func (d *antreaIPAMRequest) getResource() string {
	return fmt.Sprintf("Kind:%s", k8s.NamespacedName(d.namespace, d.podName))
}

func NewantreaIPAMRequest(poolName string, namespace string, podName string) (antreaIPAMRequest, error) {
	allocator, err := poolallocator.NewIPPoolAllocator(poolName, antreaIPAMController.crdClient)
	if err != nil {
		return antreaIPAMRequest{}, err
	}

	klog.V(2).Infof("Pod %s in namespace %s associated with IP Pool %s", podName, namespace, poolName)
	return antreaIPAMRequest{
		allocator: allocator,
		namespace: namespace,
		podName:   podName,
	}, nil
}

func (d *AntreaIPAM) validateRequest(data interface{}) (*antreaIPAMRequest, error) {
	request, ok := data.(antreaIPAMRequest)
	if !ok {
		// Should never happen since we expect Owns to return
		// data consistent with current driver
		panic(fmt.Errorf("Unexpected data type received in Antrea IPAM driver"))
	}

	if request.allocator == nil {
		return nil, fmt.Errorf("Failed to initialize pool allocator")
	}

	return &request, nil
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
	ipConfig := &current.IPConfig{
		Address: net.IPNet{IP: ip, Mask: generateCIDRMask(ip, int(subnetInfo.PrefixLength))},
		Gateway: net.ParseIP(subnetInfo.Gateway),
	}
	result.IPs = append(result.IPs, ipConfig)
	return &result, nil
}

// Del deletes IP associated with resource from IP Pool status
func (d *AntreaIPAM) Del(args *invoke.Args, networkConfig []byte, data interface{}) error {

	request, err := d.validateRequest(data)
	if err != nil {
		return err
	}

	return request.allocator.ReleaseResource(request.getResource())
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
		return fmt.Errorf("No IP Address is associated with pod %s", request.podName)
	}

	return nil
}

// Owns checks whether this driver owns coming IPAM request. This decision is based on
// Antrea IPAM annotation for the resource (only Namespace annotation is supported as
// of today). If annotation is not present, or annotated IP Pool not found, the driver
// will not own the request and fall back to next IPAM driver.
func (d *AntreaIPAM) Owns(args *invoke.Args, k8sArgs *argtypes.K8sArgs, networkConfig []byte) (bool, interface{}, error) {
	if antreaIPAMController == nil {
		klog.Warningf("Antrea IPAM driver failed to initialize due to inconsistent configuration. Falling back to default IPAM")
		return false, nil, nil
	}

	// As of today, only Namespace annotation is supported
	// In future, Deployment, Statefulset and Pod annotations will be
	// supported as well
	namespace := string(k8sArgs.K8S_POD_NAMESPACE)
	klog.V(2).Infof("Inspecting IPAM annotation for namespace %s", namespace)
	poolNames, shouldOwn := antreaIPAMController.getIPPoolsByNamespace(namespace)
	if shouldOwn {
		// Only one pool is supported as of today
		// TODO - support a pool for each IP version
		ipPool := poolNames[0]
		request, err := NewantreaIPAMRequest(ipPool, namespace, string(k8sArgs.K8S_POD_NAME))
		if err != nil {
			return true, nil, fmt.Errorf("Antrea IPAM driver failed to initialize IP allocator for pool %s", ipPool)
		}
		return true, request, nil
	}
	return false, nil, nil
}

func init() {
	// Antrea driver must come first
	if err := RegisterIPAMDriver(AntreaIPAMType, &AntreaIPAM{}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", AntreaIPAMType)
	}

	// Host local plugin is fallback driver
	if err := RegisterIPAMDriver(AntreaIPAMType, &IPAMDelegator{pluginType: ipamHostLocal}); err != nil {
		klog.Errorf("Failed to register IPAM plugin on type %s", ipamHostLocal)
	}
}

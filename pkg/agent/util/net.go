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

package util

import (
	"crypto/rand"
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/util/ip"
)

const (
	interfaceNameLength   = 15
	interfacePrefixLength = 8
	interfaceKeyLength    = interfaceNameLength - (interfacePrefixLength + 1)

	FamilyIPv4 uint8 = 4
	FamilyIPv6 uint8 = 6

	bridgedUplinkSuffix = "~"
)

var (
	// Declared variables which are meant to be overridden for testing.
	netInterfaceByName  = net.InterfaceByName
	netInterfaceByIndex = net.InterfaceByIndex
	netInterfaces       = net.Interfaces
	netInterfaceAddrs   = (*net.Interface).Addrs
)

func generateInterfaceName(key string, name string, useHead bool) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	io.WriteString(hash, key)
	interfaceKey := hex.EncodeToString(hash.Sum(nil))
	prefix := name
	if len(name) > interfacePrefixLength {
		// We use Node/Pod name to generate the interface name,
		// valid chars for Node/Pod name are ASCII letters from a to z,
		// the digits from 0 to 9, and the hyphen (-).
		// Hyphen (-) is the only char which will impact command-line interpretation
		// if the interface name starts with one, so we remove it here.
		if useHead {
			prefix = strings.TrimLeft(name[:interfacePrefixLength], "-")
		} else {
			prefix = strings.TrimLeft(name[len(name)-interfacePrefixLength:], "-")
		}
	}
	return fmt.Sprintf("%s-%s", prefix, interfaceKey[:interfaceKeyLength])
}

// GenerateContainerInterfaceKey generates a unique string for a Pod's
// interface as: "c/<Container-ID>/<IFDev-Name>".
// We must use ContainerID instead of PodNamespace + PodName because there could
// be more than one container associated with the same Pod at some point.
// For example, when deleting a StatefulSet Pod with 0 second grace period, the
// Pod will be removed from the Kubernetes API very quickly and a new Pod will
// be created immediately, and kubelet may process the deletion of the previous
// Pod and the addition of the new Pod simultaneously.
func GenerateContainerInterfaceKey(containerID, ifDev string) string {
	return fmt.Sprintf("c/%s/%s", containerID, ifDev)
}

// GenerateNodeTunnelInterfaceKey generates a unique string for a Node's
// tunnel interface as: node/<Node-name>.
func GenerateNodeTunnelInterfaceKey(nodeName string) string {
	return fmt.Sprintf("node/%s", nodeName)
}

// GenerateContainerInterfaceName generates a unique interface name using the
// Pod's Namespace, name and container ID. The output should be deterministic
// (so that multiple calls to GenerateContainerInterfaceName with the same
// parameters return the same value). The output has the length of
// interfaceNameLength(15).
// The probability of collision should be neglectable.
func GenerateContainerInterfaceName(podName, podNamespace, containerID string) string {
	// Use the podName as the prefix and the containerID as the hashing key.
	// podNamespace is not used currently.
	return generateInterfaceName(containerID, podName, true)
}

// GenerateContainerHostVethName generates a unique interface name using the
// Pod's Name, container ID, and the container veth interface name. The output
// should be deterministic.
func GenerateContainerHostVethName(podName, podNamespace, containerID, containerVeth string) string {
	var key string
	if containerVeth == "eth0" {
		key = containerID
	} else {
		// Secondary interface.
		key = containerID + containerVeth
	}
	return generateInterfaceName(key, podName, true)
}

// GenerateNodeTunnelInterfaceName generates a unique interface name for the
// tunnel to the Node, using the Node's name.
func GenerateNodeTunnelInterfaceName(nodeName string) string {
	return generateInterfaceName(GenerateNodeTunnelInterfaceKey(nodeName), nodeName, false)
}

type LinkNotFound struct {
	error
}

func newLinkNotFoundError(name string) LinkNotFound {
	return LinkNotFound{
		fmt.Errorf("link %s not found", name),
	}
}

func listenUnix(address string) (net.Listener, error) {
	return net.Listen("unix", address)
}

// GetIPNetDeviceFromIP returns local IPs/masks and associated device from IP, and ignores the interfaces which have
// names in the ignoredInterfaces.
func GetIPNetDeviceFromIP(localIPs *ip.DualStackIPs, ignoredInterfaces sets.Set[string]) (v4IPNet *net.IPNet, v6IPNet *net.IPNet, iface *net.Interface, err error) {
	linkList, err := netInterfaces()
	if err != nil {
		return nil, nil, nil, err
	}

	// localIPs includes at most one IPv4 address and one IPv6 address. For each device in linkList, all its addresses
	// are compared with IPs in localIPs. If found, the iface is set to the device and v4IPNet, v6IPNet are set to
	// the matching addresses.
	saveIface := func(current *net.Interface) error {
		if iface != nil && iface.Index != current.Index {
			return fmt.Errorf("IPs of localIPs should be on the same device")
		}
		iface = current
		return nil
	}
	for i := range linkList {
		link := linkList[i]
		if ignoredInterfaces.Has(link.Name) {
			continue
		}
		addrList, err := netInterfaceAddrs(&link)
		if err != nil {
			continue
		}
		for _, addr := range addrList {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIPs.IPv4) {
					if err := saveIface(&link); err != nil {
						return nil, nil, nil, err
					}
					v4IPNet = ipNet
				} else if ipNet.IP.Equal(localIPs.IPv6) {
					if err := saveIface(&link); err != nil {
						return nil, nil, nil, err
					}
					v6IPNet = ipNet
				}
			}
		}
	}
	if iface == nil {
		return nil, nil, nil, fmt.Errorf("unable to find local IPs and device")
	}
	return v4IPNet, v6IPNet, iface, nil
}

func GetIPNetDeviceByName(ifaceName string) (v4IPNet *net.IPNet, v6IPNet *net.IPNet, link *net.Interface, err error) {
	link, err = netInterfaceByName(ifaceName)
	if err != nil {
		return nil, nil, nil, err
	}
	addrList, err := netInterfaceAddrs(link)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, addr := range addrList {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.IsGlobalUnicast() {
				if ipNet.IP.To4() != nil {
					if v4IPNet == nil {
						v4IPNet = ipNet
					}
				} else if v6IPNet == nil {
					v6IPNet = ipNet
				}
			}
		}
	}
	if v4IPNet != nil || v6IPNet != nil {
		return v4IPNet, v6IPNet, link, nil
	}
	return nil, nil, nil, fmt.Errorf("unable to find local IP and device")
}

func GetIPNetDeviceByCIDRs(cidrsList []string) (v4IPNet, v6IPNet *net.IPNet, link *net.Interface, err error) {
	cidrs, err := utilnet.ParseCIDRs(cidrsList)
	if err != nil {
		return nil, nil, nil, err
	}

	dualStack, err := utilnet.IsDualStackCIDRs(cidrs)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(cidrs) > 1 && !dualStack {
		return nil, nil, nil, fmt.Errorf("len of cidrs is %v and they are not configured as dual stack (at least one from each IPFamily)", len(cidrs))
	}

	if len(cidrs) > 2 {
		return nil, nil, nil, fmt.Errorf("length of cidrs is %v more than max allowed of 2", len(cidrs))
	}

	ifaces, err := netInterfaces()
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range ifaces {
		addresses, err := netInterfaceAddrs(&ifaces[i])
		if err != nil {
			return nil, nil, nil, err
		}
		for _, addr := range addresses {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || !ipNet.IP.IsGlobalUnicast() {
				continue
			}
			for _, cidr := range cidrs {
				if !cidr.Contains(ipNet.IP) {
					continue
				}
				if v4IPNet == nil && ipNet.IP.To4() != nil {
					v4IPNet = ipNet
				} else if v6IPNet == nil && ipNet.IP.To4() == nil {
					v6IPNet = ipNet
				}
			}
		}
		if v4IPNet != nil || v6IPNet != nil {
			return v4IPNet, v6IPNet, &ifaces[i], nil
		}
	}
	return nil, nil, nil, fmt.Errorf("unable to find local IP and device")
}

func GetAllIPNetsByName(ifaceName string) ([]*net.IPNet, error) {
	ips := []*net.IPNet{}
	adapter, err := netInterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, _ := netInterfaceAddrs(adapter)
	for _, addr := range addrs {
		if ip, ipNet, err := net.ParseCIDR(addr.String()); err != nil {
			klog.Warningf("Unable to parse addr %+v, err=%+v", addr, err)
		} else if !ip.IsLinkLocalUnicast() {
			ipNet.IP = ip
			ips = append(ips, ipNet)
		}
	}
	klog.InfoS("Found IPs on interface", "IPs", ips, "interface", ifaceName)
	return ips, nil
}

func GetIPv4Addr(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return nil
}

func GetIPWithFamily(ips []net.IP, addrFamily uint8) (net.IP, error) {
	if addrFamily == FamilyIPv6 {
		for _, ip := range ips {
			if ip.To4() == nil {
				return ip, nil
			}
		}
		return nil, errors.New("no IP found with IPv6 AddressFamily")
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip, nil
		}
	}
	return nil, errors.New("no IP found with IPv4 AddressFamily")
}

// ExtendCIDRWithIP is used for extending an IPNet with an IP.
func ExtendCIDRWithIP(ipNet *net.IPNet, ip net.IP) (*net.IPNet, error) {
	if ipNet == nil {
		return NewIPNet(ip), nil
	}
	cpl := longestCommonPrefixLen(ipNet.IP, ip)
	if cpl == 0 {
		return nil, fmt.Errorf("invalid common prefix length")
	}
	_, newIPNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipNet.IP.String(), cpl))
	if err != nil {
		return nil, err
	}
	return newIPNet, nil
}

// This is copied from func commonPrefixLen in net/addrselect.go and modified:
// - Replace argument type IP with argument type net.IP.
// - Remove the prefix limit (64 bits) for IPv6.
func longestCommonPrefixLen(a, b net.IP) (cpl int) {
	if a4 := a.To4(); a4 != nil {
		a = a4
	}
	if b4 := b.To4(); b4 != nil {
		b = b4
	}
	if len(a) != len(b) {
		return 0
	}
	for len(a) > 0 {
		if a[0] == b[0] {
			cpl += 8
			a = a[1:]
			b = b[1:]
			continue
		}
		bits := 8
		ab, bb := a[0], b[0]
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}

// GetAllNodeAddresses gets all Node IP addresses (not including IPv6 link local address).
func GetAllNodeAddresses(excludeDevices []string) ([]net.IP, []net.IP, error) {
	var nodeAddressesIPv4, nodeAddressesIPv6 []net.IP
	_, ipv6LinkLocalNet, _ := net.ParseCIDR("fe80::/64")

	// Get all interfaces.
	interfaces, err := netInterfaces()
	if err != nil {
		return nil, nil, err
	}

	// Transform excludeDevices to a set
	excludeDevicesSet := sets.New[string](excludeDevices...)

	for i := range interfaces {
		// If the device is in excludeDevicesSet, skip it.
		if excludeDevicesSet.Has(interfaces[i].Name) {
			continue
		}

		// Get all IPs of every interface
		addrs, err := netInterfaceAddrs(&interfaces[i])
		if err != nil {
			return nil, nil, err
		}

		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ipv6LinkLocalNet.Contains(ip) {
				continue // Skip IPv6 link local address
			}

			if ip.To4() != nil {
				nodeAddressesIPv4 = append(nodeAddressesIPv4, ip)
			} else {
				nodeAddressesIPv6 = append(nodeAddressesIPv6, ip)
			}
		}
	}
	return nodeAddressesIPv4, nodeAddressesIPv6, nil
}

// Copied from github.com/vishvananda/netlink/netlink.go
// NewIPNet generates an IPNet from an ip address using a netmask of 32 or 128.
func NewIPNet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func PortToUint16(port int) uint16 {
	if port > 0 && port <= math.MaxUint16 {
		return uint16(port)
	}
	klog.Errorf("Port value %d out-of-bounds", port)
	return 0
}

// GenerateUplinkInterfaceName generates the uplink interface name after bridged to OVS
func GenerateUplinkInterfaceName(name string) string {
	return name + bridgedUplinkSuffix
}

func GenerateRandomMAC() net.HardwareAddr {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		klog.ErrorS(err, "Failed to generate a random MAC")
	}
	// Unset the multicast bit.
	buf[0] &= 0xfe
	buf[0] |= 0x02
	return buf
}

func GetIPNetsByLink(link *net.Interface) ([]*net.IPNet, error) {
	addrList, err := netInterfaceAddrs(link)
	if err != nil {
		return nil, err
	}
	var addrs []*net.IPNet
	for _, a := range addrList {
		if ipNet, ok := a.(*net.IPNet); ok {
			addrs = append(addrs, ipNet)
		}
	}
	return addrs, nil
}

// GenerateOVSDatapathID generates an OVS datapath ID string.
func GenerateOVSDatapathID(macString string) string {
	// The length of datapathID is 64 bits, the lower 48-bits are for a MAC address, while the
	// upper 16-bits are implementer-defined. Antrea uses "0x0000" for the upper 16-bits.
	if macString == "" {
		macString = GenerateRandomMAC().String()
	}
	return "0000" + strings.Replace(macString, ":", "", -1)
}

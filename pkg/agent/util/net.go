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
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	interfaceNameLength   = 15
	interfacePrefixLength = 8
	interfaceKeyLength    = interfaceNameLength - (interfacePrefixLength + 1)

	FamilyIPv4 uint8 = 4
	FamilyIPv6 uint8 = 6
)

func generateInterfaceName(key string, name string, useHead bool) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	io.WriteString(hash, key)
	interfaceKey := hex.EncodeToString(hash.Sum(nil))
	prefix := name
	if len(name) > interfacePrefixLength {
		if useHead {
			prefix = name[:interfacePrefixLength]
		} else {
			prefix = name[len(name)-interfacePrefixLength:]
		}
	}
	return fmt.Sprintf("%s-%s", prefix, interfaceKey[:interfaceKeyLength])
}

// GenerateContainerInterfaceKey generates a unique string for a Pod's
// interface as: container/<Container-ID>.
// We must use ContainerID instead of PodNamespace + PodName because there could
// be more than one container associated with the same Pod at some point.
// For example, when deleting a StatefulSet Pod with 0 second grace period, the
// Pod will be removed from the Kubernetes API very quickly and a new Pod will
// be created immediately, and kubelet may process the deletion of the previous
// Pod and the addition of the new Pod simultaneously.
func GenerateContainerInterfaceKey(containerID string) string {
	return fmt.Sprintf("container/%s", containerID)
}

// GenerateNodeTunnelInterfaceKey generates a unique string for a Node's
// tunnel interface as: node/<Node-name>.
func GenerateNodeTunnelInterfaceKey(nodeName string) string {
	return fmt.Sprintf("node/%s", nodeName)
}

// GenerateContainerInterfaceName generates a unique interface name using the
// Pod's namespace, name and containerID. The output should be deterministic (so that
// multiple calls to GenerateContainerInterfaceName with the same parameters
// return the same value). The output has the length of interfaceNameLength(15).
// The probability of collision should be neglectable.
func GenerateContainerInterfaceName(podName, podNamespace, containerID string) string {
	// Use the podName as the prefix and the containerID as the hashing key.
	// podNamespace is not used currently.
	return generateInterfaceName(containerID, podName, true)
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

func dialUnix(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}

// GetIPNetDeviceFromIP returns a local IP/mask and associated device from IP.
func GetIPNetDeviceFromIP(localIP net.IP) (*net.IPNet, *net.Interface, error) {
	linkList, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range linkList {
		addrList, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrList {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIP) {
					return ipNet, &link, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("unable to find local IP and device")
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
	} else {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip, nil
			}
		}
		return nil, errors.New("no IP found with IPv4 AddressFamily")
	}
}

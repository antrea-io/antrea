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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/vishvananda/netlink"
	"io"
	"k8s.io/klog"
	"net"
)

const (
	interfaceNameLength   = 15
	interfacePrefixLength = 8
	interfaceKeyLength    = interfaceNameLength - (interfacePrefixLength + 1)
)

func generateInterfaceName(key string, name string, useHead bool) string {
	hash := sha1.New()
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

// GenerateContainerInterfaceKey generates a unique string for a Pod
// interface as: pod/<Pod-Namespace-name>/<Pod-name>.
func GenerateContainerInterfaceKey(podName, podNamespace string) string {
	return fmt.Sprintf("pod/%s/%s", podNamespace, podName)
}

// GenerateNodeTunnelInterfaceKey generates a unique string for a Node's
// tunnel interface as: node/<Node-name>.
func GenerateNodeTunnelInterfaceKey(nodeName string) string {
	return fmt.Sprintf("node/%s", nodeName)
}

// GenerateContainerInterfaceName generates a unique interface name using the
// Pod's Namespace and name. The output should be deterministic (so that
// multiple calls to GenerateContainerInterfaceName with the same parameters
// return the same value). The output has the length of interfaceNameLength(15).
// The probability of collision should be neglectable.
func GenerateContainerInterfaceName(podName string, podNamespace string) string {
	return generateInterfaceName(GenerateContainerInterfaceKey(podNamespace, podName), podName, true)
}

// GenerateNodeTunnelInterfaceName generates a unique interface name for the
// tunnel to the Node, using the Node's name.
func GenerateNodeTunnelInterfaceName(nodeName string) string {
	return generateInterfaceName(GenerateNodeTunnelInterfaceKey(nodeName), nodeName, false)
}

// GetLocalNodeAddr return a local IP/mask that is on the path of default route.
func GetDefaultLocalNodeAddr() (*net.IPNet, netlink.Link, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	localIP := conn.LocalAddr().(*net.UDPAddr).IP

	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, nil, err
	}

	var dev netlink.Link
	var localAddr *net.IPNet
	for _, link := range linkList {
		addrList, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			klog.Errorf("Failed to get addr list for device %s", link)
			continue
		}
		for _, addr := range addrList {
			if addr.IP.Equal(localIP) {
				localAddr = addr.IPNet
				dev = link
				break
			}
		}
		if dev != nil {
			break
		}
	}

	err = nil
	if dev == nil {
		err = fmt.Errorf("Unable to find local ip and device")
	}
	return localAddr, dev, err
}

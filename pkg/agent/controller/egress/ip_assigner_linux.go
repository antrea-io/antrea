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

package egress

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
)

var ipv6NotSupportErr = errors.New("IPv6 not supported")

type ipAssigner struct {
	egressInterface *net.Interface
	egressLink      netlink.Link
	egressRunDir    string
	mutex           sync.RWMutex
	assignedEgress  map[string]string
}

// NewIPAssigner return an *ipAssigner.
func NewIPAssigner(nodeIPAddr net.IP, dir string) (*ipAssigner, error) {
	_, egressInterface, err := util.GetIPNetDeviceFromIP(nodeIPAddr)
	if err != nil {
		return nil, fmt.Errorf("get IPNetDevice from ip %v error: %+v", nodeIPAddr, err)
	}
	ifaceName := egressInterface.Name
	egressLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("get netlink by name(%s) error: %+v", ifaceName, err)
	}
	a := &ipAssigner{
		egressInterface: egressInterface,
		egressLink:      egressLink,
		egressRunDir:    dir,
		assignedEgress:  make(map[string]string),
	}
	if err := a.initAssignedIPFiles(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *ipAssigner) initAssignedIPFiles() (err error) {
	files, err := ioutil.ReadDir(a.egressRunDir)
	if err != nil {
		if err := os.MkdirAll(a.egressRunDir, os.ModeDir); err != nil {
			return fmt.Errorf("error when creating egress run dir: %v", err)
		}
		return nil
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for _, file := range files {
		egressName := file.Name()
		fileName := ipSavedFile(a.egressRunDir, egressName)
		if ip, err := ioutil.ReadFile(fileName); err == nil {
			a.assignedEgress[egressName] = string(ip)
		}
	}
	return
}

// AssignEgressIP assign an egressIP and save persistent files.
func (a *ipAssigner) AssignEgressIP(egressIP, egressName string) error {
	egressSpecIP := net.ParseIP(egressIP)
	if egressSpecIP == nil {
		return fmt.Errorf("invalid IP %s", egressIP)
	}
	addr := netlink.Addr{IPNet: &net.IPNet{IP: egressSpecIP, Mask: net.CIDRMask(32, 32)}}
	ifaceName := a.egressInterface.Name
	if err := netlink.AddrAdd(a.egressLink, &addr); err != nil {
		return fmt.Errorf("failed to add ip %v to interface %s: %v", addr, ifaceName, err)
	}
	if err := a.saveIPAssignFile(egressIP, egressName); err != nil {
		return fmt.Errorf("failed to save egress ip assign, egress %s, ip: %s: %v", egressName, egressIP, err)
	}
	isIPv4 := egressSpecIP.To4()
	if isIPv4 != nil {
		if err := arping.GratuitousARPOverIface(isIPv4, a.egressInterface); err != nil {
			return fmt.Errorf("Failed to send gratuitous ARP: %v", err)
		}
		klog.InfoS("Sent gratuitous ARP", "ip", isIPv4)
	} else if isIPv6 := egressSpecIP.To16(); isIPv6 != nil {
		return fmt.Errorf("Failed to send Advertisement: %v", ipv6NotSupportErr)
	}
	klog.V(2).InfoS("Added ip", "ip", addr, "interface", ifaceName)
	return nil
}

// UnassignEgressIP unassign an egressIP and delete the persistent files.
func (a *ipAssigner) UnassignEgressIP(egressName string) error {
	egressIP, has := a.isAssignedIP(egressName)
	if !has {
		return nil
	}
	egressSpecIP := net.ParseIP(egressIP)
	addr := netlink.Addr{IPNet: &net.IPNet{IP: egressSpecIP, Mask: net.CIDRMask(32, 32)}}
	ifaceName := a.egressLink.Attrs().Name
	if err := netlink.AddrDel(a.egressLink, &addr); err != nil {
		return fmt.Errorf("failed to delete ip %v from interface %s: %v", addr, ifaceName, err)
	}
	if err := a.removeAssignedIPFile(egressName); err != nil {
		return fmt.Errorf("failed to remove egress ip assign file, egressName: %s, egressIP: %s: %v", egressName, egressIP, err)
	}
	klog.V(2).InfoS("Deleted ip", "ip", addr, "interface", ifaceName)
	return nil
}

// isAssignedIP check that if an IP address has been assigned with a specific egressName.
func (a *ipAssigner) isAssignedIP(egressName string) (egressIP string, has bool) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	if ip, ok := a.assignedEgress[egressName]; ok {
		return ip, true
	}
	return
}

func ipSavedFile(dir, name string) string {
	return filepath.Join(dir, name)
}

func (a *ipAssigner) saveIPAssignFile(egressIP, egressName string) error {
	var buffer bytes.Buffer
	buffer.WriteString(egressIP)
	f, err := os.Create(ipSavedFile(a.egressRunDir, egressName))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, &buffer)
	if err == nil {
		a.mutex.Lock()
		defer a.mutex.Unlock()
		a.assignedEgress[egressName] = egressIP
		return nil
	}
	return err
}

func (a *ipAssigner) removeAssignedIPFile(egressName string) error {
	fileName := ipSavedFile(a.egressRunDir, egressName)
	if err := os.Remove(fileName); err != nil && !os.IsNotExist(err) {
		return err
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.assignedEgress, egressName)
	return nil
}

// AssignedIPs return a map of the allocated IPs ([egressName]IP).
func (a *ipAssigner) AssignedIPs() map[string]string {
	ips := make(map[string]string)
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	for k, v := range a.assignedEgress {
		ips[k] = v
	}
	return ips
}

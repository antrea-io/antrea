//go:build linux
// +build linux

// Copyright 2022 Antrea Authors
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
	"fmt"
	"net"
	"sync"
	"testing"
	"unsafe"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"

	cniservertest "antrea.io/antrea/pkg/agent/cniserver/testing"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/util/arping"
	"antrea.io/antrea/pkg/agent/util/ndp"
	netlinkutil "antrea.io/antrea/pkg/agent/util/netlink"
	netlinktest "antrea.io/antrea/pkg/agent/util/netlink/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	mtu                 = 1450
	containerVethMac, _ = net.ParseMAC(containerMAC)
	hostVethMac, _      = net.ParseMAC(hostIfaceMAC)
	containerIfaceName  = "eth0"
	podName             = "pod0"
	podContainerID      = "abcefgh-12345678"
	hostIfaceName       = util.GenerateContainerInterfaceName(podName, testPodNamespace, podContainerID)
	containerVeth       = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         containerIfaceName,
			Flags:        net.FlagUp,
			MTU:          mtu,
			HardwareAddr: containerVethMac,
			Index:        1,
		},
		PeerName: hostIfaceName,
	}
	hostVeth = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         hostIfaceName,
			Flags:        net.FlagUp,
			MTU:          mtu,
			HardwareAddr: hostVethMac,
			Index:        2,
		},
		PeerName: containerIfaceName,
	}
	validNSs = sync.Map{}

	sriovUplinkName    = "uplink"
	sriovVfIndex       = 5
	sriovVfRepresentor = fmt.Sprintf("%s-%d", sriovUplinkName, sriovVfIndex)
)

func newTestIfConfigurator(ovsHardwareOffloadEnabled bool, netlink netlinkutil.Interface, sriovnet SriovNet) *ifConfigurator {
	return &ifConfigurator{
		ovsDatapathType:             ovsconfig.OVSDatapathSystem,
		isOvsHardwareOffloadEnabled: ovsHardwareOffloadEnabled,
		disableTXChecksumOffload:    true,
		netlink:                     netlink,
		sriovnet:                    sriovnet,
	}
}

type fakeNS struct {
	path          string
	fd            uintptr
	setErr        error
	stopCh        chan struct{}
	waitCompleted bool
}

func (ns *fakeNS) Do(toRun func(ns.NetNS) error) error {
	defer func() {
		if ns.waitCompleted {
			ns.stopCh <- struct{}{}
		}
	}()
	return toRun(ns)
}

func (ns *fakeNS) Set() error {
	return ns.setErr
}

func (ns *fakeNS) Path() string {
	return ns.path
}

func (ns *fakeNS) Fd() uintptr {
	return ns.fd
}

func (ns *fakeNS) Close() error {
	return nil
}

func (ns *fakeNS) clear() {
	if ns.waitCompleted {
		<-ns.stopCh
	}
	validNSs.Delete(ns.path)
}

func createNS(t *testing.T, waitForComplete bool) *fakeNS {
	nsPath := generateUUID()
	fakeNs := &fakeNS{path: nsPath, fd: uintptr(unsafe.Pointer(&nsPath)), waitCompleted: waitForComplete, stopCh: make(chan struct{})}
	validNSs.Store(nsPath, fakeNs)
	return fakeNs
}

func getFakeNS(nspath string) (ns.NetNS, error) {
	fakeNs, exists := validNSs.Load(nspath)
	if exists {
		return fakeNs.(*fakeNS), nil
	}
	return nil, fmt.Errorf("ns not found %s", nspath)
}

func TestConfigureContainerLink(t *testing.T) {
	controller := gomock.NewController(t)
	fakeSriovNet := cniservertest.NewMockSriovNet(controller)
	fakeNetlink := netlinktest.NewMockInterface(controller)

	sriovPfName := "pf"
	sriovVfNetdeviceName := "vfDevice"
	vfDeviceLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: containerVethMac, Name: sriovVfNetdeviceName, Flags: net.FlagUp}}

	defer mockGetNS()()
	defer mockWithNetNSPath()()

	for _, tc := range []struct {
		name                      string
		ovsHardwareOffloadEnabled bool
		sriovVFDeviceID           string
		vfNetdevices              []string
		podSriovVFDeviceID        string
		renameIntefaceErr         error
		setupVethErr              error
		ipamConfigureIfaceErr     error
		ethtoolEthTXHWCsumOffErr  error
		expectErr                 error
	}{
		{
			name:                      "container-vethpair-success",
			ovsHardwareOffloadEnabled: false,
		}, {
			name:                      "container-vethpair-failure",
			ovsHardwareOffloadEnabled: false,
			setupVethErr:              fmt.Errorf("unable to setup veth pair for container"),
			expectErr:                 fmt.Errorf("failed to create veth devices for container %s: unable to setup veth pair for container", podContainerID),
		}, {
			name:                      "container-ipam-failure",
			ovsHardwareOffloadEnabled: false,
			ipamConfigureIfaceErr:     fmt.Errorf("unable to configure container IPAM"),
			expectErr:                 fmt.Errorf("failed to configure IP address for container %s: unable to configure container IPAM", podContainerID),
		}, {
			name:                      "container-hwoffload-failure",
			ovsHardwareOffloadEnabled: true,
			ethtoolEthTXHWCsumOffErr:  fmt.Errorf("unable to disable offloading"),
			expectErr:                 fmt.Errorf("error when disabling TX checksum offload on container veth: unable to disable offloading"),
		}, {
			name:                      "br-sriov-offloading-disable",
			ovsHardwareOffloadEnabled: false,
			sriovVFDeviceID:           "br-vf",
			expectErr:                 fmt.Errorf("OVS is configured with hardware offload disabled, but SR-IOV VF was requested; please set hardware offload to true via antrea yaml"),
		}, {
			name:                      "br-sriov-success",
			ovsHardwareOffloadEnabled: true,
			sriovVFDeviceID:           "br-vf",
			vfNetdevices:              []string{sriovVfNetdeviceName},
		}, {
			name:                      "br-sriov-pciaddress-issue",
			ovsHardwareOffloadEnabled: true,
			sriovVFDeviceID:           "br-vf",
			vfNetdevices:              []string{},
			expectErr:                 fmt.Errorf("failed to get one netdevice interface per br-vf"),
		}, {
			name:                      "br-sriov-rename-failure",
			ovsHardwareOffloadEnabled: true,
			sriovVFDeviceID:           "br-vf",
			vfNetdevices:              []string{sriovVfNetdeviceName},
			renameIntefaceErr:         fmt.Errorf("unable to rename netlink"),
			expectErr:                 fmt.Errorf("failed to rename %s to %s: unable to rename netlink", sriovVfRepresentor, hostIfaceName),
		}, {
			name:                      "pod-sriov-success",
			ovsHardwareOffloadEnabled: true,
			podSriovVFDeviceID:        "sriovPodVF",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockSetupVethWithName(tc.setupVethErr, 1, 2)()
			defer mockRenameInterface(tc.renameIntefaceErr)()
			defer mockIPAMConfigureIface(tc.ipamConfigureIfaceErr)()
			defer mockEthtoolTXHWCsumOff(tc.ethtoolEthTXHWCsumOffErr)()
			testIfConfigurator := newTestIfConfigurator(tc.ovsHardwareOffloadEnabled, fakeNetlink, fakeSriovNet)
			containerNS := createNS(t, false)
			defer containerNS.clear()
			moveVFtoNS := false
			if tc.sriovVFDeviceID != "" && tc.ovsHardwareOffloadEnabled {
				fakeSriovNet.EXPECT().GetNetDevicesFromPci(tc.sriovVFDeviceID).Return(tc.vfNetdevices, nil).Times(1)
				if len(tc.vfNetdevices) == 1 {
					fakeSriovNet.EXPECT().GetUplinkRepresentor(tc.sriovVFDeviceID).Return(sriovUplinkName, nil).Times(1)
					fakeSriovNet.EXPECT().GetVfIndexByPciAddress(tc.sriovVFDeviceID).Return(sriovVfIndex, nil).Times(1)
					fakeSriovNet.EXPECT().GetVfRepresentor(sriovUplinkName, sriovVfIndex).Return(sriovVfRepresentor, nil).Times(1)
					if tc.renameIntefaceErr == nil {
						hostInterfaceLink := &netlink.Dummy{
							LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: hostVethMac, Name: hostIfaceName, Flags: net.FlagUp},
						}
						fakeNetlink.EXPECT().LinkByName(hostIfaceName).Return(hostInterfaceLink, nil).Times(1)
						moveVFtoNS = true
					}
				}
			}
			if tc.podSriovVFDeviceID != "" {
				fakeSriovNet.EXPECT().GetPfName(tc.podSriovVFDeviceID).Return(sriovPfName, nil).Times(1)
				fakeSriovNet.EXPECT().GetVfid(tc.podSriovVFDeviceID, sriovPfName).Return(sriovVfIndex, nil).Times(1)
				fakeSriovNet.EXPECT().GetVFLinkNames(tc.podSriovVFDeviceID).Return(sriovVfNetdeviceName, nil).Times(1)
				fakeNetlink.EXPECT().LinkByName(sriovVfNetdeviceName).Return(vfDeviceLink, nil).Times(1)
				moveVFtoNS = true
			}
			if moveVFtoNS {
				fakeNetlink.EXPECT().LinkByName(sriovVfNetdeviceName).Return(vfDeviceLink, nil).Times(1)
				fakeNetlink.EXPECT().LinkSetNsFd(vfDeviceLink, gomock.Any()).Return(nil).Times(1)
				containerInterfaceLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: containerVethMac, Name: containerIfaceName, Flags: net.FlagUp}}
				fakeNetlink.EXPECT().LinkByName(containerIfaceName).Return(containerInterfaceLink, nil).Times(1)
				fakeNetlink.EXPECT().LinkSetMTU(containerInterfaceLink, gomock.Any()).Return(nil).Times(1)
				fakeNetlink.EXPECT().LinkSetUp(containerInterfaceLink).Return(nil).Times(1)
			}
			err := testIfConfigurator.configureContainerLink(podName, testPodNamespace, podContainerID, containerNS.Path(), containerIfaceName, mtu, tc.sriovVFDeviceID, tc.podSriovVFDeviceID, ipamResult, nil)
			if tc.expectErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestChangeContainerMTU(t *testing.T) {
	controller := gomock.NewController(t)
	fakeNetlink := netlinktest.NewMockInterface(controller)
	hostIfaceName := "pair0"
	containerIfaceName := "eth0"

	containerInterfaceLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: containerVethMac, Name: containerIfaceName, Flags: net.FlagUp}}
	hostInterfaceLink := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: hostVethMac, Name: hostIfaceName, Flags: net.FlagUp},
	}
	notFoundErr := fmt.Errorf("not found")

	tests := []struct {
		name                   string
		containerLink          netlink.Link
		hostLink               netlink.Link
		getPeerErr             error
		getContainerLinkErr    error
		getHostLinkErr         error
		getInfByIdxErr         error
		setContainerMTUErr     error
		setPairInterfaceMTUErr error
		expectedErrStr         string
	}{
		{
			name:          "change MTU successfully",
			containerLink: containerInterfaceLink,
			hostLink:      hostInterfaceLink,
		},
		{
			name:                "failed to change MTU due to interface not found",
			getContainerLinkErr: notFoundErr,
			expectedErrStr:      "failed to find interface eth0 in container",
		},
		{
			name:           "failed to change MTU due to peer interface not found",
			getPeerErr:     notFoundErr,
			expectedErrStr: "failed to get peer index for dev",
		},
		{
			name:           "failed to change MTU due to host interface not found by index",
			containerLink:  containerInterfaceLink,
			getInfByIdxErr: notFoundErr,
			expectedErrStr: "failed to get host interface for index",
		},
		{
			name:           "failed to change MTU due to host link not found by name",
			containerLink:  containerInterfaceLink,
			getHostLinkErr: notFoundErr,
			expectedErrStr: "failed to find host interface pair0",
		},
		{
			name:               "failed to change MTU due to container interface MTU update failure",
			containerLink:      containerInterfaceLink,
			setContainerMTUErr: fmt.Errorf("failed to set MTU"),
			expectedErrStr:     "failed to set MTU for interface eth0 in container",
		},
		{
			name:                   "failed to change MTU due to pair interface MTU update failure",
			containerLink:          containerInterfaceLink,
			hostLink:               hostInterfaceLink,
			setPairInterfaceMTUErr: fmt.Errorf("failed to set MTU"),
			expectedErrStr:         "failed to set MTU for host interface",
		},
	}

	defer mockWithNetNSPath()()
	testIfConfigurator := newTestIfConfigurator(false, fakeNetlink, nil)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			containerNS := createNS(t, false)
			defer containerNS.clear()
			defer mockGetInterfaceByName(nil, 2)()
			defer mockIpGetVethPeerIfindex(2, tc.getPeerErr)()
			defer mockGetInterfaceByIndex(tc.getInfByIdxErr, 2, hostIfaceName)()

			if tc.containerLink != nil {
				fakeNetlink.EXPECT().LinkByName(containerIfaceName).Return(tc.containerLink, nil).Times(1)
				fakeNetlink.EXPECT().LinkSetMTU(tc.containerLink, gomock.Any()).Return(tc.setContainerMTUErr).Times(1)
			} else {
				fakeNetlink.EXPECT().LinkByName(containerIfaceName).Return(nil, tc.getContainerLinkErr).Times(1)
			}

			if tc.hostLink != nil {
				fakeNetlink.EXPECT().LinkByName(hostIfaceName).Return(tc.hostLink, nil).Times(1)
				fakeNetlink.EXPECT().LinkSetMTU(tc.hostLink, gomock.Any()).Return(tc.setPairInterfaceMTUErr).Times(1)
			}
			if tc.getHostLinkErr != nil {
				fakeNetlink.EXPECT().LinkByName(hostIfaceName).Return(nil, tc.getHostLinkErr).Times(1)
			}

			err := testIfConfigurator.changeContainerMTU(containerNS.Path(), containerIfaceName, 50)
			if tc.expectedErrStr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrStr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAdvertiseContainerAddr(t *testing.T) {
	interfaceID := 1
	ipv4CIDR := net.IPNet{
		IP:   net.ParseIP("192.168.100.100"),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	ipv4Gateway := net.ParseIP("192.168.100.1")
	ipv6CIDR := net.IPNet{
		IP:   net.ParseIP("fe12:ab::64:64"),
		Mask: net.IPMask([]byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}),
	}
	ipv6Gateway := net.ParseIP("fe12:ab::64:1")
	defer mockIsNSorErr()()
	defer mockWithNetNSPath()()
	testIfConfigurator := newTestIfConfigurator(false, nil, nil)

	for _, tc := range []struct {
		name              string
		result            *current.Result
		runInNS           bool
		netInterfaceError error
		advertiseIPv4     bool
		advertiseIPv6     bool
		ipv4ArpingErr     error
		ipv6NDPErr        error
	}{
		{
			name:   "result-no-ips",
			result: &current.Result{IPs: nil},
		}, {
			name:    "interface-not-found",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv4CIDR, Gateway: ipv4Gateway},
				{Interface: &interfaceID, Address: ipv6CIDR, Gateway: ipv6Gateway},
			}},
			netInterfaceError: fmt.Errorf("unable to find interface"),
		}, {
			name:    "advertise-ipv4-only",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv4CIDR, Gateway: ipv4Gateway},
			}},
			advertiseIPv4: true,
		}, {
			name:    "advertise-ipv4-failure",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv4CIDR, Gateway: ipv4Gateway},
			}},
			ipv4ArpingErr: fmt.Errorf("failed to send GARP on interface"),
			advertiseIPv4: true,
		}, {
			name:    "advertise-ipv6-only",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv6CIDR, Gateway: ipv6Gateway},
			}},
			advertiseIPv6: true,
		}, {
			name:    "advertise-ipv6-failure",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv6CIDR, Gateway: ipv6Gateway},
			}},
			advertiseIPv6: true,
			ipv6NDPErr:    fmt.Errorf("failed to send IPv6 NDP on interface"),
		}, {
			name:    "advertise-dualstack",
			runInNS: true,
			result: &current.Result{IPs: []*current.IPConfig{
				{Interface: &interfaceID, Address: ipv4CIDR, Gateway: ipv4Gateway},
				{Interface: &interfaceID, Address: ipv6CIDR, Gateway: ipv6Gateway},
			}},
			advertiseIPv4: true,
			advertiseIPv6: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockGetInterfaceByName(tc.netInterfaceError, 1)()
			defer func() {
				arpingGratuitousARPOverIface = arping.GratuitousARPOverIface
				ndpGratuitousNDPOverIface = ndp.GratuitousNDPOverIface
			}()
			containerNS := createNS(t, tc.runInNS)
			count := 0
			if tc.advertiseIPv4 {
				count += 3
			}
			if tc.advertiseIPv6 {
				count += 3
			}
			if tc.advertiseIPv4 {
				arpingGratuitousARPOverIface = func(srcIP net.IP, iface *net.Interface) error {
					count -= 1
					return tc.ipv4ArpingErr
				}
			}
			if tc.advertiseIPv6 {
				ndpGratuitousNDPOverIface = func(srcIP net.IP, iface *net.Interface) error {
					count -= 1
					return tc.ipv6NDPErr
				}
			}
			err := testIfConfigurator.advertiseContainerAddr(containerNS.Path(), containerIfaceName, tc.result)
			assert.NoError(t, err)
			containerNS.clear()
			assert.Equal(t, 0, count)
		})
	}
}

func TestCheckContainerInterface(t *testing.T) {
	controller := gomock.NewController(t)
	containerIPs := ipamResult.IPs
	containerRoutes := ipamResult.Routes
	sriovVfNetdeviceName := "vfDevice"
	vfDeviceLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, MTU: mtu, HardwareAddr: containerVethMac, Name: sriovVfNetdeviceName, Flags: net.FlagUp}}

	fakeSriovNet := cniservertest.NewMockSriovNet(controller)
	fakeNetlink := netlinktest.NewMockInterface(controller)

	defer mockWithNetNSPath()()
	testIfConfigurator := newTestIfConfigurator(false, fakeNetlink, fakeSriovNet)
	for _, tc := range []struct {
		name             string
		sriovVFDeviceID  string
		vfDevices        []string
		containerIPs     []*current.IPConfig
		containerIface   *current.Interface
		containerLink    netlink.Link
		getPeerErr       error
		getNetDevice     bool
		getDeviceErr     error
		validateIPErr    error
		validateRouteErr error
		expectErrStr     string
	}{
		{
			name:           "containerNS-not-equal",
			containerIface: &current.Interface{Name: containerIfaceName, Sandbox: "not-exist", Mac: "01:02:03:04:05:06"},
			expectErrStr:   "sandbox in prevResult not-exist doesn't match configured netns",
		},
		{
			name:            "sriov-interface-unset",
			containerIface:  &current.Interface{Mac: containerMAC},
			sriovVFDeviceID: "sriovVF",
			vfDevices:       []string{},
			expectErrStr:    "interface name is missing",
		},
		{
			name:            "sriov-netdevice-count-issue",
			containerIface:  &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			sriovVFDeviceID: "sriovVF",
			getNetDevice:    true,
			vfDevices:       []string{sriovVfNetdeviceName},
			containerLink:   vfDeviceLink,
			expectErrStr:    "VF netdevice still in host network namespace sriovVF [vfDevice]",
		}, {
			name:            "sriov-get-netdevice-failure",
			containerIface:  &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			sriovVFDeviceID: "sriovVF",
			getNetDevice:    true,
			vfDevices:       []string{},
			containerLink:   vfDeviceLink,
			getDeviceErr:    fmt.Errorf("unable to get VF device"),
			expectErrStr:    "failed to find netdevice to PCI address sriovVF: unable to get VF device",
		}, {
			name:            "sriov-MAC-mismatch",
			containerIface:  &current.Interface{Name: containerIfaceName, Mac: hostIfaceMAC},
			sriovVFDeviceID: "sriovVF",
			getNetDevice:    true,
			vfDevices:       []string{},
			containerLink:   vfDeviceLink,
			expectErrStr:    fmt.Sprintf("interface %s MAC %s doesn't match container MAC: %s", containerIfaceName, hostIfaceMAC, "01:02:03:04:05:06"),
		}, {
			name:            "sriov-success",
			containerIface:  &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			sriovVFDeviceID: "sriovVF",
			getNetDevice:    true,
			vfDevices:       []string{},
			containerLink:   vfDeviceLink,
		}, {
			name:           "container-link-type-incorrect",
			containerIface: &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			containerLink:  vfDeviceLink,
			expectErrStr:   fmt.Sprintf("interface %s is not of type veth", containerIfaceName),
		}, {
			name:           "container-peer-not-found",
			containerIface: &current.Interface{Name: containerIfaceName, Mac: "01:02:03:04:05:06"},
			containerLink:  containerVeth,
			getPeerErr:     fmt.Errorf("peer not found"),
			expectErrStr:   fmt.Sprintf("failed to get veth peer index for veth %s: peer not found", containerIfaceName),
		}, {
			name:           "container-ip-not-equal",
			containerIface: &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			vfDevices:      []string{},
			containerLink:  containerVeth,
			validateIPErr:  fmt.Errorf("IP not equal"),
			expectErrStr:   "IP not equal",
		}, {
			name:             "container-route-not-equal",
			containerIface:   &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			vfDevices:        []string{},
			containerLink:    containerVeth,
			validateRouteErr: fmt.Errorf("route not equal"),
			expectErrStr:     "route not equal",
		}, {
			name:           "container-success",
			containerIface: &current.Interface{Name: containerIfaceName, Mac: containerMAC},
			vfDevices:      []string{},
			containerLink:  containerVeth,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockIpValidateExpectedInterfaceIPs(tc.validateIPErr)()
			defer mockIpValidateExpectedRoute(tc.validateRouteErr)()
			defer mockIpGetVethPeerIfindex(0, tc.getPeerErr)()

			containerNS := createNS(t, false)
			defer containerNS.clear()

			if tc.containerIface.Sandbox == "" {
				tc.containerIface.Sandbox = containerNS.Path()
			}

			if tc.containerLink != nil {
				fakeNetlink.EXPECT().LinkByName(tc.containerIface.Name).Return(tc.containerLink, nil).Times(1)
			}
			if tc.sriovVFDeviceID != "" && tc.getNetDevice {
				fakeSriovNet.EXPECT().GetNetDevicesFromPci(tc.sriovVFDeviceID).Return(tc.vfDevices, tc.getDeviceErr).Times(1)
			}
			_, err := testIfConfigurator.checkContainerInterface(containerNS.Path(), podContainerID, tc.containerIface, containerIPs, containerRoutes, tc.sriovVFDeviceID)
			if tc.expectErrStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErrStr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateVFRepInterface(t *testing.T) {
	controller := gomock.NewController(t)
	fakeSriovNet := cniservertest.NewMockSriovNet(controller)
	testIfConfigurator := newTestIfConfigurator(false, nil, fakeSriovNet)

	for _, tc := range []struct {
		name            string
		sriovVFDeviceID string
		getUplinkRepErr error
		getVfIndexErr   error
		getVfRepErr     error
		expectedErr     error
	}{
		{
			name:            "get-uplink-failure",
			sriovVFDeviceID: "vf1",
			getUplinkRepErr: fmt.Errorf("unable to get uplink"),
			expectedErr:     fmt.Errorf("failed to get uplink representor for PCI Address vf1"),
		}, {
			name:            "get-vfIndex-failure",
			sriovVFDeviceID: "vf2",
			getVfIndexErr:   fmt.Errorf("unable to get vf index"),
			expectedErr:     fmt.Errorf("failed to vf index for PCI Address vf2"),
		}, {
			name:            "get-vf-rep-failure",
			sriovVFDeviceID: "vf3",
			getVfRepErr:     fmt.Errorf("unable to get vf rep"),
			expectedErr:     fmt.Errorf("unable to get vf rep"),
		}, {
			name:            "get-vf-success",
			sriovVFDeviceID: "vf4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeSriovNet.EXPECT().GetUplinkRepresentor(tc.sriovVFDeviceID).Return(sriovUplinkName, tc.getUplinkRepErr).Times(1)
			if tc.getUplinkRepErr == nil {
				fakeSriovNet.EXPECT().GetVfIndexByPciAddress(tc.sriovVFDeviceID).Return(sriovVfIndex, tc.getVfIndexErr).Times(1)
				if tc.getVfIndexErr == nil {
					fakeSriovNet.EXPECT().GetVfRepresentor(sriovUplinkName, sriovVfIndex).Return(sriovVfRepresentor, tc.getVfRepErr).Times(1)
				}
			}
			vfRep, err := testIfConfigurator.validateVFRepInterface(tc.sriovVFDeviceID)
			if tc.expectedErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.expectedErr, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, vfRep, sriovVfRepresentor)
			}
		})
	}
}

func TestGetInterceptedInterfaces(t *testing.T) {
	sandbox := "containerSandbox"
	containerNS := "containerNS"
	testIfConfigurator := newTestIfConfigurator(false, nil, nil)

	for _, tc := range []struct {
		name                 string
		hostIfaceName        string
		brName               string
		getContainerIfaceErr error
		getPeerIfaceErr      error
		containerInterface   *current.Interface
		hostInterface        *current.Interface
		expErrStr            string
	}{
		{
			name:                 "get-container-iface-failure",
			hostIfaceName:        "hostPort1",
			getContainerIfaceErr: fmt.Errorf("unable to get container device"),
			expErrStr:            "connectInterceptedInterface failed to get veth info",
		}, {
			name:            "get-peer-iface-failure",
			hostIfaceName:   "hostPort2",
			getPeerIfaceErr: fmt.Errorf("unable to get container peer"),
			expErrStr:       "connectInterceptedInterface failed to get veth peer info",
		}, {
			name:          "peer-attach-to-bridge",
			hostIfaceName: "hostPort3",
			brName:        "br",
			expErrStr:     "connectInterceptedInterface: does not expect device hostPort3 attached to bridge",
		}, {
			name:               "success",
			hostIfaceName:      "hostPort4",
			containerInterface: &current.Interface{Name: containerIfaceName, Sandbox: sandbox, Mac: containerMAC},
			hostInterface:      &current.Interface{Name: "hostPort4", Mac: hostIfaceMAC},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containerInterface := &net.Interface{Index: 1, MTU: mtu, HardwareAddr: containerVethMac, Name: containerIfaceName, Flags: net.FlagUp}
			hostInterface := &net.Interface{Index: 2, MTU: mtu, HardwareAddr: hostVethMac, Name: tc.hostIfaceName, Flags: net.FlagUp}
			defer mockGetNSDevInterface(containerInterface, tc.getContainerIfaceErr)()
			defer mockGetNSPeerDevBridge(hostInterface, tc.brName, tc.getPeerIfaceErr)()
			containerIface, hostIface, err := testIfConfigurator.getInterceptedInterfaces(sandbox, containerNS, containerIfaceName)
			if tc.expErrStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expErrStr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.containerInterface, containerIface)
				assert.Equal(t, tc.hostInterface, hostIface)
			}
		})
	}
}

func TestValidateContainerPeerInterface(t *testing.T) {
	controller := gomock.NewController(t)
	fakeNetlink := netlinktest.NewMockInterface(controller)
	testIfConfigurator := newTestIfConfigurator(false, fakeNetlink, nil)

	for _, tc := range []struct {
		name          string
		interfaces    []*current.Interface
		containerVeth *vethPair
		hostLink      netlink.Link
		hostLinkErr   error
		peerIndex     int
		getPeerErr    error
		expError      error
		expHostVeth   *vethPair
	}{
		{
			name:          "host-interface-not-set",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1},
			expError:      fmt.Errorf("peer veth interface not found for container interface %s", containerIfaceName),
		}, {
			name:          "host-link-not-found",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: hostIfaceMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1},
			hostLink:      hostVeth,
			hostLinkErr:   fmt.Errorf("unable to find host link with name %s", hostIfaceName),
			expError:      fmt.Errorf("peer veth interface not found for container interface %s", containerIfaceName),
		}, {
			name:          "host-link-index-incorrect",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: hostIfaceMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1, peerIndex: 3},
			hostLink:      hostVeth,
			expError:      fmt.Errorf("peer veth interface not found for container interface %s", containerIfaceName),
		}, {
			name:          "host-link-peer-index-incorrect",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: hostIfaceMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1, peerIndex: 2},
			hostLink:      hostVeth,
			peerIndex:     3,
			expError:      fmt.Errorf("host interface %s peer index doesn't match container interface %s index", hostIfaceName, containerIfaceName),
		}, {
			name:          "host-link-peer-not-found",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: hostIfaceMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1, peerIndex: 2},
			hostLink:      hostVeth,
			peerIndex:     1,
			getPeerErr:    fmt.Errorf("peer link not found"),
			expError:      fmt.Errorf("failed to get veth peer index for host interface %s: peer link not found", hostIfaceName),
		}, {
			name:          "host-link-MAC-incorrect",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: "aa:bb:cc:cc:bb:aa"}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1, peerIndex: 2},
			hostLink:      hostVeth,
			peerIndex:     1,
			expError:      fmt.Errorf("host interface %s MAC aa:bb:cc:cc:bb:aa doesn't match", hostIfaceName),
		}, {
			name:          "success",
			interfaces:    []*current.Interface{{Name: containerIfaceName, Sandbox: "container-sandbox", Mac: containerMAC}, {Name: hostIfaceName, Mac: hostIfaceMAC}},
			containerVeth: &vethPair{name: containerIfaceName, ifIndex: 1, peerIndex: 2},
			hostLink:      hostVeth,
			peerIndex:     1,
			expHostVeth:   &vethPair{name: hostIfaceName, ifIndex: 2, peerIndex: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer mockIpGetVethPeerIfindex(tc.peerIndex, tc.getPeerErr)()
			if tc.hostLink != nil {
				fakeNetlink.EXPECT().LinkByName(hostIfaceName).Return(tc.hostLink, tc.hostLinkErr).Times(1)
			}
			hostVeth, err := testIfConfigurator.validateContainerPeerInterface(tc.interfaces, tc.containerVeth)
			if tc.expError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expHostVeth, hostVeth)
			}
		})
	}
}

func mockSetupVethWithName(setupVethErr error, containerIndex, hostIndex int) func() {
	originalIPSetupVethWithName := ipSetupVethWithName
	ipSetupVethWithName = func(contVethName, hostVethName string, mtu int, mac string, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
		if setupVethErr != nil {
			return net.Interface{}, net.Interface{}, setupVethErr
		}
		containerInterface := net.Interface{Index: containerIndex, MTU: mtu, HardwareAddr: containerVethMac, Name: contVethName, Flags: net.FlagUp}
		hostInterface := net.Interface{Index: hostIndex, MTU: mtu, HardwareAddr: hostVethMac, Name: hostVethName, Flags: net.FlagUp}
		return containerInterface, hostInterface, nil
	}
	return func() {
		ipSetupVethWithName = originalIPSetupVethWithName
	}
}

func mockRenameInterface(renameIntefaceErr error) func() {
	originalRenameInterface := renameInterface
	renameInterface = func(from, to string) error {
		return renameIntefaceErr
	}
	return func() {
		renameInterface = originalRenameInterface
	}
}

func mockIPAMConfigureIface(ipamConfigureIfaceErr error) func() {
	originalIPAMConfigureIface := ipamConfigureIface
	ipamConfigureIface = func(ifName string, res *current.Result) error {
		return ipamConfigureIfaceErr
	}
	return func() {
		ipamConfigureIface = originalIPAMConfigureIface
	}
}

func mockEthtoolTXHWCsumOff(ethtoolEthTXHWCsumOffErr error) func() {
	originalEthtoolTXHWCsumOff := ethtoolTXHWCsumOff
	ethtoolTXHWCsumOff = func(name string) error {
		return ethtoolEthTXHWCsumOffErr
	}
	return func() {
		ethtoolTXHWCsumOff = originalEthtoolTXHWCsumOff
	}
}

func mockGetInterfaceByName(netInterfaceError error, ifaceIndex int) func() {
	originalNetInterfaceByName := netInterfaceByName
	netInterfaceByName = func(name string) (*net.Interface, error) {
		return &net.Interface{Index: ifaceIndex, MTU: mtu, HardwareAddr: containerVethMac, Name: name, Flags: net.FlagUp}, netInterfaceError
	}
	return func() {
		netInterfaceByName = originalNetInterfaceByName
	}
}

func mockGetInterfaceByIndex(netInterfaceError error, ifaceIndex int, name string) func() {
	originalNetInterfaceByIndex := netInterfaceByIndex
	netInterfaceByIndex = func(idx int) (*net.Interface, error) {
		return &net.Interface{Index: ifaceIndex, MTU: mtu, HardwareAddr: containerVethMac, Name: name, Flags: net.FlagUp}, netInterfaceError
	}
	return func() {
		netInterfaceByIndex = originalNetInterfaceByIndex
	}
}

func mockIpValidateExpectedInterfaceIPs(validateIPErr error) func() {
	originalIpValidateExpectedInterfaceIPs := ipValidateExpectedInterfaceIPs
	ipValidateExpectedInterfaceIPs = func(ifName string, resultIPs []*current.IPConfig) error {
		return validateIPErr
	}
	return func() {
		ipValidateExpectedInterfaceIPs = originalIpValidateExpectedInterfaceIPs
	}
}

func mockIpValidateExpectedRoute(validateRouteErr error) func() {
	originalIpValidateExpectedRoute := ipValidateExpectedRoute
	ipValidateExpectedRoute = func(resultRoutes []*cnitypes.Route) error {
		return validateRouteErr
	}
	return func() {
		ipValidateExpectedRoute = originalIpValidateExpectedRoute
	}
}

func mockIpGetVethPeerIfindex(peerIndex int, getPeerErr error) func() {
	originalIpGetVethPeerIfindex := ipGetVethPeerIfindex
	ipGetVethPeerIfindex = func(ifName string) (netlink.Link, int, error) {
		return &netlink.Dummy{}, peerIndex, getPeerErr
	}
	return func() {
		ipGetVethPeerIfindex = originalIpGetVethPeerIfindex
	}
}

func mockGetNSPeerDevBridge(hostInterface *net.Interface, brName string, getPeerIfaceErr error) func() {
	originalGetNSPeerDevBridge := getNSPeerDevBridge
	getNSPeerDevBridge = func(nsPath, dev string) (*net.Interface, string, error) {
		return hostInterface, brName, getPeerIfaceErr
	}
	return func() {
		getNSPeerDevBridge = originalGetNSPeerDevBridge
	}
}

func mockGetNSDevInterface(containerInterface *net.Interface, getContainerIfaceErr error) func() {
	originalGetNSDevInterface := getNSDevInterface
	getNSDevInterface = func(nsPath, dev string) (*net.Interface, error) {
		return containerInterface, getContainerIfaceErr
	}
	return func() {
		getNSDevInterface = originalGetNSDevInterface
	}
}

func mockGetNS() func() {
	originalGetNS := nsGetNS
	nsGetNS = getFakeNS
	return func() {
		nsGetNS = originalGetNS
	}
}

func mockWithNetNSPath() func() {
	originalWithNetNSPath := nsWithNetNSPath
	nsWithNetNSPath = func(nspath string, toRun func(ns.NetNS) error) error {
		netNS, err := getFakeNS(nspath)
		if err != nil {
			return err
		}
		return netNS.Do(toRun)
	}
	return func() {
		nsWithNetNSPath = originalWithNetNSPath
	}
}

func mockIsNSorErr() func() {
	originalIsNSorErr := nsIsNSorErr
	nsIsNSorErr = func(nspath string) error {
		_, err := getFakeNS(nspath)
		return err
	}
	return func() {
		nsIsNSorErr = originalIsNSorErr
	}
}

//go:build linux
// +build linux

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

package wireguard

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

const defaultWireGuardInterfaceName = "antrea-wg0"

var zeroKey = wgtypes.Key{}

// wgctrlClient is an interface to mock wgctrl.Client
type wgctrlClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, config wgtypes.Config) error
}

var _ Interface = (*client)(nil)

var (
	linkAdd                    = netlink.LinkAdd
	linkSetUp                  = netlink.LinkSetUp
	linkSetMTU                 = netlink.LinkSetMTU
	utilConfigureLinkAddresses = util.ConfigureLinkAddresses
)

type client struct {
	wgClient                wgctrlClient
	nodeName                string
	privateKey              wgtypes.Key
	peerPublicKeyByNodeName *sync.Map
	wireGuardConfig         *config.WireGuardConfig
	gatewayConfig           *config.GatewayConfig
}

func New(nodeConfig *config.NodeConfig, wireGuardConfig *config.WireGuardConfig) (Interface, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	if wireGuardConfig.Name == "" {
		wireGuardConfig.Name = defaultWireGuardInterfaceName
	}
	c := &client{
		wgClient:                wgClient,
		nodeName:                nodeConfig.Name,
		wireGuardConfig:         wireGuardConfig,
		peerPublicKeyByNodeName: &sync.Map{},
		gatewayConfig:           nodeConfig.GatewayConfig,
	}
	return c, nil
}

func (client *client) Init(ipv4 net.IP, ipv6 net.IP) (string, error) {
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: client.wireGuardConfig.Name, MTU: client.wireGuardConfig.MTU}}
	err := linkAdd(link)
	if err != nil {
		// Ignore existing link as it may have already been created or managed by userspace process, just ensure the MTU
		// is set correctly.
		if errors.Is(err, unix.EEXIST) {
			if err := linkSetMTU(link, client.wireGuardConfig.MTU); err != nil {
				return "", fmt.Errorf("failed to change WireGuard link MTU to %d: %w", client.wireGuardConfig.MTU, err)
			}
		} else if errors.Is(err, unix.EOPNOTSUPP) {
			return "", fmt.Errorf("WireGuard not supported by the Linux kernel (netlink: %w), make sure the WireGuard kernel module is loaded", err)
		} else {
			return "", err
		}
	}
	if err := linkSetUp(link); err != nil {
		return "", err
	}
	// Configure the IP addresses same as Antrea gateway so iptables MASQUERADE target will select it as source address.
	// It's necessary to make Service traffic requiring SNAT (e.g. host to ClusterIP, external to NodePort) accepted by
	// peer Node and to make their response routed back correctly.
	// If ipv4 or ipv6 is not provided, the IP address from client's Gateway configuration will be used.
	// It uses "/32" mask for IPv4 address and "/128" mask for IPv6 address to avoid impacting routes on Antrea gateway.
	var gatewayIPs []*net.IPNet
	if ipv4 != nil {
		gatewayIPs = append(gatewayIPs, &net.IPNet{
			IP:   ipv4,
			Mask: net.CIDRMask(32, 32),
		})
	} else if client.gatewayConfig.IPv4 != nil {
		gatewayIPs = append(gatewayIPs, &net.IPNet{
			IP:   client.gatewayConfig.IPv4,
			Mask: net.CIDRMask(32, 32),
		})
	}
	if ipv6 != nil {
		gatewayIPs = append(gatewayIPs, &net.IPNet{
			IP:   ipv6,
			Mask: net.CIDRMask(128, 128),
		})
	} else if client.gatewayConfig.IPv6 != nil {
		gatewayIPs = append(gatewayIPs, &net.IPNet{
			IP:   client.gatewayConfig.IPv6,
			Mask: net.CIDRMask(128, 128),
		})
	}
	// This must be executed after netlink.LinkSetUp as the latter ensures link.Attrs().Index is set.
	if err := utilConfigureLinkAddresses(link.Attrs().Index, gatewayIPs); err != nil {
		return "", err
	}
	client.wireGuardConfig.LinkIndex = link.Attrs().Index
	wgDev, err := client.wgClient.Device(client.wireGuardConfig.Name)
	if err != nil {
		return "", err
	}
	client.privateKey = wgDev.PrivateKey
	// WireGuard private key will be persistent across agent restarts. So we only need to
	// generate a new private key if it is empty (all zero).
	if client.privateKey == zeroKey {
		newPkey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", err
		}
		client.privateKey = newPkey
	}
	cfg := wgtypes.Config{
		PrivateKey:   &client.privateKey,
		ListenPort:   &client.wireGuardConfig.Port,
		ReplacePeers: false,
	}

	return client.privateKey.PublicKey().String(), client.wgClient.ConfigureDevice(client.wireGuardConfig.Name, cfg)
}

func (client *client) RemoveStalePeers(currentPeerPublickeys map[string]string) error {
	wgdev, err := client.wgClient.Device(client.wireGuardConfig.Name)
	if err != nil {
		return err
	}
	restoredPeerPublicKeys := make(map[wgtypes.Key]struct{})
	for _, peer := range wgdev.Peers {
		restoredPeerPublicKeys[peer.PublicKey] = struct{}{}
	}

	for nodeName, pubKey := range currentPeerPublickeys {
		pubKey, err := wgtypes.ParseKey(pubKey)
		if err != nil {
			klog.ErrorS(err, "Parse WireGuard public key error", "nodeName", nodeName, "publicKey", pubKey)
			continue
		}
		if _, exist := restoredPeerPublicKeys[pubKey]; exist {
			// Save known Node name and public key mappings for tracking of public key changes when calling UpdatePeer.
			client.peerPublicKeyByNodeName.Store(nodeName, pubKey)
			delete(restoredPeerPublicKeys, pubKey)
		}
	}
	for k := range restoredPeerPublicKeys {
		if err := client.deletePeerByPublicKey(k); err != nil {
			klog.ErrorS(err, "Delete WireGuard peer error")
			return err
		}
	}
	return nil
}

func (client *client) UpdatePeer(nodeName, publicKeyString string, peerNodeIP net.IP, podCIDRs []*net.IPNet) error {
	pubKey, err := wgtypes.ParseKey(publicKeyString)
	if err != nil {
		return err
	}
	var allowedIPs []net.IPNet

	if peerNodeIP.To16() == nil {
		return fmt.Errorf("peer Node IP is not valid: %s", peerNodeIP.String())
	}

	for _, cidr := range podCIDRs {
		allowedIPs = append(allowedIPs, *cidr)
	}

	if key, exist := client.peerPublicKeyByNodeName.Load(nodeName); exist {
		cachedPeerPubKey := key.(wgtypes.Key)
		if cachedPeerPubKey != pubKey {
			klog.InfoS("WireGuard peer public key updated", "nodeName", nodeName, "publicKey", publicKeyString)
			// delete old peer by public key.
			if err := client.deletePeerByPublicKey(cachedPeerPubKey); err != nil {
				return err
			}
		}
	}
	endpoint := net.JoinHostPort(peerNodeIP.String(), strconv.Itoa(client.wireGuardConfig.Port))
	endpointUDP, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return err
	}
	client.peerPublicKeyByNodeName.Store(nodeName, pubKey)
	peerConfig := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		Endpoint:          endpointUDP,
		AllowedIPs:        allowedIPs,
		ReplaceAllowedIPs: true,
	}
	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peerConfig},
	}
	return client.wgClient.ConfigureDevice(client.wireGuardConfig.Name, cfg)
}

func (client *client) deletePeerByPublicKey(pubKey wgtypes.Key) error {
	cfg := wgtypes.Config{Peers: []wgtypes.PeerConfig{
		{PublicKey: pubKey, Remove: true},
	}}
	return client.wgClient.ConfigureDevice(client.wireGuardConfig.Name, cfg)
}

func (client *client) DeletePeer(nodeName string) error {
	key, exist := client.peerPublicKeyByNodeName.Load(nodeName)
	if !exist {
		return nil
	}
	peerPublicKey := key.(wgtypes.Key)
	if err := client.deletePeerByPublicKey(peerPublicKey); err != nil {
		return err
	}
	client.peerPublicKeyByNodeName.Delete(nodeName)
	return nil
}

func (client *client) CleanUp() error {
	if err := netlink.LinkDel(&netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Name: client.wireGuardConfig.Name, Index: client.wireGuardConfig.LinkIndex,
		}}); err != nil && err.Error() != "no such device" {
		return err
	}
	return nil
}

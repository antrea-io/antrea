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
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"antrea.io/antrea/pkg/agent/config"
)

type fakeWireGuardClient struct {
	peers map[wgtypes.Key]wgtypes.Peer
}

func (f *fakeWireGuardClient) Close() error {
	return nil
}

func (f *fakeWireGuardClient) Devices() ([]*wgtypes.Device, error) {
	return nil, nil
}

func (f *fakeWireGuardClient) Device(name string) (*wgtypes.Device, error) {
	var res []wgtypes.Peer
	for _, p := range f.peers {
		res = append(res, p)
	}
	return &wgtypes.Device{
		Peers: res,
	}, nil
}

func (f *fakeWireGuardClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	for _, c := range cfg.Peers {
		if c.Remove {
			delete(f.peers, c.PublicKey)
		} else {
			f.peers[c.PublicKey] = wgtypes.Peer{
				PublicKey:  c.PublicKey,
				Endpoint:   c.Endpoint,
				AllowedIPs: c.AllowedIPs,
			}
		}
	}
	return nil
}

func getFakeClient() *client {
	return &client{
		wgClient: &fakeWireGuardClient{},
		nodeName: "fake-node-1",
		wireGuardConfig: &config.WireGuardConfig{
			MTU:  1420,
			Port: 12345,
		},
		peerPublicKeyByNodeName: &sync.Map{},
	}
}

func Test_RemoveStalePeers(t *testing.T) {
	pk1, _ := wgtypes.GeneratePrivateKey()
	pk2, _ := wgtypes.GeneratePrivateKey()
	pk3, _ := wgtypes.GeneratePrivateKey()
	tests := []struct {
		name                           string
		existingPeers                  map[wgtypes.Key]wgtypes.Peer
		inputPublicKeys                map[string]string
		expectedPeers                  map[wgtypes.Key]wgtypes.Peer
		expectdPeerPublicKeyByNodeName map[string]wgtypes.Key
	}{
		{
			"pass empty/nil slice should remove all existing peers",
			map[wgtypes.Key]wgtypes.Peer{
				pk1.PublicKey(): {PublicKey: pk1.PublicKey()},
				pk2.PublicKey(): {PublicKey: pk2.PublicKey()},
			},
			nil,
			map[wgtypes.Key]wgtypes.Peer{},
			map[string]wgtypes.Key{},
		},
		{
			"args has no intersection with existing peers",
			map[wgtypes.Key]wgtypes.Peer{
				pk1.PublicKey(): {PublicKey: pk1.PublicKey()},
				pk2.PublicKey(): {PublicKey: pk2.PublicKey()},
			},
			map[string]string{
				"node3": pk3.PublicKey().String(),
			},
			map[wgtypes.Key]wgtypes.Peer{},
			map[string]wgtypes.Key{},
		},
		{
			"should only keep peers passed by args",
			map[wgtypes.Key]wgtypes.Peer{
				pk1.PublicKey(): {PublicKey: pk1.PublicKey()},
				pk2.PublicKey(): {PublicKey: pk2.PublicKey()},
				pk3.PublicKey(): {PublicKey: pk3.PublicKey()},
			},
			map[string]string{
				"node3": pk3.PublicKey().String(),
			},
			map[wgtypes.Key]wgtypes.Peer{
				pk3.PublicKey(): {PublicKey: pk3.PublicKey()},
			},
			map[string]wgtypes.Key{
				"node3": pk3.PublicKey(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := getFakeClient()
			fc := &fakeWireGuardClient{peers: tt.existingPeers}
			client.wgClient = fc
			err := client.RemoveStalePeers(tt.inputPublicKeys)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPeers, fc.peers)
			for k, v := range tt.expectdPeerPublicKeyByNodeName {
				pk, ok := client.peerPublicKeyByNodeName.Load(k)
				assert.True(t, ok)
				pubKey, ok := pk.(wgtypes.Key)
				assert.True(t, ok)
				assert.Equal(t, v, pubKey)
			}
		})
	}
}

func Test_UpdatePeer(t *testing.T) {
	pk1, _ := wgtypes.GeneratePrivateKey()
	pk2, _ := wgtypes.GeneratePrivateKey()
	ip1, _, _ := net.ParseCIDR("10.20.30.42/32")
	ip2, _, _ := net.ParseCIDR("10.20.30.43/32")
	_, podCIDR1, _ := net.ParseCIDR("172.16.1.0/24")
	_, podCIDR2, _ := net.ParseCIDR("172.16.2.0/24")
	listenPort := getFakeClient().wireGuardConfig.Port
	tests := []struct {
		name                   string
		existingPeers          map[string]wgtypes.Peer
		inputPeerNodeName      string
		inputPeerNodePublicKey string
		inputPeerNodeIP        net.IP
		inputPodCIDRs          []*net.IPNet
		expectedError          bool
		expectedPeers          map[wgtypes.Key]wgtypes.Peer
	}{
		{
			"call update peer to add new peers",
			map[string]wgtypes.Peer{},
			"fake-node-2",
			pk1.PublicKey().String(),
			ip1,
			[]*net.IPNet{podCIDR1},
			false,
			map[wgtypes.Key]wgtypes.Peer{
				pk1.PublicKey(): {
					PublicKey: pk1.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
		},
		{
			"call update peer to update the public key of an existing peer",
			map[string]wgtypes.Peer{
				"fake-node-2": {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
			"fake-node-2",
			pk2.PublicKey().String(),
			ip1,
			[]*net.IPNet{podCIDR1},
			false,
			map[wgtypes.Key]wgtypes.Peer{
				pk2.PublicKey(): {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
		},
		{
			"call update peer to update Node IP of an existing peer",
			map[string]wgtypes.Peer{
				"fake-node-2": {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
			"fake-node-2",
			pk2.PublicKey().String(),
			ip2,
			[]*net.IPNet{podCIDR1},
			false,
			map[wgtypes.Key]wgtypes.Peer{
				pk2.PublicKey(): {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip2,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
		},
		{
			"call update peer to update Pod CIDR of an existing peer",
			map[string]wgtypes.Peer{
				"fake-node-2": {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
			"fake-node-2",
			pk2.PublicKey().String(),
			ip1,
			[]*net.IPNet{podCIDR2},
			false,
			map[wgtypes.Key]wgtypes.Peer{
				pk2.PublicKey(): {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR2},
				},
			},
		},
		{
			"call update peer with invalid public key",
			map[string]wgtypes.Peer{
				"fake-node-2": {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
			"fake-node-2",
			"invalid key",
			ip1,
			[]*net.IPNet{podCIDR1},
			true,
			map[wgtypes.Key]wgtypes.Peer{
				pk2.PublicKey(): {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
		},
		{
			"call update peer with nil IP",
			map[string]wgtypes.Peer{
				"fake-node-2": {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
			"fake-node-2",
			pk2.PublicKey().String(),
			nil,
			[]*net.IPNet{podCIDR1},
			true,
			map[wgtypes.Key]wgtypes.Peer{
				pk2.PublicKey(): {
					PublicKey: pk2.PublicKey(),
					Endpoint: &net.UDPAddr{
						IP:   ip1,
						Port: listenPort,
					},
					AllowedIPs: []net.IPNet{*podCIDR1},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := getFakeClient()
			fc := &fakeWireGuardClient{
				peers: map[wgtypes.Key]wgtypes.Peer{},
			}
			for _, ec := range tt.existingPeers {
				fc.peers[ec.PublicKey] = ec
			}
			client.wgClient = fc
			err := client.UpdatePeer(tt.inputPeerNodeName, tt.inputPeerNodePublicKey, tt.inputPeerNodeIP, tt.inputPodCIDRs)
			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedPeers, fc.peers)
		})
	}
}

func Test_DeletePeer(t *testing.T) {
	client := getFakeClient()
	fc := &fakeWireGuardClient{
		peers: map[wgtypes.Key]wgtypes.Peer{},
	}
	client.wgClient = fc
	pk1, _ := wgtypes.GeneratePrivateKey()
	ip1, _, _ := net.ParseCIDR("10.20.30.42/32")
	t.Run("delete non-existing peer", func(tt *testing.T) {
		err := client.UpdatePeer("fake-node-1", pk1.String(), ip1, nil)
		require.NoError(tt, err)
		assert.Len(tt, fc.peers, 1)
		_, ok := client.peerPublicKeyByNodeName.Load("fake-node-1")
		assert.True(t, ok)
		err = client.DeletePeer("fake-node-2")
		require.NoError(tt, err)
		assert.Len(tt, fc.peers, 1)
		_, ok = client.peerPublicKeyByNodeName.Load("fake-node-1")
		assert.True(t, ok)
	})

	t.Run("delete existing peer", func(tt *testing.T) {
		err := client.DeletePeer("fake-node-1")
		require.NoError(tt, err)
		assert.Len(tt, fc.peers, 0)
		_, ok := client.peerPublicKeyByNodeName.Load("fake-node-1")
		assert.False(t, ok)
	})
}

func Test_New(t *testing.T) {
	_, err := New(&config.NodeConfig{Name: "test"}, &config.WireGuardConfig{})
	require.NoError(t, err)
}

func Test_Init(t *testing.T) {
	tests := []struct {
		name          string
		linkAddErr    error
		linkSetUpErr  error
		linkSetMTUErr error
		utilConfigErr error
		expectedErr   string
		extraIPv4     net.IP
		extraIPv6     net.IP
	}{
		{
			name: "init successfully",
		},
		{
			name:        "failed to init due to unix.EOPNOTSUPP error",
			linkAddErr:  unix.EOPNOTSUPP,
			expectedErr: "WireGuard not supported by the Linux kernel (netlink: operation not supported), make sure the WireGuard kernel module is loaded",
		},
		{
			name:       "init successfully with unix.EEXIST error",
			linkAddErr: unix.EEXIST,
		},
		{
			name:          "failed to init due to linkSetMTU error",
			linkAddErr:    unix.EEXIST,
			linkSetMTUErr: errors.New("link set mtu failed"),
			expectedErr:   "failed to change WireGuard link MTU to 1420: link set mtu failed",
		},
		{
			name:        "failed to init due to link add error",
			linkAddErr:  errors.New("link add failed"),
			expectedErr: "link add failed",
		},
		{
			name:         "failed to init due to link setup error",
			linkSetUpErr: errors.New("link setup failed"),
			expectedErr:  "link setup failed",
		},
		{
			name:          "failed to init due to link address config error",
			utilConfigErr: errors.New("link address config failed"),
			expectedErr:   "link address config failed",
		},
		{
			name:      "init successfully with provided IPv4 address",
			extraIPv4: net.ParseIP("192.168.0.0"),
		},
		{
			name:      "init successfully with provided IPv6 address",
			extraIPv6: net.ParseIP("0000:0000:0000:0000:0000:0000:0000:0000"),
		},
	}

	client := getFakeClient()
	client.gatewayConfig = &config.GatewayConfig{
		IPv4: net.ParseIP("192.168.0.2"),
		IPv6: net.ParseIP("fd12:ab:34:a001::11"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linkAdd = func(link netlink.Link) error {
				return tt.linkAddErr
			}
			linkSetUp = func(link netlink.Link) error {
				return tt.linkSetUpErr
			}
			linkSetMTU = func(link netlink.Link, mtu int) error {
				return tt.linkSetMTUErr
			}
			utilConfigureLinkAddresses = func(idx int, ipNets []*net.IPNet) error {
				return tt.utilConfigErr
			}

			_, err := client.Init(tt.extraIPv4, tt.extraIPv6)
			if tt.expectedErr != "" {
				assert.Equal(t, tt.expectedErr, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

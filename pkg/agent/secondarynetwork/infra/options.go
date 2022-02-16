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

package infra

import (
	"fmt"
	"io/ioutil"
//	"net"
//	"time"

//	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
//	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/agent/interfacestore"
)

const (
	secondaryNetworkConfigFile     = "/etc/antrea/antrea-agent-secondary-network.conf"
	defaultSecondaryOVSBridge      = "podbr-int0"
	defaultTunnelOVSBridge         = "tunnel-int1"
	defaultOVSPatchPort            = "c_patch0"
        defaultOVSPatchPortPeer        = "tunnel_patch0"
	defaultTunnelType              = ovsconfig.GeneveTunnel
)

type SecondaryNetworkOptions struct {
	// The path of configuration file.
	configFile      string
	interfaceStore  interfacestore.InterfaceStore
	config          *SecondaryNetworkConfig
}

func NewSecondaryNetworkOptions(interfaceStore interfacestore.InterfaceStore) *SecondaryNetworkOptions {
	return &SecondaryNetworkOptions{
		configFile:     secondaryNetworkConfigFile,
		interfaceStore: interfaceStore,
		config:         new(SecondaryNetworkConfig),
	}
}

// Validate SecondaryNetworkConfig params
func (o *SecondaryNetworkOptions) ValidateSecondaryNetworkParams() error {
	if o.config.Secondary_TunnelType != ovsconfig.VXLANTunnel && o.config.Secondary_TunnelType != ovsconfig.GeneveTunnel &&
		o.config.Secondary_TunnelType != ovsconfig.GRETunnel && o.config.Secondary_TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.config.Secondary_TunnelType)
	}
	if o.config.Secondary_OVSDatapathType != string(ovsconfig.OVSDatapathSystem) && o.config.Secondary_OVSDatapathType != string(ovsconfig.OVSDatapathNetdev) {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.Secondary_OVSDatapathType)
	}
//	ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.Secondary_TrafficEncapMode)
//	if !ok {
//		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.Secondary_TrafficEncapMode)
//	}

	return nil
}

func (o *SecondaryNetworkOptions) loadConfigFromFile() error {
	data, err := ioutil.ReadFile(o.configFile)
	if err != nil {
		return err
	}
	return yaml.UnmarshalStrict(data, &o.config)
}
// Set defaults for SecondaryNetworkConfig
func (o *SecondaryNetworkOptions) setDefaults() {
	if o.config.Secondary_OVSBridge1 == "" {
		o.config.Secondary_OVSBridge1 = defaultSecondaryOVSBridge
	}
        if o.config.Secondary_OVSBridge2 == "" {
                o.config.Secondary_OVSBridge2 = defaultTunnelOVSBridge
        }
	if o.config.Secondary_OVSDatapathType == "" {
		o.config.Secondary_OVSDatapathType = string(ovsconfig.OVSDatapathSystem)
	}
	if o.config.Secondary_OVSRunDir == "" {
		o.config.Secondary_OVSRunDir = ovsconfig.DefaultOVSRunDir
	}
        if o.config.Secondary_OVSPatchPort == "" {
                o.config.Secondary_OVSPatchPort = defaultOVSPatchPort
        }
        if o.config.Secondary_OVSPatchPortPeer == "" {
                o.config.Secondary_OVSPatchPortPeer = defaultOVSPatchPortPeer
        }
	if o.config.Secondary_TrafficEncapMode == "" {
		o.config.Secondary_TrafficEncapMode = config.TrafficEncapModeEncap.String()
	}
	if o.config.Secondary_TunnelType == "" {
		o.config.Secondary_TunnelType = defaultTunnelType
	}
}

// LoadSecondaryNetworkConfigAndSetDefaults configures SecondaryNetworkConfig params (OVS bridge config)
func (o *SecondaryNetworkOptions) LoadSecondaryNetworkConfigAndSetDefaults() error {
	klog.Info("LoadSecondaryNetworkConfigAndSetDefaults Called")
        if len(o.configFile) > 0 {
                if err := o.loadConfigFromFile(); err != nil {
                        return fmt.Errorf("loadConfigFromFile failed: %v",err)
                }
        }
        o.setDefaults()

        if err := o.ValidateSecondaryNetworkParams(); err != nil {
                return fmt.Errorf("ValidateSecondaryNetworkParams failed: %v", err)
        }

        return nil
}


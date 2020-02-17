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

package main

import (
	"fmt"
	"io/ioutil"
	"net"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/cni"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	defaultOVSBridge          = "br-int"
	defaultHostGateway        = "gw0"
	defaultHostProcPathPrefix = "/host"
	defaultServiceCIDR        = "10.96.0.0/12"
	defaultMTUVXLAN           = 1450
	defaultMTUGeneve          = 1450
	defaultMTUGRE             = 1462
	defaultMTUSTT             = 1500
	defaultMTU                = 1500
	// IPsec ESP can add a maximum of 38 bytes to the packet including the ESP
	// header and trailer.
	ipsecESPOverhead = 38
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *AgentConfig
}

func newOptions() *Options {
	return &Options{
		config: new(AgentConfig),
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		c, err := o.loadConfigFromFile(o.configFile)
		if err != nil {
			return err
		}
		o.config = c
	}
	o.setDefaults()
	return nil
}

// validate validates all the required options. It must be called after complete.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("an empty argument list is not supported")
	}
	// Validate service CIDR configuration
	_, _, err := net.ParseCIDR(o.config.ServiceCIDR)
	if err != nil {
		return fmt.Errorf("service CIDR %s is invalid", o.config.ServiceCIDR)
	}
	if o.config.TunnelType != ovsconfig.VXLANTunnel && o.config.TunnelType != ovsconfig.GeneveTunnel &&
		o.config.TunnelType != ovsconfig.GRETunnel && o.config.TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.config.TunnelType)
	}
	if o.config.EnableIPSecTunnel && o.config.TunnelType != ovsconfig.GRETunnel {
		return fmt.Errorf("IPSec encyption is supported only for GRE tunnel")
	}
	if o.config.OVSDatapathType != ovsconfig.OVSDatapathSystem && o.config.OVSDatapathType != ovsconfig.OVSDatapathNetdev {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.OVSDatapathType)
	}
	ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}
	if encapMode.SupportsNoEncap() && o.config.EnableIPSecTunnel {
		return fmt.Errorf("IPSec tunnel may only be enabled on %s mode", config.TrafficEncapModeEncap)
	}
	return nil
}

func (o *Options) loadConfigFromFile(file string) (*AgentConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var c AgentConfig
	err = yaml.UnmarshalStrict(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (o *Options) setDefaults() {
	if o.config.CNISocket == "" {
		o.config.CNISocket = cni.AntreaCNISocketAddr
	}
	if o.config.OVSBridge == "" {
		o.config.OVSBridge = defaultOVSBridge
	}
	if o.config.OVSDatapathType == "" {
		o.config.OVSDatapathType = ovsconfig.OVSDatapathSystem
	}
	if o.config.OVSRunDir == "" {
		o.config.OVSRunDir = ovsconfig.DefaultOVSRunDir
	}
	if o.config.HostGateway == "" {
		o.config.HostGateway = defaultHostGateway
	}
	if o.config.TunnelType == "" {
		o.config.TunnelType = ovsconfig.VXLANTunnel
	}
	if o.config.HostProcPathPrefix == "" {
		o.config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if o.config.ServiceCIDR == "" {
		o.config.ServiceCIDR = defaultServiceCIDR
	}
	if o.config.TrafficEncapMode == "" {
		o.config.TrafficEncapMode = config.TrafficEncapModeEncap.String()
	}

	if o.config.DefaultMTU == 0 {
		ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
		if ok && !encapMode.SupportsEncap() {
			o.config.DefaultMTU = defaultMTU
		} else if o.config.TunnelType == ovsconfig.VXLANTunnel {
			o.config.DefaultMTU = defaultMTUVXLAN
		} else if o.config.TunnelType == ovsconfig.GeneveTunnel {
			o.config.DefaultMTU = defaultMTUGeneve
		} else if o.config.TunnelType == ovsconfig.GRETunnel {
			o.config.DefaultMTU = defaultMTUGRE
		} else if o.config.TunnelType == ovsconfig.STTTunnel {
			o.config.DefaultMTU = defaultMTUSTT
		}

		if o.config.EnableIPSecTunnel {
			o.config.DefaultMTU -= ipsecESPOverhead
		}
	}
}

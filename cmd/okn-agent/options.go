// Copyright 2019 OKN Authors
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
	"okn/pkg/ovs/ovsconfig"

	"okn/pkg/cni"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

const (
	defaultOVSBridge          = "br-int"
	defaultHostGateway        = "gw0"
	defaultHostProcPathPrefix = "/host"
	defaultServiceCIDR        = "10.96.0.0/12"
	defaultMTUVxlan           = 1450
	defaultMTUGeneve          = 1450
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
		return fmt.Errorf("An empty argument list is not supported")
	}
	// Validate service CIDR configuration
	_, _, err := net.ParseCIDR(o.config.ServiceCIDR)
	if err != nil {
		return fmt.Errorf("Service CIDR %s is invalid", o.config.ServiceCIDR)
	}
	if o.config.TunnelType != ovsconfig.VXLAN_TUNNEL && o.config.TunnelType != ovsconfig.GENEVE_TUNNEL {
		return fmt.Errorf("Tunnel type %s is invalid", o.config.TunnelType)
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
		o.config.CNISocket = cni.OKNCNISocketAddr
	}
	if o.config.OVSBridge == "" {
		o.config.OVSBridge = defaultOVSBridge
	}
	if o.config.HostGateway == "" {
		o.config.HostGateway = defaultHostGateway
	}
	if o.config.TunnelType == "" {
		o.config.TunnelType = ovsconfig.VXLAN_TUNNEL
	}
	if o.config.HostProcPathPrefix == "" {
		o.config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if o.config.ServiceCIDR == "" {
		o.config.ServiceCIDR = defaultServiceCIDR
	}
	if o.config.DefaultMTU == 0 {
		if o.config.TunnelType == ovsconfig.VXLAN_TUNNEL {
			o.config.DefaultMTU = defaultMTUVxlan
		} else if o.config.TunnelType == ovsconfig.GENEVE_TUNNEL {
			o.config.DefaultMTU = defaultMTUGeneve
		}
	}
}

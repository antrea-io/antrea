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
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	"antrea.io/antrea/pkg/apis"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/yaml"
)

const (
	ipamIPv4MaskLo      = 16
	ipamIPv4MaskHi      = 30
	ipamIPv4MaskDefault = 24
	ipamIPv6MaskLo      = 64
	ipamIPv6MaskHi      = 126
	ipamIPv6MaskDefault = 64
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *controllerconfig.ControllerConfig
}

func newOptions() *Options {
	return &Options{
		config: &controllerconfig.ControllerConfig{},
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) complete() error {
	if len(o.configFile) > 0 {
		if err := o.loadConfigFromFile(); err != nil {
			return err
		}
	}
	o.setDefaults()
	return features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
}

// validate validates all the required options.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no positional arguments are supported")
	}

	if o.config.NodeIPAM.EnableNodeIPAM {
		err := o.validateNodeIPAMControllerOptions()
		if err != nil {
			return err
		}
	}

	if o.config.LegacyCRDMirroring != nil {
		klog.InfoS("The legacyCRDMirroring config option is deprecated and will be ignored (no CRD mirroring)")
	}

	if !features.DefaultFeatureGate.Enabled(features.Multicluster) && o.config.Multicluster.EnableStretchedNetworkPolicy {
		klog.InfoS("Multicluster feature gate is disabled. Multicluster.EnableStretchedNetworkPolicy is ignored")
	}

	return nil
}

func (o *Options) validateNodeIPAMControllerOptions() error {
	// Validate ClusterCIDRs
	cidrs, err := netutils.ParseCIDRs(o.config.NodeIPAM.ClusterCIDRs)
	if err != nil {
		return fmt.Errorf("cluster CIDRs %v is invalid", o.config.NodeIPAM.ClusterCIDRs)
	}

	if len(cidrs) == 0 {
		return fmt.Errorf("at least one cluster CIDR must be specified")
	}
	if len(cidrs) > 2 {
		return fmt.Errorf("at most two cluster CIDRs may be specified")
	}

	hasIP4, hasIP6 := false, false
	var ipv6Mask int
	for _, cidr := range cidrs {
		if cidr.IP.To4() == nil {
			hasIP6 = true
			ipv6Mask, _ = cidr.Mask.Size()
		} else {
			hasIP4 = true
		}
	}

	dualStack := hasIP4 && hasIP6
	if len(cidrs) > 1 && !dualStack {
		return fmt.Errorf("at most one cluster CIDR may be specified for each IP family")
	}

	if hasIP4 {
		if o.config.NodeIPAM.NodeCIDRMaskSizeIPv4 < ipamIPv4MaskLo || o.config.NodeIPAM.NodeCIDRMaskSizeIPv4 > ipamIPv4MaskHi {
			return fmt.Errorf("the Node IPv4 CIDR mask size %d is invalid, should be between %d and %d",
				o.config.NodeIPAM.NodeCIDRMaskSizeIPv4, ipamIPv4MaskLo, ipamIPv4MaskHi)
		}
	}

	if hasIP6 {
		if o.config.NodeIPAM.NodeCIDRMaskSizeIPv6 < ipamIPv6MaskLo || o.config.NodeIPAM.NodeCIDRMaskSizeIPv6 > ipamIPv6MaskHi {
			return fmt.Errorf("the Node IPv6 CIDR mask size %d is invalid, should be between %d and %d",
				o.config.NodeIPAM.NodeCIDRMaskSizeIPv6, ipamIPv6MaskLo, ipamIPv6MaskHi)
		}
		// The subnet mask size cannot be greater than 16 more than the cluster mask size.
		// See https://github.com/kubernetes/kubernetes/issues/44918 for more information.
		if o.config.NodeIPAM.NodeCIDRMaskSizeIPv6-ipv6Mask > 16 {
			return fmt.Errorf("the Node IPv6 CIDR size is too big, the cluster CIDR mask size cannot be greater than 16 more than the Node IPv6 CIDR mask size")
		}
	}

	// Validate ServiceCIDR and ServiceCIDRv6. Service CIDRs can be empty when there is no overlap with ClusterCIDR
	if o.config.NodeIPAM.ServiceCIDR != "" {
		_, _, err = net.ParseCIDR(o.config.NodeIPAM.ServiceCIDR)
		if err != nil {
			return fmt.Errorf("the Service CIDR %s is invalid", o.config.NodeIPAM.ServiceCIDR)
		}
	}
	if o.config.NodeIPAM.ServiceCIDRv6 != "" {
		_, _, err = net.ParseCIDR(o.config.NodeIPAM.ServiceCIDRv6)
		if err != nil {
			return fmt.Errorf("secondary Service CIDR %s is invalid", o.config.NodeIPAM.ServiceCIDRv6)
		}
	}

	return nil
}

func (o *Options) loadConfigFromFile() error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	err = yaml.UnmarshalLenient(data, &o.config)
	if err != nil {
		return fmt.Errorf("failed to decode config file %s: %w", o.configFile, err)
	}
	return nil
}

func (o *Options) setDefaults() {
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaControllerAPIPort
	}
	if o.config.EnablePrometheusMetrics == nil {
		o.config.EnablePrometheusMetrics = ptrBool(true)
	}
	if o.config.SelfSignedCert == nil {
		o.config.SelfSignedCert = ptrBool(true)
	}
	if o.config.NodeIPAM.NodeCIDRMaskSizeIPv4 == 0 {
		o.config.NodeIPAM.NodeCIDRMaskSizeIPv4 = ipamIPv4MaskDefault
	}

	if o.config.NodeIPAM.NodeCIDRMaskSizeIPv6 == 0 {
		o.config.NodeIPAM.NodeCIDRMaskSizeIPv6 = ipamIPv6MaskDefault
	}
	if o.config.IPsecCSRSignerConfig.SelfSignedCA == nil {
		o.config.IPsecCSRSignerConfig.SelfSignedCA = ptrBool(true)
	}
	if o.config.IPsecCSRSignerConfig.AutoApprove == nil {
		o.config.IPsecCSRSignerConfig.AutoApprove = ptrBool(true)
	}
}

func ptrBool(value bool) *bool {
	return &value
}

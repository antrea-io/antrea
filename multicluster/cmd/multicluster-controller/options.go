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

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/util/yaml"
)

type Options struct {
	// The path of configuration file.
	configFile     string
	SelfSignedCert bool
	// options store some base controller Manager options (initialized from the provided config).
	options ctrl.Options
	// The Service ClusterIP range used in the member cluster.
	ServiceCIDR string
	// PodCIDRs is the Pod IP address CIDRs of the member cluster.
	PodCIDRs []string
	// The precedence about which IP (private or public one) of Node is preferred to
	// be used as tunnel endpoint. If not specified, private IP will be chosen.
	GatewayIPPrecedence mcsv1alpha1.Precedence
	// The type of IP address (ClusterIP or PodIP) to be used as the Multi-cluster
	// Services' Endpoints.
	EndpointIPType string
	// Enable StretchedNetworkPolicy to exchange labelIdentities info among the whole
	// ClusterSet.
	EnableStretchedNetworkPolicy bool
	// Watch EndpointSlice API for exported Service if EndpointSlice API is available.
	EnableEndpointSlice bool
	// ClusterCalimCRDAvailable indicates if the ClusterClaim CRD is available or not
	// in the cluster.
	ClusterCalimCRDAvailable bool
	// WebhookConfig contains the controllers webhook configuration
	WebhookConfig mcsv1alpha1.ControllerWebhook
}

func newOptions() *Options {
	return &Options{
		SelfSignedCert: true,
	}
}

func (o *Options) complete(args []string) error {
	var err error
	o.setDefaults()
	ctrlConfig := &mcsv1alpha1.MultiClusterConfig{}
	if len(o.configFile) > 0 {
		klog.InfoS("Loading config", "file", o.configFile)
		if err = o.loadConfigFromFile(ctrlConfig); err != nil {
			return err
		}
		if ctrlConfig.ServiceCIDR != "" {
			if _, _, err := net.ParseCIDR(ctrlConfig.ServiceCIDR); err != nil {
				return fmt.Errorf("failed to parse serviceCIDR, invalid CIDR string %s", ctrlConfig.ServiceCIDR)
			}
		}
		cidrs := []string{}
		for _, cidr := range ctrlConfig.PodCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil && cidr != "" {
				return fmt.Errorf("failed to parse podCIDRs, invalid CIDR string %s", cidr)
			}
			if cidr != "" {
				cidrs = append(cidrs, cidr)
			}
		}
		o.ServiceCIDR = ctrlConfig.ServiceCIDR
		o.PodCIDRs = cidrs
		o.GatewayIPPrecedence = ctrlConfig.GatewayIPPrecedence
		o.WebhookConfig = ctrlConfig.Webhook
		if ctrlConfig.EndpointIPType == "" {
			o.EndpointIPType = common.EndpointIPTypeClusterIP
		} else {
			if ctrlConfig.EndpointIPType != common.EndpointIPTypeClusterIP && ctrlConfig.EndpointIPType != common.EndpointIPTypePodIP {
				return fmt.Errorf("invalid endpointIPType: %s, only 'PodIP' or 'ClusterIP' is allowed", ctrlConfig.EndpointIPType)
			}
			o.EndpointIPType = ctrlConfig.EndpointIPType
		}
		o.EnableStretchedNetworkPolicy = ctrlConfig.EnableStretchedNetworkPolicy
		klog.InfoS("Using config from file", "config", o.configFile)
	} else {
		klog.InfoS("Using default config")
	}
	return nil
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

func (o *Options) setDefaults() {
	o.options = ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		HealthProbeBindAddress: ":8080",
	}
}

func (o *Options) loadConfigFromFile(multiclusterConfig *mcsv1alpha1.MultiClusterConfig) error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}
	codecs := serializer.NewCodecFactory(scheme)
	if err := yaml.UnmarshalLenient(data, multiclusterConfig); err != nil {
		return err
	}
	if err = runtime.DecodeInto(codecs.UniversalDecoder(), data, multiclusterConfig); err != nil {
		return err
	}

	if multiclusterConfig.Metrics.BindAddress != "" {
		o.options.Metrics.BindAddress = multiclusterConfig.Metrics.BindAddress
	}
	if multiclusterConfig.Health.HealthProbeBindAddress != "" {
		o.options.HealthProbeBindAddress = multiclusterConfig.Health.HealthProbeBindAddress
	}

	return nil
}

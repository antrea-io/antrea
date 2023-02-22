//go:build linux
// +build linux

// Copyright 2020 Antrea Authors
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
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func (o *Options) validateNodeType() error {
	switch o.config.NodeType {
	case config.ExternalNode.String():
		if !features.DefaultFeatureGate.Enabled(features.ExternalNode) {
			return fmt.Errorf("nodeType %s requires feature gate ExternalNode to be enabled", o.config.NodeType)
		}
		o.nodeType = config.ExternalNode
	case config.K8sNode.String():
		o.nodeType = config.K8sNode
	default:
		return fmt.Errorf("unsupported nodeType %s", o.config.NodeType)
	}
	return nil
}

func (o *Options) validateTrafficModes() error {
	switch o.config.TunnelType {
	case ovsconfig.VXLANTunnel:
		fallthrough
	case ovsconfig.GeneveTunnel:
		fallthrough
	case ovsconfig.GRETunnel:
		fallthrough
	case ovsconfig.STTTunnel:
		o.tunnelType = ovsconfig.TunnelType(o.config.TunnelType)
	default:
		return fmt.Errorf("TunnelType %s is not supported", o.config.TunnelType)
	}

	var ok bool
	ok, o.trafficEncryptionMode = config.GetTrafficEncryptionModeFromStr(o.config.TrafficEncryptionMode)
	if !ok {
		return fmt.Errorf("TrafficEncryptionMode %s is unknown", o.config.TrafficEncryptionMode)
	}
	if o.trafficEncryptionMode == config.TrafficEncryptionModeNone && o.config.EnableIPSecTunnel {
		klog.InfoS("enableIPSecTunnel is deprecated, use trafficEncryptionMode instead.")
		o.trafficEncryptionMode = config.TrafficEncryptionModeIPSec
	}

	ok, o.trafficEncapMode = config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}

	if o.trafficEncapMode.SupportsNoEncap() && o.trafficEncryptionMode != config.TrafficEncryptionModeNone {
		return fmt.Errorf("TrafficEncryptionMode %s may only be enabled in %s mode", o.trafficEncryptionMode, config.TrafficEncapModeEncap)
	}

	if o.trafficEncryptionMode == config.TrafficEncryptionModeIPSec {
		ok, o.ipsecAuthenticationMode = config.GetIPsecAuthenticationModeFromStr(o.config.IPsec.AuthenticationMode)
		if !ok {
			return fmt.Errorf("IPsec AuthenticationMode %s is unknown", o.config.IPsec.AuthenticationMode)
		}

		if o.ipsecAuthenticationMode == config.IPsecAuthenticationModeCert && !features.DefaultFeatureGate.Enabled(features.IPsecCertAuth) {
			return fmt.Errorf("IPsec AuthenticationMode %s requires feature gate %s to be enabled", o.ipsecAuthenticationMode, features.IPsecCertAuth)
		}
	}

	if o.config.NoSNAT && !(o.trafficEncapMode == config.TrafficEncapModeNoEncap || o.trafficEncapMode == config.TrafficEncapModeNetworkPolicyOnly) {
		return fmt.Errorf("noSNAT is only applicable to the %s mode", config.TrafficEncapModeNoEncap)
	}
	if o.trafficEncapMode == config.TrafficEncapModeNetworkPolicyOnly {
		// In the NetworkPolicyOnly mode, Antrea will not perform SNAT
		// (but SNAT can be done by the primary CNI).
		o.config.NoSNAT = true
	}
	return nil
}

func (o *Options) validateEgressConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.Egress) {
		return nil
	}
	if o.trafficEncapMode != config.TrafficEncapModeEncap {
		klog.InfoS("Egress requires 'encap' TrafficEncapMode, skipp running it")
		return nil
	}
	if o.config.Egress.MaxEgressIPsPerNode > defaultMaxEgressIPsPerNode {
		return fmt.Errorf("maxEgressIPsPerNode cannot be greater than %d", defaultMaxEgressIPsPerNode)
	}

	for _, cidr := range o.config.Egress.ExceptCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Egress Except CIDR %s is invalid", cidr)
		}
		o.exceptCIDRs = append(o.exceptCIDRs, ipNet)
	}
	o.enableEgress = true
	return nil
}

func (o *Options) validateL7NetworkPolicyConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.L7NetworkPolicy) {
		return nil
	}
	// L7NetworkPolicy depends on AntreaProxy.
	if !o.enableAntreaPolicy {
		return nil
	}
	o.enableL7NetworkPolicy = true
	return nil
}

func (o *Options) validateMulticastConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.Multicast) {
		return nil
	}
	if o.trafficEncapMode.IsNetworkPolicyOnly() {
		klog.InfoS("Multicast doesn't work with 'networkPolicyOnly' TrafficEncapMode, skipp running it")
		return nil
	}
	var err error
	o.igmpQueryInterval, err = time.ParseDuration(o.config.Multicast.IGMPQueryInterval)
	if err != nil {
		return fmt.Errorf("invalid multicast.igmpQueryInterval %s: %v", o.config.Multicast.IGMPQueryInterval, err)
	}
	if len(o.config.Multicast.MulticastInterfaces) == 0 && len(o.config.MulticastInterfaces) > 0 {
		klog.InfoS("The multicastInterfaces option is deprecated, please use multicast.multicastInterfaces instead")
		o.config.Multicast.MulticastInterfaces = o.config.MulticastInterfaces
	}
	o.enableMulticast = true
	return nil
}

func (o *Options) validateMulticlusterConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.Multicluster) {
		if o.config.Multicluster.EnableGateway {
			klog.InfoS("The multicluster.enableGateway config option is set to true, but it will be ignored because the Multicluster feature gate is disabled")
		}
		return nil
	}
	if !o.config.Multicluster.EnableGateway && o.config.Multicluster.Enable {
		// Multicluster.Enable is deprecated but it may be set by an earlier version
		// deployment manifest. If it is set to true, pass the value to
		// Multicluster.EnableGateway.
		klog.InfoS("The multicluster.enable option is deprecated, please use multicluster.enableGateway instead")
		o.config.Multicluster.EnableGateway = true
	}
	if o.config.Multicluster.EnableGateway {
		if o.trafficEncapMode != config.TrafficEncapModeEncap {
			// Only Encap mode is supported for Multi-cluster Gateway.
			return fmt.Errorf("Multicluster is only applicable to the %s mode", config.TrafficEncapModeEncap)
		}
	} else {
		if o.config.Multicluster.EnableStretchedNetworkPolicy {
			return fmt.Errorf("Multicluster Gateway must be enabled to enable StretchedNetworkPolicy")
		}
		if o.config.Multicluster.EnablePodToPodConnectivity {
			return fmt.Errorf("Multicluster Gateway must be enabled to enable PodToPodConnectivity")
		}
	}
	return nil
}

func (o *Options) validateAntreaIPAMConfig() error {
	if o.config.EnableBridgingMode {
		if !features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
			return fmt.Errorf("AntreaIPAM feature gate must be enabled to support bridging mode")
		}
		if o.trafficEncapMode != config.TrafficEncapModeNoEncap {
			return fmt.Errorf("bridging mode requires 'noEncap' TrafficEncapMode, current: %s", o.config.TrafficEncapMode)
		}
		// TODO(gran): support SNAT for Per-Node IPAM Pods
		// SNAT needs to be updated to bypass traffic from AntreaIPAM Pod to Per-Node IPAM Pod
		if !o.config.NoSNAT {
			return fmt.Errorf("bridging mode requires noSNAT")
		}
	}

	if features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		if !features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
			return fmt.Errorf("AntreaIPAM feature gate must be enabled to support secondary network")
		}
		o.enableSecondaryNetwork = true
	}

	o.enableAntreaIPAM = features.DefaultFeatureGate.Enabled(features.AntreaIPAM)
	return nil
}

func (o *Options) validatePolicyBypassRulesConfig() error {
	allowedProtocols := sets.NewString("tcp", "udp", "icmp", "ip")
	for _, rule := range o.config.ExternalNode.PolicyBypassRules {
		if rule.Direction != "ingress" && rule.Direction != "egress" {
			return fmt.Errorf("direction %s for policyBypassRule is invalid", rule.Direction)
		}
		if !allowedProtocols.Has(rule.Protocol) {
			return fmt.Errorf("protocol %s for policyBypassRule is invalid", rule.Protocol)
		}
		var err error
		var cidr *net.IPNet
		if _, cidr, err = net.ParseCIDR(rule.CIDR); err != nil {
			return fmt.Errorf("cidr %s for policyBypassRule is invalid", rule.CIDR)
		}
		if rule.Port == 0 && (rule.Protocol == "tcp" || rule.Protocol == "udp") {
			return fmt.Errorf("missing port for policyBypassRule when protocol is %s", rule.Protocol)
		}
		if rule.Port < 0 || rule.Port > 65535 {
			return fmt.Errorf("port %d for policyBypassRule is invalid", rule.Port)
		}
		o.policyBypassRules = append(o.policyBypassRules, &types.PolicyBypassRule{
			Ingress:  rule.Direction == "ingress",
			Protocol: openflow.Protocol(rule.Protocol),
			CIDR:     cidr,
			Port:     uint16(rule.Port),
		})
	}
	return nil
}

func (o *Options) validateServiceExternalIP() error {
	o.enableServiceExternalIP = features.DefaultFeatureGate.Enabled(features.ServiceExternalIP)
	return nil
}

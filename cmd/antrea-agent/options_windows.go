//go:build windows
// +build windows

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

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func (o *Options) validateNodeType() error {
	// Only K8s NodeType is supported on Windows.
	if o.config.NodeType == config.K8sNode.String() {
		o.nodeType = config.K8sNode
	} else {
		return fmt.Errorf("unsupported nodeType %s", o.config.NodeType)
	}
	return nil
}

func (o *Options) validateTrafficModes() error {
	// GRE tunnel is not supported on Windows.
	switch o.config.TunnelType {
	case ovsconfig.VXLANTunnel:
		fallthrough
	case ovsconfig.GeneveTunnel:
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
	if o.trafficEncryptionMode != config.TrafficEncryptionModeNone {
		return fmt.Errorf("TrafficEncryptionMode %s is not supported", o.config.TrafficEncryptionMode)
	}

	ok, o.trafficEncapMode = config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}
	if o.trafficEncapMode == config.TrafficEncapModeNetworkPolicyOnly {
		return fmt.Errorf("TrafficEncapMode %s is not supported", o.config.TrafficEncapMode)
	}

	if o.config.NoSNAT && o.trafficEncapMode != config.TrafficEncapModeNoEncap {
		return fmt.Errorf("noSNAT is only applicable to the %s mode", config.TrafficEncapModeNoEncap)
	}
	return nil
}

func (o *Options) validateMulticastConfig() error {
	// Multicast is not supported on Windows.
	o.enableMulticast = false
	return nil
}

func (o *Options) validateMulticlusterConfig() error {
	// Multicluster is not supported on Windows.
	if o.config.Multicluster.EnableGateway || o.config.Multicluster.EnableStretchedNetworkPolicy || o.config.Multicluster.EnablePodToPodConnectivity {
		return fmt.Errorf("Multicluster is not supported on Windows")
	}
	return nil
}

func (o *Options) validateAntreaIPAMConfig() error {
	// AntreaIPAM and related features are supported on Windows.
	if o.config.EnableBridgingMode {
		return fmt.Errorf("bridging mode is not supported on Windows")
	}
	o.enableSecondaryNetwork = false
	o.enableAntreaIPAM = false
	return nil
}

func (o *Options) validateL7NetworkPolicyConfig() error {
	// L7NetworkPolicy is supported on Windows.
	o.enableL7NetworkPolicy = false
	return nil
}

func (o *Options) validateEgressConfig() error {
	// Egress is not supported in Windows.
	o.enableEgress = false
	return nil
}

func (o *Options) validateServiceExternalIP() error {
	// ServiceExternalIP is not supported in Windows.
	o.enableServiceExternalIP = false
	return nil
}

func (o *Options) validatePolicyBypassRulesConfig() error {
	// PolicyBypassRules is specific to External NodeType, which is not applicable to Windows.
	return nil
}

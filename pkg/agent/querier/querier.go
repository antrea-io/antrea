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

package querier

import (
	"strconv"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/proxy"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

var _ AgentQuerier = new(agentQuerier)

type AgentQuerier interface {
	GetNodeConfig() *config.NodeConfig
	GetNetworkConfig() *config.NetworkConfig
	GetInterfaceStore() interfacestore.InterfaceStore
	GetK8sClient() clientset.Interface
	GetAgentInfo(agentInfo *v1beta1.AntreaAgentInfo, partial bool)
	GetOpenflowClient() openflow.Client
	GetOVSCtlClient() ovsctl.OVSCtlClient
	GetProxier() proxy.Proxier
	GetNetworkPolicyInfoQuerier() querier.AgentNetworkPolicyInfoQuerier
}

type agentQuerier struct {
	nodeConfig               *config.NodeConfig
	networkConfig            *config.NetworkConfig
	interfaceStore           interfacestore.InterfaceStore
	k8sClient                clientset.Interface
	ofClient                 openflow.Client
	ovsBridgeClient          ovsconfig.OVSBridgeClient
	proxier                  proxy.Proxier
	networkPolicyInfoQuerier querier.AgentNetworkPolicyInfoQuerier
	apiPort                  int
}

func NewAgentQuerier(
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	interfaceStore interfacestore.InterfaceStore,
	k8sClient clientset.Interface,
	ofClient openflow.Client,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	proxier proxy.Proxier,
	networkPolicyInfoQuerier querier.AgentNetworkPolicyInfoQuerier,
	apiPort int,
) *agentQuerier {
	return &agentQuerier{
		nodeConfig:               nodeConfig,
		networkConfig:            networkConfig,
		interfaceStore:           interfaceStore,
		k8sClient:                k8sClient,
		ofClient:                 ofClient,
		ovsBridgeClient:          ovsBridgeClient,
		proxier:                  proxier,
		networkPolicyInfoQuerier: networkPolicyInfoQuerier,
		apiPort:                  apiPort}
}

// GetNodeConfig returns NodeConfig.
func (aq agentQuerier) GetNodeConfig() *config.NodeConfig {
	return aq.nodeConfig
}

// GetNetworkConfig returns NetworkConfig.
func (aq agentQuerier) GetNetworkConfig() *config.NetworkConfig {
	return aq.networkConfig
}

// GetInterfaceStore returns InterfaceStore.
func (aq agentQuerier) GetInterfaceStore() interfacestore.InterfaceStore {
	return aq.interfaceStore
}

// GetK8sClient returns Kubernetes client.
func (aq agentQuerier) GetK8sClient() clientset.Interface {
	return aq.k8sClient
}

// GetOpenflowClient returns openflow.Client.
func (aq *agentQuerier) GetOpenflowClient() openflow.Client {
	return aq.ofClient
}

// GetOVSCtlClient returns a new OVSCtlClient.
func (aq *agentQuerier) GetOVSCtlClient() ovsctl.OVSCtlClient {
	return ovsctl.NewClient(aq.nodeConfig.OVSBridge)
}

// GetProxier returns proxy.Proxier.
func (aq *agentQuerier) GetProxier() proxy.Proxier {
	return aq.proxier
}

// GetNetworkPolicyInfoQuerier returns AgentNetworkPolicyInfoQuerier.
func (aq agentQuerier) GetNetworkPolicyInfoQuerier() querier.AgentNetworkPolicyInfoQuerier {
	return aq.networkPolicyInfoQuerier
}

// getOVSVersion gets current OVS version.
func (aq agentQuerier) getOVSVersion() string {
	v, err := aq.ovsBridgeClient.GetOVSVersion()
	if err != nil {
		klog.Errorf("Failed to get OVS client version: %v", err)
		return ""
	}
	return v
}

// getOVSFlowTable gets current OVS flow tables.
func (aq agentQuerier) getOVSFlowTable() map[string]int32 {
	flowTable := make(map[string]int32)
	flowTableStatus := aq.ofClient.GetFlowTableStatus()
	for _, tableStatus := range flowTableStatus {
		flowTable[strconv.Itoa(int(tableStatus.ID))] = int32(tableStatus.FlowCount)
	}
	return flowTable
}

// getAgentConditions gets current conditions of agent pod.
func (aq agentQuerier) getAgentConditions(ovsConnected bool) []v1beta1.AgentCondition {
	lastHeartbeatTime := metav1.Now()
	controllerConnectionStatus := v1.ConditionTrue
	ovsdbConnectionStatus := v1.ConditionTrue
	openflowConnectionStatus := v1.ConditionTrue
	if !aq.networkPolicyInfoQuerier.GetControllerConnectionStatus() {
		controllerConnectionStatus = v1.ConditionFalse
	}
	if !ovsConnected {
		ovsdbConnectionStatus = v1.ConditionFalse
	}
	if !aq.ofClient.IsConnected() {
		openflowConnectionStatus = v1.ConditionFalse
	}
	return []v1beta1.AgentCondition{
		{
			Type:              v1beta1.AgentHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: lastHeartbeatTime,
		},
		{
			Type:              v1beta1.ControllerConnectionUp,
			Status:            controllerConnectionStatus,
			LastHeartbeatTime: lastHeartbeatTime,
		},
		{
			Type:              v1beta1.OVSDBConnectionUp,
			Status:            ovsdbConnectionStatus,
			LastHeartbeatTime: lastHeartbeatTime,
		},
		{
			Type:              v1beta1.OpenflowConnectionUp,
			Status:            openflowConnectionStatus,
			LastHeartbeatTime: lastHeartbeatTime,
		},
	}
}

// getNetworkPolicyControllerInfo gets current network policy controller info
// including: number of network policies, address groups and applied to groups.
func (aq agentQuerier) getNetworkPolicyControllerInfo() v1beta1.NetworkPolicyControllerInfo {
	return v1beta1.NetworkPolicyControllerInfo{
		NetworkPolicyNum:  int32(aq.networkPolicyInfoQuerier.GetNetworkPolicyNum()),
		AddressGroupNum:   int32(aq.networkPolicyInfoQuerier.GetAddressGroupNum()),
		AppliedToGroupNum: int32(aq.networkPolicyInfoQuerier.GetAppliedToGroupNum()),
	}
}

// GetAgentInfo gets current agent pod info.
func (aq agentQuerier) GetAgentInfo(agentInfo *v1beta1.AntreaAgentInfo, partial bool) {
	// LocalPodNum, FlowTable, NetworkPolicyControllerInfo, OVSVersion and AgentConditions can be changed, so reset these fields.
	// Only these fields are updated when partial is true.
	agentInfo.Name = aq.nodeConfig.Name
	agentInfo.LocalPodNum = int32(aq.interfaceStore.GetContainerInterfaceNum())
	agentInfo.OVSInfo.FlowTable = aq.getOVSFlowTable()
	agentInfo.NetworkPolicyControllerInfo = aq.getNetworkPolicyControllerInfo()
	ovsVersion := aq.getOVSVersion()
	// OVS version query will fail and return empty string when OVSDB connection is down.
	// Only change OVS version when the query gets a valid version.
	ovsConnected := ovsVersion != ""
	if ovsConnected {
		agentInfo.OVSInfo.Version = ovsVersion
	}
	agentInfo.AgentConditions = aq.getAgentConditions(ovsConnected)

	// Some other fields are needed when partial if false.
	if !partial {
		agentInfo.Version = querier.GetVersion()
		agentInfo.PodRef = querier.GetSelfPod()
		agentInfo.NodeRef = querier.GetSelfNode(true, aq.nodeConfig.Name)
		// Make a new string slice instead of appending agentInfo.NodeSubnets directly to avoid duplicate CIDRs.
		nodeSubnets := make([]string, 0)
		if aq.nodeConfig.PodIPv4CIDR != nil {
			nodeSubnets = append(nodeSubnets, aq.nodeConfig.PodIPv4CIDR.String())
		}
		if aq.nodeConfig.PodIPv6CIDR != nil {
			nodeSubnets = append(nodeSubnets, aq.nodeConfig.PodIPv6CIDR.String())
		}
		agentInfo.NodeSubnets = nodeSubnets
		agentInfo.OVSInfo.BridgeName = aq.nodeConfig.OVSBridge
		agentInfo.APIPort = aq.apiPort
	}
}

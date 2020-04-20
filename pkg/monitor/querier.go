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

package monitor

import (
	"os"
	"strconv"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/version"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

const (
	serviceName  = "antrea"
	podName      = "POD_NAME"
	podNamespace = "POD_NAMESPACE"
	nodeName     = "NODE_NAME"
)

// Querier provides interface for both monitor CRD and CLI to consume controller and agent status.
type Querier interface {
	GetSelfPod() v1.ObjectReference
	GetSelfNode() v1.ObjectReference
	GetNetworkPolicyControllerInfo() v1beta1.NetworkPolicyControllerInfo
	GetVersion() string
}

type AgentQuerier interface {
	Querier
	GetOVSFlowTable() map[string]int32
	GetLocalPodNum() int32
	GetAgentInfo() *v1beta1.AntreaAgentInfo
	GetInterfaceStore() interfacestore.InterfaceStore
}

type ControllerQuerier interface {
	Querier
	GetService() v1.ObjectReference
	GetControllerInfo() *v1beta1.AntreaControllerInfo
}

type NetworkPolicyInfoQuerier interface {
	GetNetworkPolicyNum() int
	GetAddressGroupNum() int
	GetAppliedToGroupNum() int
}

type AgentNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetControllerConnectionStatus() bool
	GetNetworkPolicies() []networkingv1beta1.NetworkPolicy
	GetAddressGroups() []networkingv1beta1.AddressGroup
	GetAppliedToGroups() []networkingv1beta1.AppliedToGroup
}

type ControllerNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetConnectedAgentNum() int
}

func (monitor *agentMonitor) GetSelfPod() v1.ObjectReference {
	if os.Getenv(podName) == "" || os.Getenv(podNamespace) == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Pod", Name: os.Getenv(podName), Namespace: os.Getenv(podNamespace)}
}

func (monitor *agentMonitor) GetSelfNode() v1.ObjectReference {
	if monitor.nodeName == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Node", Name: monitor.nodeName}
}

func (monitor *agentMonitor) GetOVSVersion() string {
	v, err := monitor.ovsBridgeClient.GetOVSVersion()
	if err != nil {
		klog.Errorf("Failed to get OVS client version: %v", err)
		return ""
	}
	return v
}

func (monitor *agentMonitor) GetOVSFlowTable() map[string]int32 {
	flowTable := make(map[string]int32)
	flowTableStatus := monitor.ofClient.GetFlowTableStatus()
	for _, tableStatus := range flowTableStatus {
		flowTable[strconv.Itoa(int(tableStatus.ID))] = int32(tableStatus.FlowCount)
	}
	return flowTable
}

func (monitor *agentMonitor) GetNetworkPolicyControllerInfo() v1beta1.NetworkPolicyControllerInfo {
	return v1beta1.NetworkPolicyControllerInfo{
		NetworkPolicyNum:  int32(monitor.networkPolicyInfoQuerier.GetNetworkPolicyNum()),
		AddressGroupNum:   int32(monitor.networkPolicyInfoQuerier.GetAddressGroupNum()),
		AppliedToGroupNum: int32(monitor.networkPolicyInfoQuerier.GetAppliedToGroupNum()),
	}
}

// GetLocalPodNum gets the number of Pod which the Agent is in charge of.
func (monitor *agentMonitor) GetLocalPodNum() int32 {
	return int32(monitor.interfaceStore.GetContainerInterfaceNum())
}

func (monitor *agentMonitor) GetInterfaceStore() interfacestore.InterfaceStore {
	return monitor.interfaceStore
}

func (monitor *agentMonitor) GetAgentConditions(ovsConnected bool) []v1beta1.AgentCondition {
	lastHeartbeatTime := metav1.Now()
	controllerConnectionStatus := v1.ConditionTrue
	ovsdbConnectionStatus := v1.ConditionTrue
	openflowConnectionStatus := v1.ConditionTrue
	if !monitor.networkPolicyInfoQuerier.GetControllerConnectionStatus() {
		controllerConnectionStatus = v1.ConditionFalse
	}
	if !ovsConnected {
		ovsdbConnectionStatus = v1.ConditionFalse
	}
	if !monitor.ofClient.IsConnected() {
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

func (monitor *agentMonitor) GetVersion() string {
	return version.GetFullVersion()
}

func (monitor *controllerMonitor) GetSelfPod() v1.ObjectReference {
	if os.Getenv(podName) == "" || os.Getenv(podNamespace) == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Pod", Name: os.Getenv(podName), Namespace: os.Getenv(podNamespace)}
}

func (monitor *controllerMonitor) GetSelfNode() v1.ObjectReference {
	if os.Getenv(nodeName) == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Node", Name: os.Getenv(nodeName)}
}

func (monitor *controllerMonitor) GetService() v1.ObjectReference {
	return v1.ObjectReference{Kind: "Service", Name: serviceName}
}

func (monitor *controllerMonitor) GetVersion() string {
	return version.GetFullVersion()
}

func (monitor *controllerMonitor) GetNetworkPolicyControllerInfo() v1beta1.NetworkPolicyControllerInfo {
	return v1beta1.NetworkPolicyControllerInfo{
		NetworkPolicyNum:  int32(monitor.networkPolicyInfoQuerier.GetNetworkPolicyNum()),
		AddressGroupNum:   int32(monitor.networkPolicyInfoQuerier.GetAddressGroupNum()),
		AppliedToGroupNum: int32(monitor.networkPolicyInfoQuerier.GetAppliedToGroupNum()),
	}
}

func (monitor *controllerMonitor) GetConnectedAgentNum() int {
	return monitor.networkPolicyInfoQuerier.GetConnectedAgentNum()
}

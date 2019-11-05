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

	"github.com/vmware-tanzu/antrea/pkg/version"

	"k8s.io/api/core/v1"
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
	GetVersion() string
}

type AgentQuerier interface {
	Querier
	GetOVSFlowTable() map[string]int32
	GetLocalPodNum() int32
}

type ControllerQuerier interface {
	Querier
	GetService() v1.ObjectReference
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
	version, err := monitor.ovsBridgeClient.GetOVSVersion()
	if err != nil {
		klog.Errorf("Failed to get OVS client version: %v", err)
		return ""
	}
	return version
}

func (monitor *agentMonitor) GetOVSFlowTable() map[string]int32 {
	flowTable := make(map[string]int32)
	flowTableStatus := monitor.ofClient.GetFlowTableStatus()
	for _, tableStatus := range flowTableStatus {
		flowTable[strconv.Itoa(int(tableStatus.ID))] = int32(tableStatus.FlowCount)
	}
	return flowTable
}

// GetLocalPodNum gets the number of Pod which the Agent is in charge of.
func (monitor *agentMonitor) GetLocalPodNum() int32 {
	return int32(monitor.interfaceStore.GetContainerInterfaceNum())
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

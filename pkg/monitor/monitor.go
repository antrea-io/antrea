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
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/crd/antrea/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

type monitor interface {
	Run(stopCh <-chan struct{})
}

type controllerMonitor struct {
	client clientset.Interface
}

type agentMonitor struct {
	client          clientset.Interface
	ovsBridge       string
	nodeName        string
	nodeSubnet      string
	interfaceStore  agent.InterfaceStore
	ofClient        openflow.Client
	ovsBridgeClient ovsconfig.OVSBridgeClient
}

func NewControllerMonitor(client clientset.Interface) *controllerMonitor {
	return &controllerMonitor{client: client}
}

func NewAgentMonitor(client clientset.Interface, ovsBridge string, nodeName string, nodeSubnet string, interfaceStore agent.InterfaceStore, ofClient openflow.Client, ovsBridgeClient ovsconfig.OVSBridgeClient) *agentMonitor {
	return &agentMonitor{client: client, ovsBridge: ovsBridge, nodeName: nodeName, nodeSubnet: nodeSubnet, interfaceStore: interfaceStore, ofClient: ofClient, ovsBridgeClient: ovsBridgeClient}
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *controllerMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Controller Monitor")
	controllerCRD := monitor.getControllerCRD()
	var err error = nil
	for {
		if controllerCRD == nil {
			controllerCRD, err = monitor.createControllerCRD()
			if err != nil {
				klog.Errorf("Failed to create controller monitoring CRD %v : %v", controllerCRD, err)
			}
		} else {
			controllerCRD, err = monitor.updateControllerCRD(controllerCRD)
			if err != nil {
				klog.Errorf("Failed to update controller monitoring CRD %v : %v", controllerCRD, err)
			}
		}
		time.Sleep(60 * time.Second)
	}
	<-stopCh
}

// Run creates AntreaAgentInfo CRD first after controller is running.
// Then updates AntreaAgentInfo CRD every 60 seconds.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")
	agentCRD := monitor.getAgentCRD()
	var err error = nil
	for {
		if agentCRD == nil {
			agentCRD, err = monitor.createAgentCRD()
			if err != nil {
				klog.Errorf("Failed to create agent monitoring CRD %v : %v", agentCRD, err)
				break
			}
		} else {
			agentCRD, err = monitor.updateAgentCRD(agentCRD)
			if err != nil {
				klog.Errorf("Failed to update agent monitoring CRD %v : %v", agentCRD, err)
				break
			}
		}
		time.Sleep(60 * time.Second)
	}
	<-stopCh
}

// getControllerCRD is used to check the existence of controller monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *controllerMonitor) getControllerCRD() *v1beta1.AntreaControllerInfo {
	podName := monitor.GetSelfPod().Name
	controllerCRD, err := monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Get(podName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Controller monitoring CRD named %v doesn't exist, will create one", podName)
		return nil
	}
	return controllerCRD
}

func (monitor *controllerMonitor) createControllerCRD() (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: monitor.GetSelfPod().Name,
		},
		Version:    version.GetFullVersion(),
		PodRef:     monitor.GetSelfPod(),
		NodeRef:    monitor.GetSelfNode(),
		ServiceRef: monitor.GetService(),
		ControllerConditions: []v1beta1.ControllerCondition{
			{
				Type:              v1beta1.ControllerHealthy,
				Status:            v1.ConditionTrue,
				LastHeartbeatTime: metav1.Now(),
			},
		},
	}
	klog.V(2).Infof("Creating controller monitor CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Create(controllerCRD)
}

// TODO: Update network policy related fields when the upstreaming is ready
func (monitor *controllerMonitor) updateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	klog.V(2).Infof("Updating controller monitor CRD %v", controllerCRD)
	controllerCRD.ControllerConditions = []v1beta1.ControllerCondition{
		{
			Type:              v1beta1.ControllerHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD() *v1beta1.AntreaAgentInfo {
	podName := monitor.GetSelfPod().Name
	agentCRD, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Get(podName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Agent monitoring CRD named %v doesn't exist, will create one", podName)
		return nil
	}
	return agentCRD
}

func (monitor *agentMonitor) createAgentCRD() (*v1beta1.AntreaAgentInfo, error) {
	agentCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: monitor.GetSelfPod().Name,
		},
		Version:     version.GetFullVersion(),
		PodRef:      monitor.GetSelfPod(),
		NodeRef:     monitor.GetSelfNode(),
		NodeSubnet:  []string{monitor.nodeSubnet},
		OVSInfo:     v1beta1.OVSInfo{Version: monitor.GetOVSVersion(), BridgeName: monitor.ovsBridge, FlowTable: monitor.GetOVSFlowTable()},
		LocalPodNum: monitor.GetLocalPodNum(),
		AgentConditions: []v1beta1.AgentCondition{
			{
				Type:              v1beta1.AgentHealthy,
				Status:            v1.ConditionTrue,
				LastHeartbeatTime: metav1.Now(),
			},
		},
	}
	klog.V(2).Infof("Creating agent monitor CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Create(agentCRD)
}

func (monitor *agentMonitor) updateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	// LocalPodNum and FlowTable can be changed, so reset these fields.
	agentCRD.LocalPodNum = monitor.GetLocalPodNum()
	agentCRD.OVSInfo.FlowTable = monitor.GetOVSFlowTable()
	agentCRD.AgentConditions = []v1beta1.AgentCondition{
		{
			Type:              v1beta1.AgentHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
	klog.V(2).Infof("Updating agent monitor CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

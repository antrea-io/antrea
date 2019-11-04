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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/crd/antrea/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

type monitor interface {
	Run(stopCh <-chan struct{})
}

type controllerMonitor struct {
	client clientset.Interface
}

type agentMonitor struct {
	client         clientset.Interface
	ovsBridge      string
	nodeName       string
	nodeSubnet     string
	interfaceStore agent.InterfaceStore
	ofClient       openflow.Client
}

func NewControllerMonitor(client clientset.Interface) *controllerMonitor {
	return &controllerMonitor{client: client}
}

func NewAgentMonitor(client clientset.Interface, ovsBridge string, nodeName string, nodeSubnet string, interfaceStore agent.InterfaceStore, ofClient openflow.Client) *agentMonitor {
	return &agentMonitor{client: client, ovsBridge: ovsBridge, nodeName: nodeName, nodeSubnet: nodeSubnet, interfaceStore: interfaceStore, ofClient: ofClient}
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *controllerMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Controller Monitor")
	var controllerCRD *v1beta1.AntreaControllerInfo = nil
	var err error = nil
	for {
		if controllerCRD == nil {
			controllerCRD, err = monitor.createControllerCRD(controllerCRD)
			if err != nil {
				klog.Errorf("Failed to create controller monitor CRD %v : %v", controllerCRD, err)
			}
		} else {
			controllerCRD, err = monitor.updateControllerCRD(controllerCRD)
			if err != nil {
				klog.Errorf("Failed to update controller monitor CRD %v : %v", controllerCRD, err)
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
	var agentCRD *v1beta1.AntreaAgentInfo = nil
	var err error = nil
	for {
		if agentCRD == nil {
			agentCRD, err = monitor.createAgentCRD(agentCRD)
			if err != nil {
				klog.Errorf("Failed to create agent monitor CRD %v : %v", agentCRD, err)
				break
			}
		} else {
			agentCRD, err = monitor.updateAgentCRD(agentCRD)
			if err != nil {
				klog.Errorf("Failed to update agent monitor CRD %v : %v", agentCRD, err)
				break
			}
		}
		time.Sleep(60 * time.Second)
	}
	<-stopCh
}

func (monitor *controllerMonitor) createControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD = &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: monitor.GetSelfPod().Name,
		},
		Version:    version.GetFullVersion(),
		PodRef:     monitor.GetSelfPod(),
		NodeRef:    monitor.GetSelfNode(),
		ServiceRef: monitor.GetService(),
	}
	klog.V(2).Infof("Creating controller monitor CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Create(controllerCRD)
}

// TODO: Update network policy related fields when the upstreaming is ready
func (monitor *controllerMonitor) updateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	klog.V(2).Infof("Updating controller monitor CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

func (monitor *agentMonitor) createAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	agentCRD = &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: monitor.GetSelfPod().Name,
		},
		Version:     version.GetFullVersion(),
		PodRef:      monitor.GetSelfPod(),
		NodeRef:     monitor.GetSelfNode(),
		NodeSubnet:  []string{monitor.nodeSubnet},
		OVSInfo:     v1beta1.OVSInfo{BridgeName: monitor.ovsBridge, FlowTable: monitor.GetOVSFlowTable()},
		LocalPodNum: monitor.GetLocalPodNum(),
	}
	klog.V(2).Infof("Creating agent monitor CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Create(agentCRD)
}

func (monitor *agentMonitor) updateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	// LocalPodNum and FlowTable can be changed, so reset these fields.
	agentCRD.LocalPodNum = monitor.GetLocalPodNum()
	agentCRD.OVSInfo.FlowTable = monitor.GetOVSFlowTable()
	klog.V(2).Infof("Updating agent monitor CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

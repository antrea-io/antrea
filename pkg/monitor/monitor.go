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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
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
	client       clientset.Interface
	nodeInformer coreinformers.NodeInformer
	// nodeListerSynced is a function which returns true if the node shared informer has been synced at least once.
	nodeListerSynced cache.InformerSynced
}

type agentMonitor struct {
	client          clientset.Interface
	ovsBridge       string
	nodeName        string
	nodeSubnet      string
	interfaceStore  interfacestore.InterfaceStore
	ofClient        openflow.Client
	ovsBridgeClient ovsconfig.OVSBridgeClient
}

func NewControllerMonitor(client clientset.Interface, nodeInformer coreinformers.NodeInformer) monitor {
	m := &controllerMonitor{client: client, nodeInformer: nodeInformer, nodeListerSynced: nodeInformer.Informer().HasSynced}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nil,
		UpdateFunc: nil,
		DeleteFunc: m.deleteStaleAgentCRD,
	})

	return m
}

func NewAgentMonitor(
	client clientset.Interface,
	ovsBridge string,
	nodeName string,
	nodeSubnet string,
	interfaceStore interfacestore.InterfaceStore,
	ofClient openflow.Client,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
) monitor {
	return &agentMonitor{client: client, ovsBridge: ovsBridge, nodeName: nodeName, nodeSubnet: nodeSubnet, interfaceStore: interfaceStore, ofClient: ofClient, ovsBridgeClient: ovsBridgeClient}
}

// Run creates AntreaControllerInfo CRD first after controller is running.
// Then updates AntreaControllerInfo CRD every 60 seconds if there is any change.
func (monitor *controllerMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Controller Monitor")
	crdName := "antrea-controller"

	// Initialize controller monitoring CRD.
	controllerCRD := monitor.getControllerCRD(crdName)
	var err error = nil
	if controllerCRD == nil {
		controllerCRD, err = monitor.createControllerCRD(crdName)
		if err != nil {
			klog.Errorf("Failed to create controller monitoring CRD %v : %v", controllerCRD, err)
			return
		}
	} else {
		controllerCRD, err = monitor.updateControllerCRD(controllerCRD)
		if err != nil {
			klog.Errorf("Failed to update controller monitoring CRD %v : %v", controllerCRD, err)
			return
		}
	}

	klog.Info("Waiting for node synced for Controller Monitor")
	if !cache.WaitForCacheSync(stopCh, monitor.nodeListerSynced) {
		klog.Error("Unable to sync node for Controller Monitor")
		return
	}
	monitor.deleteStaleAgentCRDs()

	// Update controller monitoring CRD variables every 60 seconds util stopCh is closed.
	wait.PollUntil(60*time.Second, func() (done bool, err error) {
		controllerCRD, err = monitor.partialUpdateControllerCRD(controllerCRD)
		if err != nil {
			klog.Errorf("Failed to partially update controller monitoring CRD %v : %v", controllerCRD, err)
			return true, err
		}
		return false, nil
	}, stopCh)
}

// Run creates AntreaAgentInfo CRD first after controller is running.
// Then updates AntreaAgentInfo CRD every 60 seconds.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")
	crdName := monitor.GetSelfNode().Name
	agentCRD := monitor.getAgentCRD(crdName)
	var err error = nil

	// Initialize agent monitoring CRD.
	if agentCRD == nil {
		agentCRD, err = monitor.createAgentCRD(crdName)
		if err != nil {
			klog.Errorf("Failed to create agent monitoring CRD %v : %v", agentCRD, err)
			return
		}
	} else {
		agentCRD, err = monitor.updateAgentCRD(agentCRD)
		if err != nil {
			klog.Errorf("Failed to update agent monitoring CRD %v : %v", agentCRD, err)
			return
		}
	}

	// Update agent monitoring CRD variables every 60 seconds util stopCh is closed.
	wait.PollUntil(60*time.Second, func() (done bool, err error) {
		agentCRD, err = monitor.partialUpdateAgentCRD(agentCRD)
		if err != nil {
			klog.Errorf("Failed to partially update agent monitoring CRD %v : %v", agentCRD, err)
			return true, err
		}
		return false, nil
	}, stopCh)
}

// getControllerCRD is used to check the existence of controller monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *controllerMonitor) getControllerCRD(crdName string) *v1beta1.AntreaControllerInfo {
	controllerCRD, err := monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Get(crdName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Controller monitoring CRD named %s doesn't exist, will create one", crdName)
		return nil
	}
	return controllerCRD
}

func (monitor *controllerMonitor) createControllerCRD(crdName string) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
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
	klog.V(2).Infof("Creating controller monitoring CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Create(controllerCRD)
}

// updateControllerCRD updates all the fields of existing monitoring CRD.
func (monitor *controllerMonitor) updateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD.Version = version.GetFullVersion()
	controllerCRD.PodRef = monitor.GetSelfPod()
	controllerCRD.NodeRef = monitor.GetSelfNode()
	controllerCRD.ServiceRef = monitor.GetService()
	controllerCRD.ControllerConditions = []v1beta1.ControllerCondition{
		{
			Type:              v1beta1.ControllerHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
	klog.V(2).Infof("Updating controller monitoring CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

// partialUpdateControllerCRD only updates the variables.
func (monitor *controllerMonitor) partialUpdateControllerCRD(controllerCRD *v1beta1.AntreaControllerInfo) (*v1beta1.AntreaControllerInfo, error) {
	controllerCRD.ControllerConditions = []v1beta1.ControllerCondition{
		{
			Type:              v1beta1.ControllerHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
	klog.V(2).Infof("Partially updating controller monitoring CRD %v", controllerCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaControllerInfos().Update(controllerCRD)
}

func (monitor *controllerMonitor) deleteStaleAgentCRDs() {
	crds, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().List(metav1.ListOptions{})
	if err != nil {
		klog.Errorf("Failed to list agent monitoring CRDs : %v", err)
		return
	}
	// Delete stale agent monitoring CRD based on existing nodes.
	nodeLister := monitor.nodeInformer.Lister()
	for _, crd := range crds.Items {
		_, err := nodeLister.Get(crd.Name)
		if errors.IsNotFound(err) {
			monitor.deleteAgentCRD(crd.Name)
		}
	}
}

func (monitor *controllerMonitor) deleteStaleAgentCRD(old interface{}) {
	node := old.(*v1.Node)
	monitor.deleteAgentCRD(node.Name)
}

func (monitor *controllerMonitor) deleteAgentCRD(name string) {
	klog.Infof("Deleting agent monitoring CRD %s", name)
	err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Delete(name, &metav1.DeleteOptions{})
	if err != nil {
		klog.Errorf("Failed to delete agent monitoring CRD %s : %v", name, err)
	}
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD(crdName string) *v1beta1.AntreaAgentInfo {
	agentCRD, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Get(crdName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Agent monitoring CRD named %s doesn't exist, will create one", crdName)
		return nil
	}
	return agentCRD
}

func (monitor *agentMonitor) createAgentCRD(crdName string) (*v1beta1.AntreaAgentInfo, error) {
	agentCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
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
	klog.V(2).Infof("Creating agent monitoring CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Create(agentCRD)
}

// updateAgentCRD updates all the fields of existing monitoring CRD.
func (monitor *agentMonitor) updateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	agentCRD.Version = version.GetFullVersion()
	agentCRD.PodRef = monitor.GetSelfPod()
	agentCRD.NodeRef = monitor.GetSelfNode()
	agentCRD.NodeSubnet = []string{monitor.nodeSubnet}
	agentCRD.OVSInfo = v1beta1.OVSInfo{Version: monitor.GetOVSVersion(), BridgeName: monitor.ovsBridge, FlowTable: monitor.GetOVSFlowTable()}
	agentCRD.LocalPodNum = monitor.GetLocalPodNum()
	agentCRD.AgentConditions = []v1beta1.AgentCondition{
		{
			Type:              v1beta1.AgentHealthy,
			Status:            v1.ConditionTrue,
			LastHeartbeatTime: metav1.Now(),
		},
	}
	klog.V(2).Infof("Updating agent monitoring CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

// partialUpdateAgentCRD only updates the variables.
func (monitor *agentMonitor) partialUpdateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
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
	klog.V(2).Infof("Partially updating agent monitoring CRD %v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

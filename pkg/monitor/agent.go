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

package monitor

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

type agentMonitor struct {
	client  clientset.Interface
	querier agentquerier.AgentQuerier
}

// NewAgentMonitor creates a new agent monitor.
func NewAgentMonitor(client clientset.Interface, querier agentquerier.AgentQuerier) *agentMonitor {
	return &agentMonitor{client: client, querier: querier}
}

// Run creates AntreaAgentInfo CRD first after controller is running.
// Then updates AntreaAgentInfo CRD every 60 seconds.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")
	agentCRD := monitor.getAgentCRD()
	var err error = nil

	// Initialize agent monitoring CRD.
	if agentCRD == nil {
		agentCRD, err = monitor.createAgentCRD()
		if err != nil {
			klog.Errorf("Failed to create agent monitoring CRD %+v: %v", agentCRD, err)
			return
		}
	} else {
		agentCRD, err = monitor.updateAgentCRD(agentCRD)
		if err != nil {
			klog.Errorf("Failed to update agent monitoring CRD %+v: %v", agentCRD, err)
			return
		}
	}

	// Update agent monitoring CRD variables every 60 seconds util stopCh is closed.
	wait.PollUntil(60*time.Second, func() (done bool, err error) {
		agentCRD, err = monitor.partialUpdateAgentCRD(agentCRD)
		if err != nil {
			klog.Errorf("Failed to partially update agent monitoring CRD %+v: %v", agentCRD, err)
		}
		return false, nil
	}, stopCh)
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD() *v1beta1.AntreaAgentInfo {
	crdName := monitor.querier.GetNodeName()
	agentCRD, err := monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Get(crdName, metav1.GetOptions{})
	if err != nil {
		klog.V(2).Infof("Agent monitoring CRD named %s doesn't exist, will create one", crdName)
		return nil
	}
	return agentCRD
}

// createAgentCRD creates a new agent CRD.
func (monitor *agentMonitor) createAgentCRD() (*v1beta1.AntreaAgentInfo, error) {
	agentCRD := new(v1beta1.AntreaAgentInfo)
	monitor.querier.GetAgentInfo(agentCRD, false)
	klog.V(2).Infof("Creating agent monitoring CRD %+v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Create(agentCRD)
}

// updateAgentCRD updates all the fields of existing monitoring CRD.
func (monitor *agentMonitor) updateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	monitor.querier.GetAgentInfo(agentCRD, false)
	klog.V(2).Infof("Updating agent monitoring CRD %+v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

// partialUpdateAgentCRD only updates some variables.
func (monitor *agentMonitor) partialUpdateAgentCRD(agentCRD *v1beta1.AntreaAgentInfo) (*v1beta1.AntreaAgentInfo, error) {
	monitor.querier.GetAgentInfo(agentCRD, true)
	klog.V(2).Infof("Partially updating agent monitoring CRD %+v", agentCRD)
	return monitor.client.ClusterinformationV1beta1().AntreaAgentInfos().Update(agentCRD)
}

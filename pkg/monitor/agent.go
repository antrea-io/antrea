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
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

type agentMonitor struct {
	client  clientset.Interface
	querier agentquerier.AgentQuerier
	// apiCertData is not provided by the querier to avoid a circular dependency between
	// apiServer and querier.
	apiCertData []byte
	// agentCRD is the desired state of agent monitoring CRD which agentMonitor expects.
	agentCRD *v1beta1.AntreaAgentInfo
}

// NewAgentMonitor creates a new agent monitor.
func NewAgentMonitor(client clientset.Interface, querier agentquerier.AgentQuerier, apiCertData []byte) *agentMonitor {
	return &agentMonitor{
		client:      client,
		querier:     querier,
		apiCertData: apiCertData,
		agentCRD:    nil,
	}
}

// Run creates AntreaAgentInfo CRD first after controller is running.
// Then updates AntreaAgentInfo CRD every 60 seconds.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")

	// Sync agent monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncAgentCRD, time.Minute, stopCh)
}

func (monitor *agentMonitor) syncAgentCRD() {
	var err error
	if monitor.agentCRD != nil {
		if monitor.agentCRD, err = monitor.updateAgentCRD(true); err == nil {
			return
		}
		klog.ErrorS(err, "Failed to partially update agent monitoring CRD")
		monitor.agentCRD = nil
	}

	monitor.agentCRD, err = monitor.getAgentCRD()
	if err != nil {
		klog.ErrorS(err, "Failed to get agent monitoring CRD")
		monitor.agentCRD = nil
		return
	}

	monitor.agentCRD, err = monitor.updateAgentCRD(false)
	if err != nil {
		klog.ErrorS(err, "Failed to entirely update agent monitoring CRD")
		monitor.agentCRD = nil
	}
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD() (*v1beta1.AntreaAgentInfo, error) {
	crdName := monitor.querier.GetNodeConfig().Name
	klog.V(2).InfoS("Getting agent monitoring CRD", "name", crdName)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

// updateAgentCRD updates the monitoring CRD.
func (monitor *agentMonitor) updateAgentCRD(partial bool) (*v1beta1.AntreaAgentInfo, error) {
	monitor.querier.GetAgentInfo(monitor.agentCRD, partial)
	monitor.agentCRD.APICABundle = monitor.apiCertData
	klog.V(2).Infof("Updating agent monitoring CRD %+v, partial: %t", monitor.agentCRD, partial)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Update(context.TODO(), monitor.agentCRD, metav1.UpdateOptions{})
}

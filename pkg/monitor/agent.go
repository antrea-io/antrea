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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"

	agentquerier "github.com/vmware-tanzu/antrea/pkg/agent/querier"
	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1beta1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	legacyv1beta1 "github.com/vmware-tanzu/antrea/pkg/legacyapis/clusterinformation/v1beta1"
	legacyclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
)

type agentMonitor struct {
	client       clientset.Interface
	legacyClient legacyclientset.Interface
	querier      agentquerier.AgentQuerier
	// agentCRD is the desired state of agent monitoring CRD which agentMonitor expects.
	agentCRD *v1beta1.AntreaAgentInfo
	// legacyAgentCRD is the desired state of agent monitoring CRD which agentMonitor expects.
	legacyAgentCRD *legacyv1beta1.AntreaAgentInfo
}

// NewAgentMonitor creates a new agent monitor.
func NewAgentMonitor(client clientset.Interface,
	legacyClient legacyclientset.Interface,
	querier agentquerier.AgentQuerier) *agentMonitor {
	return &agentMonitor{
		client:         client,
		legacyClient:   legacyClient,
		querier:        querier,
		agentCRD:       nil,
		legacyAgentCRD: nil,
	}
}

// Run creates AntreaAgentInfo CRD first after controller is running.
// Then updates AntreaAgentInfo CRD every 60 seconds.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")

	// Sync agent monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncAgentCRD, time.Minute, stopCh)

	// Sync legacy agent monitoring CRD every minute util stopCh is closed.
	wait.Until(monitor.syncLegacyAgentCRD, time.Minute, stopCh)
}

func (monitor *agentMonitor) syncAgentCRD() {
	var err error = nil
	if monitor.agentCRD != nil {
		if monitor.agentCRD, err = monitor.updateAgentCRD(true); err == nil {
			return
		}
		klog.Errorf("Failed to partially update agent monitoring CRD: %v", err)
		monitor.agentCRD = nil
	}

	monitor.agentCRD, err = monitor.getAgentCRD()

	if errors.IsNotFound(err) {
		monitor.agentCRD, err = monitor.createAgentCRD()
		if err != nil {
			klog.Errorf("Failed to create agent monitoring CRD: %v", err)
			monitor.agentCRD = nil
		}
		return
	}

	if err != nil {
		klog.Errorf("Failed to get agent monitoring CRD: %v", err)
		monitor.agentCRD = nil
		return
	}

	monitor.agentCRD, err = monitor.updateAgentCRD(false)
	if err != nil {
		klog.Errorf("Failed to entirely update agent monitoring CRD: %v", err)
		monitor.agentCRD = nil
	}
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD() (*v1beta1.AntreaAgentInfo, error) {
	crdName := monitor.querier.GetNodeConfig().Name
	klog.V(2).Infof("Getting agent monitoring CRD %+v", crdName)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

// createAgentCRD creates a new agent CRD.
func (monitor *agentMonitor) createAgentCRD() (*v1beta1.AntreaAgentInfo, error) {
	agentCRD := new(v1beta1.AntreaAgentInfo)
	monitor.querier.GetAgentInfo(agentCRD, false)
	klog.V(2).Infof("Creating agent monitoring CRD %+v", agentCRD)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Create(context.TODO(), agentCRD, metav1.CreateOptions{})
}

// updateAgentCRD updates the monitoring CRD.
func (monitor *agentMonitor) updateAgentCRD(partial bool) (*v1beta1.AntreaAgentInfo, error) {
	monitor.querier.GetAgentInfo(monitor.agentCRD, partial)
	klog.V(2).Infof("Updating agent monitoring CRD %+v, partial: %t", monitor.agentCRD, partial)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Update(context.TODO(), monitor.agentCRD, metav1.UpdateOptions{})
}

func (monitor *agentMonitor) syncLegacyAgentCRD() {
	var err error = nil
	if monitor.legacyAgentCRD != nil {
		if monitor.legacyAgentCRD, err = monitor.updateLegacyAgentCRD(true); err == nil {
			return
		}
		klog.Errorf("Failed to partially update agent monitoring CRD: %v", err)
		monitor.legacyAgentCRD = nil
	}

	monitor.legacyAgentCRD, err = monitor.getLegacyAgentCRD()

	if errors.IsNotFound(err) {
		monitor.legacyAgentCRD, err = monitor.createLegacyAgentCRD()
		if err != nil {
			klog.Errorf("Failed to create agent monitoring CRD: %v", err)
			monitor.legacyAgentCRD = nil
		}
		return
	}

	if err != nil {
		klog.Errorf("Failed to get agent monitoring CRD: %v", err)
		monitor.legacyAgentCRD = nil
		return
	}

	monitor.legacyAgentCRD, err = monitor.updateLegacyAgentCRD(false)
	if err != nil {
		klog.Errorf("Failed to entirely update agent monitoring CRD: %v", err)
		monitor.legacyAgentCRD = nil
	}
}

// getLegacyAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getLegacyAgentCRD() (*legacyv1beta1.AntreaAgentInfo, error) {
	crdName := monitor.querier.GetNodeConfig().Name
	klog.V(2).Infof("Getting legacy agent monitoring CRD %+v", crdName)
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaAgentInfos().Get(context.TODO(), crdName, metav1.GetOptions{})
}

// createLegacyAgentCRD creates a new agent CRD.
func (monitor *agentMonitor) createLegacyAgentCRD() (*legacyv1beta1.AntreaAgentInfo, error) {
	agentCRD := new(v1beta1.AntreaAgentInfo)
	monitor.querier.GetAgentInfo(agentCRD, false)
	legacyAgentCRD := agentInfoDeepCopy(agentCRD)
	klog.V(2).Infof("Creating legacy agent monitoring CRD %+v", legacyAgentCRD)
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaAgentInfos().Create(context.TODO(), legacyAgentCRD, metav1.CreateOptions{})
}

// updateLegacyAgentCRD updates the monitoring CRD.
func (monitor *agentMonitor) updateLegacyAgentCRD(partial bool) (*legacyv1beta1.AntreaAgentInfo, error) {
	monitor.querier.GetAgentInfo(monitor.agentCRD, partial)
	monitor.legacyAgentCRD = agentInfoDeepCopy(monitor.agentCRD)
	klog.V(2).Infof("Updating legacy agent monitoring CRD %+v, partial: %t", monitor.legacyAgentCRD, partial)
	return monitor.legacyClient.ClusterinformationV1beta1().AntreaAgentInfos().Update(context.TODO(), monitor.legacyAgentCRD, metav1.UpdateOptions{})
}

func agentInfoDeepCopy(aa *v1beta1.AntreaAgentInfo) *legacyv1beta1.AntreaAgentInfo {
	laa := new(legacyv1beta1.AntreaAgentInfo)
	laa.Name = aa.Name
	laa.Version = aa.Version
	laa.PodRef = *aa.PodRef.DeepCopy()
	laa.NodeRef = *aa.NodeRef.DeepCopy()
	laa.NodeSubnets = aa.NodeSubnets
	laa.OVSInfo = *aa.OVSInfo.DeepCopy()
	laa.NetworkPolicyControllerInfo = *aa.NetworkPolicyControllerInfo.DeepCopy()
	laa.LocalPodNum = aa.LocalPodNum
	laa.AgentConditions = []v1beta1.AgentCondition{}
	for _, ac := range aa.AgentConditions {
		laa.AgentConditions = append(laa.AgentConditions, *ac.DeepCopy())
	}
	laa.APIPort = aa.APIPort
	return laa
}

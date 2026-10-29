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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/config"
	agentquerier "antrea.io/antrea/v2/pkg/agent/querier"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
)

type agentMonitor struct {
	nodeConfigStatusProvider   NodeConfigStatusProvider
	nodeConfigReportingEnabled bool
	client                     clientset.Interface
	querier                    agentquerier.AgentQuerier
	// apiCertData is not provided by the querier to avoid a circular dependency between
	// apiServer and querier.
	apiCertData []byte
	// agentCRD is the desired state of agent monitoring CRD which agentMonitor expects.
	agentCRD *v1beta1.AntreaAgentInfo
}

// NodeConfigStatusProvider exposes the latest node configuration reconciliation result.
type NodeConfigStatusProvider interface {
	GetAntreaNodeConfigStatus() *v1beta1.AntreaNodeConfigAgentStatus
	AntreaNodeConfigStatusUpdates() <-chan struct{}
}

// SetNodeConfigStatusProvider enables configuration status reporting before Run starts.
// Call it when AntreaNodeConfig and SecondaryNetwork are enabled, even if the provider is unavailable.
func (monitor *agentMonitor) SetNodeConfigStatusProvider(provider NodeConfigStatusProvider) {
	monitor.nodeConfigStatusProvider = provider
	monitor.nodeConfigReportingEnabled = true
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

// Run publishes AgentInfo updates every minute and on configuration status notifications.
func (monitor *agentMonitor) Run(stopCh <-chan struct{}) {
	klog.Info("Starting Antrea Agent Monitor")
	ctx := wait.ContextForChannel(stopCh)

	if monitor.nodeConfigStatusProvider == nil {
		wait.UntilWithContext(ctx, monitor.syncAgentCRD, time.Minute)
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	monitor.syncAgentCRD(ctx)
	for {
		select {
		case <-monitor.nodeConfigStatusProvider.AntreaNodeConfigStatusUpdates():
		case <-ticker.C:
		case <-stopCh:
			return
		}
		monitor.syncAgentCRD(ctx)
	}
}

func (monitor *agentMonitor) syncAgentCRD(ctx context.Context) {
	var err error
	if monitor.agentCRD != nil {
		if monitor.agentCRD, err = monitor.updateAgentCRD(ctx, true); err == nil {
			return
		}
		klog.ErrorS(err, "Failed to partially update agent monitoring CRD")
		monitor.agentCRD = nil
	}

	monitor.agentCRD, err = monitor.getAgentCRD(ctx)
	if err != nil {
		klog.ErrorS(err, "Failed to get agent monitoring CRD")
		monitor.agentCRD = nil
		return
	}

	monitor.agentCRD, err = monitor.updateAgentCRD(ctx, false)
	if err != nil {
		klog.ErrorS(err, "Failed to entirely update agent monitoring CRD")
		monitor.agentCRD = nil
	}
}

// getAgentCRD is used to check the existence of agent monitoring CRD.
// So when the pod restarts, it will update this monitoring CRD instead of creating a new one.
func (monitor *agentMonitor) getAgentCRD(ctx context.Context) (*v1beta1.AntreaAgentInfo, error) {
	crdName := monitor.querier.GetNodeConfig().Name
	klog.V(2).InfoS("Getting agent monitoring CRD", "name", crdName)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, crdName, metav1.GetOptions{})
}

// updateAgentCRD updates the monitoring CRD.
func (monitor *agentMonitor) updateAgentCRD(ctx context.Context, partial bool) (*v1beta1.AntreaAgentInfo, error) {
	var node *corev1.Node
	if monitor.querier.GetNodeConfig().Type == config.K8sNode && monitor.querier.GetNodeLister() != nil {
		var err error
		node, err = monitor.querier.GetNodeLister().Get(monitor.agentCRD.Name)
		if err != nil {
			return nil, err
		}
	}
	var previousReady *metav1.Condition
	if previous := monitor.agentCRD.NodeConfigStatus; previous != nil && previous.SecondaryNetwork != nil {
		previousReady = meta.FindStatusCondition(previous.SecondaryNetwork.Conditions, "Ready").DeepCopy()
	}
	monitor.querier.GetAgentInfo(monitor.agentCRD, partial)
	monitor.agentCRD.NodeConfigStatus = nil
	if monitor.nodeConfigStatusProvider != nil {
		monitor.agentCRD.NodeConfigStatus = monitor.nodeConfigStatusProvider.GetAntreaNodeConfigStatus().DeepCopy()
	}
	if node != nil {
		report := monitor.agentCRD.NodeConfigStatus
		var fallback *metav1.Condition
		switch {
		case !monitor.nodeConfigReportingEnabled:
			fallback = &metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse,
				Reason: "FeatureDisabled", Message: "AntreaNodeConfig or SecondaryNetwork is disabled on this Agent"}
		case node.Labels[corev1.LabelOSStable] == "windows":
			fallback = &metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse,
				Reason: "UnsupportedNode", Message: "Secondary network configuration is not supported on Windows Nodes"}
		case report == nil || report.SecondaryNetwork == nil || meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready") == nil:
			fallback = &metav1.Condition{Type: "Ready", Status: metav1.ConditionUnknown,
				Reason: "ConfigurationUnavailable", Message: "Agent configuration reconciliation is not available"}
		}
		if fallback != nil {
			// Unavailable feature data must not inherit a previous Ready or revision.
			// Disabled and unsupported reports also carry no selected configuration.
			if report == nil || fallback.Reason != "ConfigurationUnavailable" {
				report = &v1beta1.AntreaNodeConfigAgentStatus{}
			}
			report.SecondaryNetwork = &v1beta1.SecondaryNetworkStatus{}
			if previousReady != nil {
				report.SecondaryNetwork.Conditions = append(report.SecondaryNetwork.Conditions, *previousReady)
			}
			meta.SetStatusCondition(&report.SecondaryNetwork.Conditions, *fallback)
		}
		report.NodeUID, report.LastHeartbeatTime = node.UID, metav1.Now()
		monitor.agentCRD.NodeConfigStatus = report
	}
	monitor.agentCRD.APICABundle = monitor.apiCertData
	klog.V(2).InfoS("Updating agent monitoring CRD", "name", klog.KObj(monitor.agentCRD), "partial", partial)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Update(ctx, monitor.agentCRD, metav1.UpdateOptions{})
}

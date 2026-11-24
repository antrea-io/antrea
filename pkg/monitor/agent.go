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

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	"antrea.io/antrea/v2/pkg/agent/config"
	agentquerier "antrea.io/antrea/v2/pkg/agent/querier"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
)

type agentMonitor struct {
	secondaryNetworkStatusProvider   SecondaryNetworkStatusProvider
	antreaNodeConfigSnapshotProvider AntreaNodeConfigSnapshotProvider
	secondaryNetworkReportingEnabled bool
	client                           clientset.Interface
	querier                          agentquerier.AgentQuerier
	// apiCertData is not provided by the querier to avoid a circular dependency between
	// apiServer and querier.
	apiCertData []byte
	// agentCRD is the desired state of agent monitoring CRD which agentMonitor expects.
	agentCRD *v1beta1.AntreaAgentInfo
}

// SecondaryNetworkStatusProvider exposes the latest secondary network reconciliation result.
type SecondaryNetworkStatusProvider interface {
	GetSecondaryNetworkStatus() *agenttypes.SecondaryNetworkStatus
	SecondaryNetworkStatusUpdates() <-chan struct{}
}

// AntreaNodeConfigSnapshotProvider exposes the current target independently of feature progress.
type AntreaNodeConfigSnapshotProvider interface {
	GetAntreaNodeConfigSnapshot() *antreanodeconfig.Snapshot
	AntreaNodeConfigSnapshotUpdates() <-chan struct{}
}

// SetAntreaNodeConfigSnapshotProvider enables selected configuration reporting before Run starts.
func (monitor *agentMonitor) SetAntreaNodeConfigSnapshotProvider(provider AntreaNodeConfigSnapshotProvider) {
	monitor.antreaNodeConfigSnapshotProvider = provider
}

// SetSecondaryNetworkStatusProvider enables secondary network status reporting before Run starts.
// Call it when SecondaryNetwork is enabled, even if the provider is unavailable.
func (monitor *agentMonitor) SetSecondaryNetworkStatusProvider(provider SecondaryNetworkStatusProvider) {
	monitor.secondaryNetworkStatusProvider = provider
	monitor.secondaryNetworkReportingEnabled = true
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

	var featureUpdates, targetUpdates <-chan struct{}
	if monitor.secondaryNetworkStatusProvider != nil {
		featureUpdates = monitor.secondaryNetworkStatusProvider.SecondaryNetworkStatusUpdates()
	}
	if monitor.antreaNodeConfigSnapshotProvider != nil {
		targetUpdates = monitor.antreaNodeConfigSnapshotProvider.AntreaNodeConfigSnapshotUpdates()
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	retryDelay := time.Second
	retryTimer := time.NewTimer(time.Hour)
	if !retryTimer.Stop() {
		<-retryTimer.C
	}
	var retry <-chan time.Time
	syncAndScheduleRetry := func() {
		if monitor.syncAgentCRD(ctx) {
			retryDelay = time.Second
			retry = nil
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			return
		}
		if !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		retryTimer.Reset(retryDelay)
		retry = retryTimer.C
		if retryDelay < time.Minute/2 {
			retryDelay *= 2
		} else {
			retryDelay = time.Minute
		}
	}
	defer retryTimer.Stop()
	syncAndScheduleRetry()
	for {
		select {
		case <-featureUpdates:
		case <-targetUpdates:
		case <-ticker.C:
		case <-retry:
			retry = nil
		case <-stopCh:
			return
		}
		syncAndScheduleRetry()
	}
}

func (monitor *agentMonitor) syncAgentCRD(ctx context.Context) bool {
	var err error
	if monitor.agentCRD != nil {
		if monitor.agentCRD, err = monitor.updateAgentCRD(ctx, true); err == nil {
			return true
		}
		klog.ErrorS(err, "Failed to partially update agent monitoring CRD")
		monitor.agentCRD = nil
	}

	monitor.agentCRD, err = monitor.getAgentCRD(ctx)
	if err != nil {
		klog.ErrorS(err, "Failed to get agent monitoring CRD")
		monitor.agentCRD = nil
		return false
	}

	monitor.agentCRD, err = monitor.updateAgentCRD(ctx, false)
	if err != nil {
		klog.ErrorS(err, "Failed to entirely update agent monitoring CRD")
		monitor.agentCRD = nil
		return false
	}
	return true
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
	readyCondition := string(v1beta1.SecondaryNetworkConditionReady)
	var previousReady *metav1.Condition
	if previous := monitor.agentCRD.SecondaryNetwork; previous != nil {
		previousReady = meta.FindStatusCondition(previous.Conditions, readyCondition).DeepCopy()
	}
	previousANC := monitor.agentCRD.AntreaNodeConfig.DeepCopy()
	var snapshot *antreanodeconfig.Snapshot
	if monitor.antreaNodeConfigSnapshotProvider != nil {
		snapshot = monitor.antreaNodeConfigSnapshotProvider.GetAntreaNodeConfigSnapshot()
	}
	monitor.querier.GetAgentInfo(monitor.agentCRD, partial)
	monitor.agentCRD.SecondaryNetwork = nil
	var featureResult *agenttypes.SecondaryNetworkStatus
	if monitor.secondaryNetworkStatusProvider != nil && monitor.secondaryNetworkReportingEnabled {
		featureResult = monitor.secondaryNetworkStatusProvider.GetSecondaryNetworkStatus().DeepCopy()
		if featureResult != nil {
			monitor.agentCRD.SecondaryNetwork = featureResult.SecondaryNetworkStatus
		}
	}
	if node != nil {
		report := monitor.agentCRD.SecondaryNetwork
		var fallback *metav1.Condition
		switch {
		case node.Labels[corev1.LabelOSStable] == "windows":
			fallback = &metav1.Condition{Type: readyCondition, Status: metav1.ConditionFalse,
				Reason: "UnsupportedNode", Message: "Secondary network configuration is not supported on Windows Nodes"}
		case !monitor.secondaryNetworkReportingEnabled:
			fallback = &metav1.Condition{Type: readyCondition, Status: metav1.ConditionFalse,
				Reason: "FeatureDisabled", Message: "SecondaryNetwork is disabled on this Agent"}
		case report == nil || meta.FindStatusCondition(report.Conditions, readyCondition) == nil:
			fallback = &metav1.Condition{Type: readyCondition, Status: metav1.ConditionUnknown,
				Reason: "ConfigurationUnavailable", Message: "Agent configuration reconciliation is not available"}
		}
		if fallback != nil {
			// Unavailable feature data must not inherit a previous Ready or revision.
			// Disabled and unsupported reports also carry no selected configuration.
			if report == nil || fallback.Reason != "ConfigurationUnavailable" {
				report = &v1beta1.SecondaryNetworkStatus{}
			}
			report.CurrentBridge, report.DesiredBridge = "", ""
			report.Conditions = nil
			if previousReady != nil {
				report.Conditions = append(report.Conditions, *previousReady)
			}
			meta.SetStatusCondition(&report.Conditions, *fallback)
		}
		monitor.agentCRD.SecondaryNetwork = report
	}
	monitor.assembleAntreaNodeConfigStatus(snapshot, featureResult, previousReady, previousANC)
	monitor.agentCRD.APICABundle = monitor.apiCertData
	klog.V(2).InfoS("Updating agent monitoring CRD", "name", klog.KObj(monitor.agentCRD), "partial", partial)
	return monitor.client.CrdV1beta1().AntreaAgentInfos().Update(ctx, monitor.agentCRD, metav1.UpdateOptions{})
}

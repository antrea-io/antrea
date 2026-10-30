// Copyright 2026 Antrea Authors
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

package secondarynetwork

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// GetAntreaNodeConfigStatus returns an independent copy of the latest reconciliation result.
func (c *Controller) GetAntreaNodeConfigStatus() *crdv1beta1.AntreaNodeConfigAgentStatus {
	c.statusMutex.RLock()
	defer c.statusMutex.RUnlock()
	return c.nodeConfigStatus.DeepCopy()
}

// AntreaNodeConfigStatusUpdates signals that a new reconciliation result is available.
func (c *Controller) AntreaNodeConfigStatusUpdates() <-chan struct{} {
	return c.statusUpdates
}

func (c *Controller) updateNodeConfigStatus(snap *antreanodeconfig.Snapshot, desired *agenttypes.OVSBridgeConfig, err error) {
	feature := &crdv1beta1.SecondaryNetworkStatus{}
	report := &crdv1beta1.AntreaNodeConfigAgentStatus{SecondaryNetwork: feature}
	var generation int64
	if snap != nil && snap.AntreaNodeConfig != nil {
		cfg := snap.AntreaNodeConfig
		report.ConfigName, report.ConfigUID = cfg.Name, cfg.UID
		generation = cfg.Generation
	}
	if desired != nil {
		feature.DesiredBridge = desired.BridgeName
	}
	if c.ovsBridgeClient != nil {
		feature.CurrentBridge = c.ovsBridgeClient.GetBridgeName()
	}
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue,
		ObservedGeneration: generation, Reason: "Reconciled",
		Message: "Secondary network configuration has been realized"}
	available := snap != nil && snap.AntreaNodeConfigListError == ""
	switch {
	case !available:
		condition.Status, condition.Reason = metav1.ConditionUnknown, "ConfigurationUnavailable"
		condition.Message = "AntreaNodeConfig snapshot is unavailable"
		if snap != nil {
			condition.Message = snap.AntreaNodeConfigListError
		}
	case err != nil:
		condition.Status, condition.Reason, condition.Message = metav1.ConditionFalse, "ReconcileFailed", err.Error()
	}
	if available {
		switch {
		case snap.AntreaNodeConfig != nil && c.secNetConfig != nil && len(c.secNetConfig.OVSBridges) > 0:
			condition.Status, condition.Reason = metav1.ConditionFalse, "OverriddenByStaticConfig"
			condition.Message = "Static Agent secondary network configuration takes precedence over AntreaNodeConfig"
			if err != nil {
				condition.Message += "; static bridge reconciliation failed: " + err.Error()
			}
		case err == errStaleBridgeInUse:
			condition.Reason = "BridgeInUse"
			condition.Message = "Waiting for Pod secondary interfaces to be removed before deleting the bridge"
		}
	}
	c.statusMutex.Lock()
	if c.nodeConfigStatus != nil && c.nodeConfigStatus.SecondaryNetwork != nil {
		if previous := meta.FindStatusCondition(c.nodeConfigStatus.SecondaryNetwork.Conditions, "Ready"); previous != nil {
			feature.Conditions = append(feature.Conditions, *previous)
		}
	}
	meta.SetStatusCondition(&feature.Conditions, condition)
	c.nodeConfigStatus = report
	c.statusMutex.Unlock()
	select {
	case c.statusUpdates <- struct{}{}:
	default:
	}
}

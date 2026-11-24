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

package monitor

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

func (monitor *agentMonitor) assembleAntreaNodeConfigStatus(snapshot *antreanodeconfig.Snapshot,
	result *agenttypes.SecondaryNetworkStatus, previousReady *metav1.Condition, previous *v1beta1.AntreaNodeConfigStatus) {
	monitor.agentCRD.AntreaNodeConfig = nil
	report := monitor.agentCRD.SecondaryNetwork
	var ready *metav1.Condition
	if report != nil {
		ready = meta.FindStatusCondition(report.Conditions, "Ready")
	}
	available := snapshot != nil && snapshot.AntreaNodeConfigListError == ""
	var target *v1beta1.AntreaNodeConfigStatus
	var generation int64
	if available && snapshot.AntreaNodeConfig != nil {
		cfg := snapshot.AntreaNodeConfig
		target = &v1beta1.AntreaNodeConfigStatus{Name: cfg.Name, UID: cfg.UID}
		generation = cfg.Generation
	}

	// A public feature result with ANC source belongs to the common target. Its
	// internal UID must match too: generations restart when an ANC is recreated.
	if report != nil && report.ConfigSource == v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig &&
		(target == nil || result == nil || result.ConfigUID != target.UID || ready == nil ||
			ready.ObservedGeneration != generation) {
		condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionUnknown,
			Reason: "ConfigurationUnavailable", Message: "Waiting for reconciliation of the selected AntreaNodeConfig"}
		if !available {
			condition.Message = "AntreaNodeConfig snapshot is unavailable"
		}
		report.Conditions = nil
		if previousReady != nil {
			report.Conditions = []metav1.Condition{*previousReady}
		}
		meta.SetStatusCondition(&report.Conditions, condition)
		report.CurrentBridge, report.DesiredBridge = "", ""
		if target == nil {
			report.ConfigSource = ""
		}
		ready = meta.FindStatusCondition(report.Conditions, "Ready")
	}
	if target == nil {
		return
	}

	contribution := metav1.Condition{Status: metav1.ConditionUnknown, ObservedGeneration: generation}
	switch {
	case report != nil && report.ConfigSource == v1beta1.SecondaryNetworkConfigSourceAgentConfig:
		contribution.Status, contribution.Reason = metav1.ConditionFalse, "OverriddenByStaticConfig"
	case ready != nil && ready.Status == metav1.ConditionFalse &&
		(ready.Reason == "FeatureDisabled" || ready.Reason == "UnsupportedNode"):
		contribution.Status = metav1.ConditionFalse
	case report != nil && report.ConfigSource == v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig &&
		result != nil && result.ConfigUID == target.UID && ready != nil && ready.ObservedGeneration == generation:
		contribution = *ready
	}
	condition := aggregateFeatureConditions(generation, contribution)
	if previous != nil {
		if ready := meta.FindStatusCondition(previous.Conditions, "Ready"); ready != nil {
			target.Conditions = append(target.Conditions, *ready)
		}
	}
	meta.SetStatusCondition(&target.Conditions, condition)
	monitor.agentCRD.AntreaNodeConfig = target
}

func aggregateFeatureConditions(generation int64, features ...metav1.Condition) metav1.Condition {
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue,
		ObservedGeneration: generation, Reason: "Reconciled"}
	if len(features) == 0 {
		condition.Status, condition.Reason = metav1.ConditionUnknown, "WaitingForFeatureResults"
	}
	for _, feature := range features {
		if feature.ObservedGeneration != generation || feature.Status == metav1.ConditionUnknown || feature.Status == "" {
			if condition.Status == metav1.ConditionTrue {
				condition.Status, condition.Reason = metav1.ConditionUnknown, "WaitingForFeatureResults"
			}
			continue
		}
		if feature.Status == metav1.ConditionFalse {
			condition.Status = metav1.ConditionFalse
			if feature.Reason == "OverriddenByStaticConfig" || condition.Reason != "OverriddenByStaticConfig" {
				condition.Reason = "FeaturesNotReady"
				if feature.Reason == "OverriddenByStaticConfig" {
					condition.Reason = feature.Reason
				}
			}
		}
	}
	return condition
}

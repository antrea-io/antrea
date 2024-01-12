//go:build !linux
// +build !linux

// Copyright 2024 Antrea Authors
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

package networkpolicy

import (
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
)

type nodeReconciler struct{}

func newNodeReconciler(routeClient route.Interface, ipv4Enabled, ipv6Enabled bool) *nodeReconciler {
	return &nodeReconciler{}
}

func (r *nodeReconciler) Reconcile(rule *CompletedRule) error {
	return nil
}

func (r *nodeReconciler) BatchReconcile(rules []*CompletedRule) error {
	return nil
}

func (r *nodeReconciler) Forget(ruleID string) error {
	return nil
}

func (r *nodeReconciler) GetRuleByFlowID(ruleID uint32) (*types.PolicyRule, bool, error) {
	return nil, false, nil
}

func (r *nodeReconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {

}

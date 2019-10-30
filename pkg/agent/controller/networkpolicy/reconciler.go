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

package networkpolicy

import (
	"k8s.io/klog"
)

// Reconciler is an interface that knows how to reconcile the desired state of
// CompletedRule with the actual state of Openflow entries.
type Reconciler interface {
	// Reconcile reconciles the desired state of the provided CompletedRule
	// with the actual state of Openflow entries.
	Reconcile(rule *CompletedRule) error

	// Forget cleanups the actual state of Openflow entries of the specified ruleID.
	Forget(ruleID string) error
}

type NoopReconciler struct{}

func (r *NoopReconciler) Reconcile(rule *CompletedRule) error {
	klog.Infof("Reconciling rule %v", rule)
	return nil
}

func (r *NoopReconciler) Forget(ruleID string) error {
	klog.Infof("Forgetting rule %v", ruleID)
	return nil
}

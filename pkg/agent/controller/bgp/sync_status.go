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

package bgp

import (
	"fmt"

	"antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

// BGPPolicyNotAppliedError is returned by the query methods of Controller when a BGPPolicy selects the Node but could
// not be applied, so that there is no BGP server to query.
type BGPPolicyNotAppliedError struct {
	BGPPolicyName string
	Err           error
}

func (e *BGPPolicyNotAppliedError) Error() string {
	return fmt.Sprintf("BGPPolicy %s could not be applied: %v", e.BGPPolicyName, e.Err)
}

func (e *BGPPolicyNotAppliedError) Unwrap() error {
	return e.Err
}

// recordSyncResult records the name of the BGPPolicy that the last sync tried to apply, and the error that stopped it,
// if any, and records the Events that the result implies. The caller must hold bgpPolicyStateMutex.
func (c *Controller) recordSyncResult(effectivePolicy *v1alpha1.BGPPolicy, err error) {
	var policyName string
	switch {
	case effectivePolicy != nil:
		policyName = effectivePolicy.Name
	case c.bgpPolicyState != nil:
		// No BGPPolicy selects the Node any more, but the BGP server of the previous one could not be stopped.
		policyName = c.bgpPolicyState.bgpPolicyName
	}
	if policyName != c.lastSyncPolicyName {
		updateEffectivePolicyMetric(c.lastSyncPolicyName, policyName)
	}
	c.lastSyncPolicyName = policyName
	c.lastSyncError = err
	c.recordSyncEvents(effectivePolicy, err)
}

// noBGPServerError returns the error that the query methods report when there is no BGP server. The caller must hold
// bgpPolicyStateMutex.
func (c *Controller) noBGPServerError() error {
	// Without a BGP server, a sync error means that the BGPPolicy which selects the Node could not be applied.
	if c.lastSyncError != nil {
		return &BGPPolicyNotAppliedError{BGPPolicyName: c.lastSyncPolicyName, Err: c.lastSyncError}
	}
	return ErrBGPPolicyNotFound
}

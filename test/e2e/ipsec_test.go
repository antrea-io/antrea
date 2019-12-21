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

package e2e

import (
	"testing"
)

// TestIPSecTunnelConnectivity checks that Pod traffic across two Nodes over
// the IPSec tunnel, by creating multiple Pods across distinct Nodes and having
// them ping each other.
func TestIPSecTunnelConnectivity(t *testing.T) {
	if testOptions.providerName == "kind" {
		t.Skipf("Skipping test for the KIND provider as IPSec tunnel does not work with KIND")
	}
	if clusterInfo.numNodes < 2 {
		t.Skipf("Skipping test as it requires 2 different nodes")
	}

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Logf("Redeploy Antrea with IPSec tunnel enabled")
	data.redeployAntrea(t, true)

	data.testPodConnectivityDifferentNodes(t)

	// Restore normal Antrea deployment with IPSec disabled.
	data.redeployAntrea(t, false)
}

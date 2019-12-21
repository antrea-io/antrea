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
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
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

// TestIPSecDeleteStaleTunnelPorts checks that when switching from IPsec mode to
// non-encrypted mode, the previously created tunnel ports are deleted
// correctly.
func TestIPSecDeleteStaleTunnelPorts(t *testing.T) {
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

	nodeName0 := nodeName(0)
	nodeName1 := nodeName(1)
	antreaPodName := func() string {
		antreaPodName, err := data.getAntreaPodOnNode(nodeName0)
		if err != nil {
			t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", nodeName0, err)
		}
		t.Logf("The Antrea Pod for Node '%s' is '%s'", nodeName0, antreaPodName)
		return antreaPodName
	}
	portName := util.GenerateNodeTunnelInterfaceName(nodeName1)

	doesOVSPortExist := func() bool {
		exists, err := data.doesOVSPortExist(antreaPodName(), portName)
		if err != nil {
			t.Fatalf("Cannot determine if OVS port exists: %v", err)
		}
		return exists
	}

	t.Logf("Checking that tunnel port has been created")
	if err := wait.PollImmediate(1*time.Second, defaultTimeout, func() (found bool, err error) {
		return doesOVSPortExist(), nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be created")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be created")
	}

	t.Logf("Redeploy Antrea with IPSec tunnel disabled")
	data.redeployAntrea(t, false)

	t.Logf("Checking that tunnel port has been deleted")
	if err := wait.PollImmediate(1*time.Second, defaultTimeout, func() (found bool, err error) {
		return !doesOVSPortExist(), nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be deleted")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be	deleted")
	}
}

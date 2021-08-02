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
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/util"
)

// TestIPSec is the top-level test which contains all subtests for
// IPSec related test cases so they can share setup, teardown.
func TestIPSec(t *testing.T) {
	skipIfProviderIs(t, "kind", "IPSec tunnel does not work with Kind")
	skipIfIPv6Cluster(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testIPSecTunnelConnectivity", func(t *testing.T) { testIPSecTunnelConnectivity(t, data) })
	t.Run("testIPSecDeleteStaleTunnelPorts", func(t *testing.T) { testIPSecDeleteStaleTunnelPorts(t, data) })
}

func (data *TestData) readSecurityAssociationsStatus(nodeName string) (up int, connecting int, err error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return 0, 0, err
	}
	cmd := []string{"ipsec", "status"}
	stdout, stderr, err := data.runCommandFromPod(antreaNamespace, antreaPodName, "antrea-ipsec", cmd)
	if err != nil {
		return 0, 0, fmt.Errorf("error when running 'ipsec status' on '%s': %v - stdout: %s - stderr: %s", nodeName, err, stdout, stderr)
	}
	re := regexp.MustCompile(`Security Associations \((\d+) up, (\d+) connecting\)`)
	matches := re.FindStringSubmatch(stdout)
	if len(matches) == 0 {
		return 0, 0, fmt.Errorf("unexpected 'ipsec status' output: %s", stdout)
	}
	if v, err := strconv.ParseUint(matches[1], 10, 32); err != nil {
		return 0, 0, fmt.Errorf("error when retrieving 'up' SAs from 'ipsec status' output: %v", err)
	} else {
		up = int(v)
	}
	if v, err := strconv.ParseUint(matches[2], 10, 32); err != nil {
		return 0, 0, fmt.Errorf("error when retrieving 'connecting' SAs from 'ipsec status' output: %v", err)
	} else {
		connecting = int(v)
	}
	return up, connecting, nil
}

// testIPSecTunnelConnectivity checks that Pod traffic across two Nodes over
// the IPSec tunnel, by creating multiple Pods across distinct Nodes and having
// them ping each other.
func testIPSecTunnelConnectivity(t *testing.T, data *TestData) {
	t.Logf("Redeploy Antrea with IPSec tunnel enabled")
	data.redeployAntrea(t, true)

	data.testPodConnectivityDifferentNodes(t)

	// We know that testPodConnectivityDifferentNodes always creates a Pod on Node 0 for the
	// inter-Node ping test.
	nodeName := nodeName(0)
	if up, _, err := data.readSecurityAssociationsStatus(nodeName); err != nil {
		t.Errorf("Error when reading Security Associations: %v", err)
	} else if up == 0 {
		t.Errorf("Expected at least one 'up' Security Association, but got %d", up)
	} else {
		t.Logf("Found %d 'up' SecurityAssociation(s) for Node '%s'", up, nodeName)
	}

	// Restore normal Antrea deployment with IPSec disabled.
	data.redeployAntrea(t, false)
}

// testIPSecDeleteStaleTunnelPorts checks that when switching from IPsec mode to
// non-encrypted mode, the previously created tunnel ports are deleted
// correctly.
func testIPSecDeleteStaleTunnelPorts(t *testing.T, data *TestData) {
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
	if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (found bool, err error) {
		return doesOVSPortExist(), nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be created")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be created")
	}

	t.Logf("Redeploy Antrea with IPSec tunnel disabled")
	data.redeployAntrea(t, false)

	t.Logf("Checking that tunnel port has been deleted")
	if err := wait.PollImmediate(defaultInterval, defaultTimeout, func() (found bool, err error) {
		return !doesOVSPortExist(), nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be deleted")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be	deleted")
	}
}

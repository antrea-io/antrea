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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/util"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
)

// TestIPSec is the top-level test which contains all subtests for
// IPsec related test cases so they can share setup, teardown.
func TestIPSec(t *testing.T) {
	skipIfIPv6Cluster(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfHasWindowsNodes(t)
	skipIfAntreaIPAMTest(t)
	skipIfProviderIs(t, "kind", "IPsec tests take too long to run and do not work with multiple Docker bridges")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Logf("Redeploy Antrea with IPsec tunnel enabled")
	data.redeployAntrea(t, deployAntreaIPsec)
	// Restore normal Antrea deployment with IPsec disabled.
	defer data.redeployAntrea(t, deployAntreaDefault)

	t.Run("testIPSecPSKAuth", func(t *testing.T) {
		conf, err := data.getAgentConf(antreaNamespace)
		failOnError(err, t)
		if conf.IPsec.AuthenticationMode != "psk" {
			t.Logf("Restarting Antrea Agent with IPsec PSK authentication mode. Current mode: %s", conf.IPsec.AuthenticationMode)
			ac := func(config *agentconfig.AgentConfig) {
				config.IPsec.AuthenticationMode = "psk"
			}
			if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
				t.Fatalf("Failed to change IPsec authentication mode to PSK: %v", err)
			}
		}
		t.Run("testIPSecTunnelConnectivity", func(t *testing.T) { testIPSecTunnelConnectivity(t, data, false) })
	})

	t.Run("testIPSecCertificateAuth", func(t *testing.T) {
		skipIfFeatureDisabled(t, features.IPsecCertAuth, true, true)
		conf, err := data.getAgentConf(antreaNamespace)
		failOnError(err, t)
		if conf.IPsec.AuthenticationMode != "cert" {
			t.Logf("Restarting Antrea Agent with IPsec Certificate authentication mode. Current mode: %s", conf.IPsec.AuthenticationMode)
			ac := func(config *agentconfig.AgentConfig) {
				config.IPsec.AuthenticationMode = "cert"
			}
			if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
				t.Fatalf("Failed to change IPsec authentication mode to Certificate: %v", err)
			}
		}
		t.Run("testIPSecTunnelConnectivity", func(t *testing.T) { testIPSecTunnelConnectivity(t, data, true) })
	})

	t.Run("testIPSecDeleteStaleTunnelPorts", func(t *testing.T) { testIPSecDeleteStaleTunnelPorts(t, data) })
}

func (data *TestData) readSecurityAssociationsStatus(nodeName string) (up int, connecting int, isCertAuth bool, err error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return 0, 0, false, err
	}
	cmd := []string{"ipsec", "statusall"}
	stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-ipsec", cmd)
	if err != nil {
		return 0, 0, false, fmt.Errorf("error when running 'ipsec status' on '%s': %v - stdout: %s - stderr: %s", nodeName, err, stdout, stderr)
	}
	re := regexp.MustCompile(`Security Associations \((\d+) up, (\d+) connecting\)`)
	matches := re.FindStringSubmatch(stdout)
	if len(matches) == 0 {
		return 0, 0, false, fmt.Errorf("unexpected 'ipsec statusall' output: %s", stdout)
	}
	v, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		return 0, 0, false, fmt.Errorf("error when retrieving 'up' SAs from 'ipsec statusall' output: %v", err)
	}
	up = int(v)
	v, err = strconv.ParseUint(matches[2], 10, 32)
	if err != nil {
		return 0, 0, false, fmt.Errorf("error when retrieving 'connecting' SAs from 'ipsec statusall' output: %v", err)
	}
	connecting = int(v)

	re = regexp.MustCompile(`uses ([a-z-]+) key authentication`)
	match := re.FindStringSubmatch(stdout)
	if len(match) == 0 {
		return 0, 0, false, fmt.Errorf("failed to determine authentication method from 'ipsec statusall' output: %s", stdout)
	}

	if match[1] == "pre-shared" {
		isCertAuth = false
	} else if match[1] == "public" {
		isCertAuth = true
	} else {
		return 0, 0, false, fmt.Errorf("unknown key authentication mode %q", match[1])
	}

	return up, connecting, isCertAuth, nil
}

// testIPSecTunnelConnectivity checks that Pod traffic across two Nodes over
// the IPsec tunnel, by creating multiple Pods across distinct Nodes and having
// them ping each other.
func testIPSecTunnelConnectivity(t *testing.T, data *TestData, certAuth bool) {
	var tag string
	if certAuth {
		tag = "ipsec-cert"
	} else {
		tag = "ipsec-psk"
	}
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, data.testNamespace, tag)
	defer deletePods()
	t.Logf("Executing ping tests across Nodes: '%s' <-> '%s'", podInfos[0].NodeName, podInfos[1].NodeName)
	// PMTU is wrong when using GRE+IPsec with some Linux kernel versions, do not set DF to work around.
	// See https://github.com/antrea-io/antrea/issues/5922 for more details.
	data.runPingMesh(t, podInfos[:2], toolboxContainerName, false)

	// Check that there is at least one 'up' Security Association on the Node
	nodeName := podInfos[0].NodeName
	if up, _, isCertAuth, err := data.readSecurityAssociationsStatus(nodeName); err != nil {
		t.Errorf("Error when reading Security Associations: %v", err)
	} else if up == 0 {
		t.Errorf("Expected at least one 'up' Security Association, but got %d", up)
	} else if isCertAuth != certAuth {
		t.Errorf("Expected certificate authentication to be %t, got %t", certAuth, isCertAuth)
	} else {
		t.Logf("Found %d 'up' SecurityAssociation(s) for Node '%s', certificate auth: %t", up, nodeName, isCertAuth)
	}
}

// testIPSecDeleteStaleTunnelPorts checks that when switching from IPsec mode to
// non-encrypted mode, the previously created tunnel ports are deleted
// correctly.
func testIPSecDeleteStaleTunnelPorts(t *testing.T, data *TestData) {

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
	if err := wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, true, func(ctx context.Context) (found bool, err error) {
		return doesOVSPortExist(), nil
	}); wait.Interrupted(err) {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be created")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be created")
	}

	t.Logf("Redeploy Antrea with IPsec tunnel disabled")
	data.redeployAntrea(t, deployAntreaDefault)

	t.Logf("Checking that tunnel port has been deleted")
	if err := wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, true, func(ctx context.Context) (found bool, err error) {
		return !doesOVSPortExist(), nil
	}); wait.Interrupted(err) {
		t.Fatalf("Timed out while waiting for OVS tunnel port to be deleted")
	} else if err != nil {
		t.Fatalf("Error while waiting for OVS tunnel port to be	deleted")
	}
}

// Copyright 2021 Antrea Authors
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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/agent/config"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
)

var (
	testIPPoolv4 = &crdv1alpha2.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ippool-ipv4",
		},
		Spec: crdv1alpha2.IPPoolSpec{
			IPVersion: crdv1alpha2.IPv4,
			IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
				CIDR: "10.123.1.0/24",
			},
				SubnetInfo: crdv1alpha2.SubnetInfo{
					Gateway:      "10.123.1.254",
					PrefixLength: 24,
				}}},
		},
	}

	testIPPoolv6 = &crdv1alpha2.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ippool-ipv6",
		},
		Spec: crdv1alpha2.IPPoolSpec{
			IPVersion: crdv1alpha2.IPv6,
			IPRanges: []crdv1alpha2.SubnetIPRange{{IPRange: crdv1alpha2.IPRange{
				Start: "3ffe:ffff:1:01ff::0101",
				End:   "3ffe:ffff:1:01ff::0200",
			},
				SubnetInfo: crdv1alpha2.SubnetInfo{
					Gateway:      "3ffe:ffff:1:01ff::1",
					PrefixLength: 64,
				}}},
		},
	}

	cniCmd = "/opt/cni/bin/antrea"

	cniEnvs = map[string]string{
		"CNI_CONTAINERID": "test-container-id",
		"CNI_NETNS":       "/var/run/netns/test-netns",
		"CNI_PATH":        "/opt/cni/bin",
		"CNI_ARGS":        "K8S_POD_NAMESPACE=test-namespace;K8S_POD_NAME=test-pod",
	}

	cniNetworkConfig = `{
    "cniVersion": "0.3.0",
    "name": "test",
    "type": "test-cni",
    "keyA": ["some more", "plugin specific", "configuration"],
    "ipam": {
        "type": "antrea",
        "ippools": [ "test-ippool-ipv4", "test-ippool-ipv6" ],
        "routes": [
            { "dst": "0.0.0.0/0" },
            { "dst": "192.168.0.0/16", "gw": "10.10.5.1" },
            { "dst": "3ffe:ffff:0:01ff::1/64" }
        ],
        "dns": {
            "nameservers" : ["8.8.8.8"],
            "domain": "example.com",
            "search": [ "example.com" ]
        }
    }
}`

	testOutput1 = `{
    "ips": [
        {
            "version": "4",
            "address": "10.123.1.1/24",
            "gateway": "10.123.1.254"
        },
        {
            "version": "6",
            "address": "3ffe:ffff:1:1ff::101/64",
            "gateway": "3ffe:ffff:1:1ff::1"
        }
    ],
    "routes": [
        {
            "dst": "0.0.0.0/0"
        },
        {
            "dst": "192.168.0.0/16",
            "gw": "10.10.5.1"
        },
        {
            "dst": "3ffe:ffff:0:1ff::1/64"
        }
    ],
    "dns": {
        "nameservers": [
            "8.8.8.8"
        ],
        "domain": "example.com",
        "search": [
            "example.com"
        ]
    }
}`

	testOutput2 = `{
    "ips": [
        {
            "version": "4",
            "address": "10.123.1.2/24",
            "gateway": "10.123.1.254"
        },
        {
            "version": "6",
            "address": "3ffe:ffff:1:1ff::102/64",
            "gateway": "3ffe:ffff:1:1ff::1"
        }
    ],
    "routes": [
        {
            "dst": "0.0.0.0/0"
        },
        {
            "dst": "192.168.0.0/16",
            "gw": "10.10.5.1"
        },
        {
            "dst": "3ffe:ffff:0:1ff::1/64"
        }
    ],
    "dns": {
        "nameservers": [
            "8.8.8.8"
        ],
        "domain": "example.com",
        "search": [
            "example.com"
        ]
    }
}`
)

func executeCNI(t *testing.T, data *TestData, add, del bool, ifName string, expectedExitCode int, expectedOutput string) {
	var code int
	var stdout, stderr string
	var err error

	t.Logf("Execute CNI for interface %s, ADD %v, DEL %v", ifName, add, del)

	cniEnvs["CNI_IFNAME"] = ifName
	defer delete(cniEnvs, "CNI_IFNAME")
	if add {
		cniEnvs["CNI_COMMAND"] = "ADD"
		defer delete(cniEnvs, "ADD")
		// antrea CNI needs to be executed as root to connect to the antrea-agent CNI
		// socket, so set sudo.
		code, stdout, stderr, err = data.RunCommandOnNodeExt(nodeName(0), cniCmd, cniEnvs, cniNetworkConfig, true)
		if err != nil {
			t.Fatalf("Failed to execute CNI ADD: %v", err)
		}
		if code != expectedExitCode {
			t.Fatalf("CNI ADD exits with code %d, expected %d, stdout:\n%s\nstderr: %s", code, expectedExitCode, stdout, stderr)
		}
		if expectedExitCode == 0 && stdout != expectedOutput {
			t.Fatalf("CNI ADD output:\n%s\nexpected:\n%s", stdout, expectedOutput)
		}
	}
	if del {
		cniEnvs["CNI_COMMAND"] = "DEL"
		defer delete(cniEnvs, "DEL")
		code, stdout, stderr, err = data.RunCommandOnNodeExt(nodeName(0), cniCmd, cniEnvs, cniNetworkConfig, true)
		if err != nil {
			t.Fatalf("Failed to execute CNI DEL: %v", err)
		}
		if code != 0 {
			t.Fatalf("CNI DEL exits with code %d, stdout:\n%s\nstderr: %s", code, stdout, stderr)
		}
	}
}

// Test secondary network IPAM by executing Antrea CNI with forged CNI arguments
// and network configuration, and validating the CNI command output. Do not
// really install Multus and create secondary networks.
func TestSecondaryNetworkIPAM(t *testing.T) {
	skipIfHasWindowsNodes(t)
	// The test is about IPAM for secondary network, which should not be
	// impacted by other modes and configurations, such as encap mode,
	// AntreaProxy, IPv6, etc., so we skip those cases.
	skipIfProxyDisabled(t)
	skipIfNotIPv4Cluster(t)
	skipIfAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	cc := func(config *controllerconfig.ControllerConfig) {
		config.FeatureGates["AntreaIPAM"] = true
	}
	ac := func(config *agentconfig.AgentConfig) {
		config.FeatureGates["AntreaIPAM"] = true
	}
	if err = data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable AntreaIPAM feature: %v", err)
	}

	_, err = data.crdClient.CrdV1alpha2().IPPools().Create(context.TODO(), testIPPoolv4, metav1.CreateOptions{})
	defer deleteIPPoolWrapper(t, data, testIPPoolv4.Name)
	if err != nil {
		t.Fatalf("Failed to create v4 IPPool CR: %v", err)
	}
	_, err = data.crdClient.CrdV1alpha2().IPPools().Create(context.TODO(), testIPPoolv6, metav1.CreateOptions{})
	defer deleteIPPoolWrapper(t, data, testIPPoolv6.Name)
	if err != nil {
		t.Fatalf("Failed to create v6 IPPool CR: %v", err)
	}

	// DEL non-existing network. Should return no error.
	// XXX executeCNI(t, data, false, true, "net1", 0, "")
	// Allocate the first IP.
	executeCNI(t, data, true, false, "net1", 0, testOutput1)
	// CNI ADD retry should return the same result.
	executeCNI(t, data, true, false, "net1", 0, testOutput1)
	// Allocate the second IP, and then DEL.
	executeCNI(t, data, true, true, "net2", 0, testOutput2)
	// The second IP should be re-allocated, as it was releaed with the previous CNI DEL.
	executeCNI(t, data, true, true, "net3", 0, testOutput2)
	// Release the first IP.
	executeCNI(t, data, false, true, "net1", 0, "")
}

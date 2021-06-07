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
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/apis"
)

const (
	cipherSuite    = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 // a TLS1.2 Cipher Suite
	cipherSuiteStr = "ECDHE-RSA-AES128-GCM-SHA256"
)

var (
	cipherSuites             = []uint16{cipherSuite}
	opensslTLS13CipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
)

// TestAntreaApiserverTLSConfig tests Cipher Suite and TLSVersion config on Antrea apiserver, Controller side or Agent side.
func TestAntreaApiserverTLSConfig(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	data.configureTLS(t, cipherSuites, "VersionTLS12")

	controllerPod, err := data.getAntreaController()
	assert.NoError(t, err, "failed to get Antrea Controller Pod")
	controllerPodName := controllerPod.Name
	controlPlaneNode := controlPlaneNodeName()
	agentPodName, err := data.getAntreaPodOnNode(controlPlaneNode)
	assert.NoError(t, err, "failed to get Antrea Agent Pod Name on Control Plane Node")

	tests := []struct {
		name          string
		podName       string
		containerName string
		apiserver     int
		apiserverStr  string
	}{
		{"ControllerApiserver", controllerPodName, controllerContainerName, apis.AntreaControllerAPIPort, "Controller"},
		{"AgentApiserver", agentPodName, agentContainerName, apis.AntreaAgentAPIPort, "Agent"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data.checkTLS(t, tc.podName, tc.containerName, tc.apiserver, tc.apiserverStr)
		})
	}
}

func (data *TestData) configureTLS(t *testing.T, cipherSuites []uint16, tlsMinVersion string) {
	var cipherSuitesStr string
	for i, cs := range cipherSuites {
		cipherSuitesStr = fmt.Sprintf("%s%s", cipherSuitesStr, tls.CipherSuiteName(cs))
		if i != len(cipherSuites)-1 {
			cipherSuitesStr = fmt.Sprintf("%s,", cipherSuitesStr)
		}
	}

	cc := []configChange{
		{"tlsCipherSuites", cipherSuitesStr, false},
		{"tlsMinVersion", tlsMinVersion, false},
	}
	ac := []configChange{
		{"tlsCipherSuites", cipherSuitesStr, false},
		{"tlsMinVersion", tlsMinVersion, false},
	}
	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to configure Cipher Suites and TLSMinVersion: %v", err)
	}
}

func (data *TestData) checkTLS(t *testing.T, podName string, containerName string, apiserver int, apiserverStr string) {
	// 1. TLSMaxVersion unset, then a TLS1.3 Cipher Suite should be used.
	stdouts := data.opensslConnect(t, podName, containerName, false, apiserver)
	for _, stdout := range stdouts {
		oneTLS13CS := false
		for _, cs := range opensslTLS13CipherSuites {
			if strings.Contains(stdout, fmt.Sprintf("New, TLSv1.3, Cipher is %s", cs)) {
				oneTLS13CS = true
				break
			}
		}
		assert.True(t, oneTLS13CS,
			"Cipher Suite used by %s apiserver should be a TLS1.3 one, output: %s", apiserverStr, stdout)
	}

	// 2. Set TLSMaxVersion to TLS1.2, then TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be used
	stdouts = data.opensslConnect(t, podName, containerName, true, apiserver)
	for _, stdout := range stdouts {
		assert.True(t, strings.Contains(stdout, fmt.Sprintf("New, TLSv1.2, Cipher is %s", cipherSuiteStr)),
			"Cipher Suite used by %s apiserver should be the TLS1.2 one '%s', output: %s", apiserverStr, cipherSuiteStr, stdout)
	}
}

func (data *TestData) opensslConnect(t *testing.T, pod string, container string, tls12 bool, port int) []string {
	var stdouts []string
	opensslConnectCommands := []struct {
		enabled bool
		ip      string
		option  string
	}{
		{
			clusterInfo.podV4NetworkCIDR != "",
			"127.0.0.1",
			"-4",
		},
		{
			clusterInfo.podV6NetworkCIDR != "",
			"::1",
			"-6",
		},
	}
	for _, c := range opensslConnectCommands {
		if !c.enabled {
			continue
		}
		cmd := []string{"timeout", "1", "openssl", "s_client", "-connect", net.JoinHostPort(c.ip, fmt.Sprint(port)), c.option}
		if tls12 {
			cmd = append(cmd, "-tls1_2")
		}
		stdout, stderr, err := data.runCommandFromPod(antreaNamespace, pod, container, cmd)
		assert.NoError(t, err, "failed to run openssl command on Pod '%s'\nstderr: %s", pod, stderr)
		t.Logf("Ran '%s' on Pod %s", strings.Join(cmd, " "), pod)
		stdouts = append(stdouts, stdout)
	}
	return stdouts
}

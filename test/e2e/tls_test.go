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
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/apis"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
)

const (
	cipherSuite    = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 // a TLS1.2 Cipher Suite
	cipherSuiteStr = "ECDHE-RSA-AES128-GCM-SHA256"
)

var (
	cipherSuites          = []uint16{cipherSuite}
	curlTLS13CipherSuites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
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
	controllerPodNode := controllerPod.Spec.NodeName
	node := getNodeByName(controllerPodNode)
	require.NotNil(t, node, "failed to get the Node")
	nodeIPv4 := node.ipv4Addr
	nodeIPv6 := node.ipv6Addr
	clientPodName, _, cleanupFunc := createAndWaitForPod(t, data, data.createToolboxPodOnNode, "client", controllerPodNode, data.testNamespace, true)
	defer cleanupFunc()

	tests := []struct {
		name         string
		apiserver    int
		apiserverStr string
	}{
		{"ControllerApiserver", apis.AntreaControllerAPIPort, "Controller"},
		{"AgentApiserver", apis.AntreaAgentAPIPort, "Agent"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data.checkTLS(t, clientPodName, toolboxContainerName, tc.apiserver, tc.apiserverStr, nodeIPv4, nodeIPv6)
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

	cc := func(config *controllerconfig.ControllerConfig) {
		config.TLSCipherSuites = cipherSuitesStr
		config.TLSMinVersion = tlsMinVersion
	}
	ac := func(config *agentconfig.AgentConfig) {
		config.TLSCipherSuites = cipherSuitesStr
		config.TLSMinVersion = tlsMinVersion
	}
	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to configure Cipher Suites and TLSMinVersion: %v", err)
	}
}

func (data *TestData) checkTLS(t *testing.T, podName string, containerName string, apiserver int, apiserverStr string, dstIPv4, dstIPv6 string) {
	// 1. TLSMaxVersion unset, then a TLS1.3 Cipher Suite should be used.
	stdouts := data.curlTestTLS(t, podName, containerName, false, apiserver, dstIPv4, dstIPv6)
	for _, stdout := range stdouts {
		oneTLS13CS := false
		for _, cs := range curlTLS13CipherSuites {
			if strings.Contains(stdout, fmt.Sprintf("SSL connection using TLSv1.3 / %s", cs)) {
				oneTLS13CS = true
				break
			}
		}
		assert.True(t, oneTLS13CS,
			"Cipher Suite used by %s apiserver should be a TLS1.3 one, output: %s", apiserverStr, stdout)
	}

	// 2. Set TLSMaxVersion to TLS1.2, then TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be used
	stdouts = data.curlTestTLS(t, podName, containerName, true, apiserver, dstIPv4, dstIPv6)
	for _, stdout := range stdouts {
		assert.True(t, strings.Contains(stdout, fmt.Sprintf("SSL connection using TLSv1.2 / %s", cipherSuiteStr)),
			"Cipher Suite used by %s apiserver should be the TLS1.2 one '%s', output: %s", apiserverStr, cipherSuiteStr, stdout)
	}
}

func (data *TestData) curlTestTLS(t *testing.T, pod string, container string, tls12 bool, port int, dstIPv4, dstIPv6 string) []string {
	var out []string
	for _, ip := range []string{dstIPv4, dstIPv6} {
		if ip == "" {
			continue
		}
		cmd := []string{"curl", "-k", "-v", "--head", fmt.Sprintf("https://%s", net.JoinHostPort(ip, fmt.Sprint(port)))}
		if tls12 {
			cmd = append(cmd, "--tls-max", "1.2", "--tlsv1.2")
		}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, pod, container, cmd)
		assert.NoError(t, err, "failed to run curl command on Pod '%s'\nstdout: %s", pod, stdout)
		t.Logf("Ran '%s' on Pod %s", strings.Join(cmd, " "), pod)
		// Collect stderr as all TLS-related details such as the cipher suite are present in stderr.
		out = append(out, stderr)
	}
	return out
}

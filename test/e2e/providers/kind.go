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

package providers

import (
	"fmt"
	"os"
	"path"
	"strings"

	"antrea.io/antrea/test/e2e/providers/exec"
)

type KindProvider struct {
	controlPlaneNodeName string
}

func (provider *KindProvider) RunCommandOnControlPlaneNode(cmd string) (
	code int, stdout string, stderr string, err error,
) {
	return exec.RunDockerExecCommand(provider.controlPlaneNodeName, cmd, "/root", nil, "")
}

func (provider *KindProvider) RunCommandOnNode(nodeName string, cmd string) (
	code int, stdout string, stderr string, err error,
) {
	return exec.RunDockerExecCommand(nodeName, cmd, "/root", nil, "")
}

func (provider *KindProvider) RunCommandOnNodeExt(nodeName, cmd string, envs map[string]string, stdin string, sudo bool) (
	code int, stdout string, stderr string, err error,
) {
	// sudo is not needed for Docker exec, so ignore the argument.
	return exec.RunDockerExecCommand(nodeName, cmd, "/root", envs, stdin)
}

func (provider *KindProvider) GetKubeconfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error when retrieving user home directory: %v", err)
	}
	kubeconfigPath := path.Join(homeDir, ".kube", "config")
	if _, err := os.Stat(kubeconfigPath); os.IsNotExist(err) {
		return "", fmt.Errorf("Kubeconfig file not found at expected location '%s'", kubeconfigPath)
	}
	return kubeconfigPath, nil
}

// enableKubectlOnControlPlane copies the Kubeconfig file on the Kind control-plane / control-plane Node to the
// default location, in order to make sure that we can run kubectl on the Node.
func (provider *KindProvider) enableKubectlOnControlPlane() error {
	rc, stdout, _, err := provider.RunCommandOnControlPlaneNode("cp /etc/kubernetes/admin.conf /root/.kube/config")
	if err != nil || rc != 0 {
		return fmt.Errorf("error when copying Kubeconfig file to /root/.kube/config on '%s': %s", provider.controlPlaneNodeName, stdout)
	}
	return nil
}

// NewKindProvider returns an implementation of ProviderInterface which is suitable for a
// Kubernetes test cluster created with Kind.
// configPath is unused for the kind provider
func NewKindProvider(configPath string) (ProviderInterface, error) {
	provider := &KindProvider{}
	// Run docker ps to fetch control-plane Node name
	rc, stdout, _, err := exec.RunDockerPsFilterCommand("name=control-plane")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("Error when running docker ps filter command: %s", stdout)
	}
	slicedOutput := strings.Fields(stdout)
	provider.controlPlaneNodeName = slicedOutput[len(slicedOutput)-1]

	if err := provider.enableKubectlOnControlPlane(); err != nil {
		return nil, err
	}
	return provider, nil
}

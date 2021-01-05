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

	"github.com/vmware-tanzu/antrea/test/e2e/providers/exec"
)

type KindProvider struct {
	controlPlaneNodeName string
}

func (provider *KindProvider) RunCommandOnControlPlaneNode(cmd string) (
	code int, stdout string, stderr string, err error,
) {
	return exec.RunDockerExecCommand(provider.controlPlaneNodeName, cmd, "/root")
}

func (provider *KindProvider) RunCommandOnNode(nodeName string, cmd string) (
	code int, stdout string, stderr string, err error,
) {
	return exec.RunDockerExecCommand(nodeName, cmd, "/root")
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

// moveCoreDNSPodsToControlPlane ensures that all the CoreDNS Pods are scheduled on the control-plane Node
// by patching the CoreDNS deployment with kubectl. Several of the e2e tests restart the Antrea
// agent on a worker Node, which causes the datapath to break. If this happens when CoreDNS Pods are
// scheduled on this specific worker Node, we observe that kube-apiserver cannot reach CoreDNS any
// more, which may cause some subsequent tests to fail. Because we never restart the Antrea agent on
// the control-plane Node, it helps to move the CoreDNS Pods to that Node. Note that CoreDNS Pods
// still need to be restarted if a test restarts all Agent Pods (e.g. as part of a rolling update
// when the Antrea YAML manifest is changed). This issue does not seem to affect clusters which use
// the OVS kernel datapath as much.
// TODO: revert changes at the end of tests?
func (provider *KindProvider) moveCoreDNSPodsToControlPlane() error {
	patch := `{"spec":{"template":{"spec":{"nodeName":"` + provider.controlPlaneNodeName + `"}}}}`
	cmd := fmt.Sprintf("kubectl patch -v 8 deployment coredns -n kube-system -p %s", patch)
	rc, stdout, _, err := provider.RunCommandOnControlPlaneNode(cmd)
	if err != nil || rc != 0 {
		return fmt.Errorf("error when scheduling CoreDNS Pods to '%s': %s", provider.controlPlaneNodeName, stdout)
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
	if err := provider.moveCoreDNSPodsToControlPlane(); err != nil {
		return nil, err
	}
	return provider, nil
}

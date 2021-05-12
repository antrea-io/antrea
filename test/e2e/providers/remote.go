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
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/kevinburke/ssh_config"

	"antrea.io/antrea/test/e2e/providers/exec"
)

var (
	homedir, _       = os.UserHomeDir()
	sshConfig        = flag.String("remote.sshconfig", path.Join(homedir, ".ssh", "config"), "Path of the sshconfig")
	remoteKubeconfig = flag.String("remote.kubeconfig", path.Join(homedir, ".kube", "config"), "Path of the kubeconfig of the cluster")
)

func getSSHConfig() (*ssh_config.Config, error) {
	info, err := os.Stat(*sshConfig)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is not a file", *sshConfig)
	}
	f, err := os.Open(*sshConfig)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ssh_config.Decode(f)
}

type RemoteProvider struct {
	sshConfig *ssh_config.Config
}

func (p *RemoteProvider) RunCommandOnNode(nodeName string, cmd string) (code int, stdout string, stderr string, err error) {
	host, clientCfg, err := convertConfig(p.sshConfig, nodeName)
	if err != nil {
		return 0, "", "", err
	}
	return exec.RunSSHCommand(host, clientCfg, cmd)
}

func (p *RemoteProvider) GetKubeconfigPath() (string, error) {
	return *remoteKubeconfig, nil
}

// NewRemoteProvider returns an implementation of ProviderInterface which enables tests to run on a remote cluster.
// configPath is unused for the remote provider
func NewRemoteProvider(configPath string) (ProviderInterface, error) {
	sshConfig, err := getSSHConfig()
	if err != nil {
		return nil, err
	}
	return &RemoteProvider{sshConfig: sshConfig}, nil
}

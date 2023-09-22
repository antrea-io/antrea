// Copyright 2023 Antrea Authors
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

//go:build windows
// +build windows

package support

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"antrea.io/antrea/pkg/util/logdir"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	aqtest "antrea.io/antrea/pkg/agent/querier/testing"
)

func TestDumpLog(t *testing.T) {
	fs := afero.NewMemMapFs()
	logDir := logdir.GetLogDir()

	fs.MkdirAll(logDir, os.ModePerm)
	fs.MkdirAll(antreaWindowsOVSLogDir, os.ModePerm)
	fs.MkdirAll(antreaWindowsKubeletLogDir, os.ModePerm)
	fs.Create(filepath.Join(logDir, "rancher-wins-antrea-agent.log"))
	fs.Create(filepath.Join(antreaWindowsOVSLogDir, "ovs.log"))
	fs.Create(filepath.Join(antreaWindowsKubeletLogDir, "kubelet.log"))

	dumper := NewAgentDumper(fs, nil, nil, nil, nil, "7s", true, true)
	err := dumper.DumpLog(baseDir)
	require.NoError(t, err)

	ok, err := afero.Exists(fs, filepath.Join(baseDir, "logs", "agent", "rancher-wins-antrea-agent.log"))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = afero.Exists(fs, filepath.Join(baseDir, "logs", "ovs", "ovs.log"))
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = afero.Exists(fs, filepath.Join(baseDir, "logs", "kubelet", "kubelet.log"))
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestDumpHostNetworkInfo(t *testing.T) {
	baseDir := "basedir"
	ctrl := gomock.NewController(t)
	q := aqtest.NewMockAgentQuerier(ctrl)

	for _, m := range []struct {
		name             string
		nodeConfigType   config.NodeType
		dumpHNSResources bool
	}{
		{
			name:             "k8s node",
			nodeConfigType:   config.K8sNode,
			dumpHNSResources: true,
		},
		{
			name:             "external node",
			nodeConfigType:   config.ExternalNode,
			dumpHNSResources: false,
		},
	} {
		t.Run(m.name, func(t *testing.T) {
			fakeExec := &testExec{}
			defaultFS := afero.NewMemMapFs()
			ad := &agentDumper{
				fs:        defaultFS,
				aq:        q,
				executor:  fakeExec,
				v4Enabled: true,
				v6Enabled: false,
			}
			c := &config.NodeConfig{
				Type: m.nodeConfigType,
			}
			q.EXPECT().GetNodeConfig().Return(c).Times(1)
			err := ad.DumpHostNetworkInfo(baseDir)
			require.NoError(t, err)
			exist, err := afero.Exists(defaultFS, path.Join(baseDir, "HNSNetwork"))
			require.NoError(t, err)
			assert.Equal(t, m.dumpHNSResources, exist)
			exist, err = afero.Exists(defaultFS, path.Join(baseDir, "HNSEndpoint"))
			require.NoError(t, err)
			assert.Equal(t, m.dumpHNSResources, exist)
		})
	}
}

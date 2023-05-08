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

package support

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"

	"antrea.io/antrea/pkg/agent/config"
	aqtest "antrea.io/antrea/pkg/agent/querier/testing"
)

type testExec struct {
	exectesting.FakeExec
}

func (te *testExec) Command(cmd string, args ...string) exec.Cmd {
	f := new(exectesting.FakeCmd)
	f.CombinedOutputScript = append(f.CombinedOutputScript, func() ([]byte, []byte, error) {
		return []byte(fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))), nil, nil
	})
	return f
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

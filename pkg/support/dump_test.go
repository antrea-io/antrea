// Copyright 2020 Antrea Authors
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"
)

var baseDir = filepath.Join("dir1", "dir2")

type testExec struct {
	exectesting.FakeExec
}

// Command func is to track correct commands are executed
func (te *testExec) Command(cmd string, args ...string) exec.Cmd {
	fakeCmd := new(exectesting.FakeCmd)
	fakeCmd.CombinedOutputScript = append(fakeCmd.CombinedOutputScript, func() ([]byte, []byte, error) {
		return []byte(fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))), nil, nil
	})
	return fakeCmd
}

func TestControllerDumpLog(t *testing.T) {
	fs := afero.NewMemMapFs()
	dumper := NewControllerDumper(fs, nil, "7s")
	err := dumper.DumpLog(baseDir)
	assert.NoError(t, err)
}

func TestParseTimeFromLogLine(t *testing.T) {
	tests := []struct {
		name              string
		data              string
		year              string
		prefix            string
		expectedError     string
		expectedTimeStamp string
	}{
		{
			name:              "log line with prefix antrea-agent",
			data:              "I0817 06:55:10.804384       1 shared_informer.go:270] caches populated",
			year:              "2021",
			prefix:            "antrea-agent",
			expectedTimeStamp: "2021-08-17 06:55:10 +0000 UTC",
		},
		{
			name:              "log line with prefix ovs",
			data:              "2021-06-01T09:30:43.823Z|00004|memory|INFO|cells:299 monitors:2 sessions:2",
			year:              "2021",
			prefix:            "ovs",
			expectedTimeStamp: "2021-06-01 09:30:43 +0000 UTC",
		},
		{
			name:          "with no log line",
			year:          "2021",
			prefix:        "ovs",
			expectedError: "log line is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTimeStamp, err := parseTimeFromLogLine(tc.data, tc.year, tc.prefix)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedTimeStamp, gotTimeStamp.String())
			}
		})
	}
}

func TestParseFileName(t *testing.T) {
	name := "antrea-agent.ubuntu-1.root.log.WARNING.20210817-094758.1"
	ts, err := parseTimeFromFileName(name)
	assert.Nil(t, err)
	assert.Equal(t, ts.String(), "2021-08-17 09:47:58 +0000 UTC")
}

func TestTimestampFilter(t *testing.T) {
	ts := timestampFilter("2m")
	require.NotNil(t, ts)
	currentTime := time.Now()
	expectedTime := currentTime.Add(-2 * time.Minute)
	assert.WithinDuration(t, expectedTime, *ts, 10*time.Second)
}

func TestWriteFile(t *testing.T) {
	resource := "test-data"
	data := []byte("foo bar")

	fs := afero.NewMemMapFs()
	err := writeFile(fs, filepath.Join(baseDir, resource), resource, data)
	require.NoError(t, err)

	fileContents, err := afero.ReadFile(fs, filepath.Join(baseDir, resource))
	require.NoError(t, err)
	assert.Equal(t, data, fileContents)
}

func TestWriteYAMLFile(t *testing.T) {
	type testData struct {
		X string
		Y int
	}
	data := testData{
		X: "foo",
		Y: 123,
	}
	resource := "test-data"
	path := filepath.Join(baseDir, resource)
	fs := afero.NewMemMapFs()
	err := writeYAMLFile(fs, path, resource, &data)
	require.NoError(t, err)

	fileContents, err := afero.ReadFile(fs, path)
	require.NoError(t, err)
	var fileData testData
	require.NoError(t, yaml.Unmarshal(fileContents, &fileData))
	assert.Equal(t, data, fileData)
}

func TestDumpAntctlGet(t *testing.T) {
	name := "agentinfo"

	exe := new(testExec)
	expectedOutput := fmt.Sprintf("antctl -oyaml get %s", name)

	fs := afero.NewMemMapFs()
	err := dumpAntctlGet(fs, exe, name, baseDir)
	require.NoError(t, err)

	result, _ := afero.ReadFile(fs, filepath.Join(baseDir, "agentinfo"))
	assert.Equal(t, expectedOutput, string(result))
}

func TestDumpNetworkPolicyResources(t *testing.T) {
	names := []string{"networkpolicies", "appliedtogroups", "addressgroups"}
	fs := afero.NewMemMapFs()
	exe := new(testExec)
	err := dumpNetworkPolicyResources(fs, exe, baseDir)
	require.NoError(t, err)
	for _, name := range names {
		expectedOutput := fmt.Sprintf("antctl -oyaml get %s", name)
		result, _ := afero.ReadFile(fs, filepath.Join(baseDir, name))
		assert.Equal(t, expectedOutput, string(result))
	}
}

func TestDumpControllerInfo(t *testing.T) {
	exe := new(testExec)
	fs := afero.NewMemMapFs()
	dumper := NewControllerDumper(fs, exe, "5s")
	err := dumper.DumpControllerInfo(baseDir)
	require.NoError(t, err)
}

func TestControllerDumpNetworkPolicyResources(t *testing.T) {
	exe := new(testExec)
	fs := afero.NewMemMapFs()
	dumper := NewControllerDumper(fs, exe, "5s")
	err := dumper.DumpNetworkPolicyResources(baseDir)
	require.NoError(t, err)
}

func TestControllerDumpHeapPprof(t *testing.T) {
	exe := new(testExec)
	fs := afero.NewMemMapFs()
	dumper := NewControllerDumper(fs, exe, "5s")
	err := dumper.DumpHeapPprof(baseDir)
	require.NoError(t, err)
}

func TestControllerDumpGoroutinePprof(t *testing.T) {
	exe := new(testExec)
	fs := afero.NewMemMapFs()
	dumper := NewControllerDumper(fs, exe, "5s")
	err := dumper.DumpGoroutinePprof(baseDir)
	require.NoError(t, err)
}

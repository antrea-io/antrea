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

package proxy

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

func TestValidateAndComplete(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defer func() {
		defaultFS = afero.NewOsFs()
	}()

	_, err := defaultFS.Create("www")
	require.NoError(t, err)

	tests := []struct {
		name           string
		proxyOpts      *proxyOptions
		expectedErr    string
		expectedErrLog string
	}{
		{
			name: "specified both port and unixSocket",
			proxyOpts: &proxyOptions{
				port:       80,
				unixSocket: "unix-socket",
			},
			expectedErr: "cannot set --unix-socket and --port at the same time",
		},
		{
			name: "specified both controller and agentnodename",
			proxyOpts: &proxyOptions{
				port:          80,
				controller:    true,
				agentNodeName: "agent-node",
			},
			expectedErr: "cannot use --controller and --agent-node at the same time",
		},
		{
			name: "missing static directory",
			proxyOpts: &proxyOptions{
				port:       80,
				controller: false,
				staticDir:  "temp",
			},
			expectedErrLog: "Failed to stat static file directory",
		},
		{
			name: "invalid static directory",
			proxyOpts: &proxyOptions{
				port:       80,
				controller: false,
				staticDir:  "www",
			},
			expectedErrLog: "Static file directory is not a directory",
		},
		{
			name: "disableFilter set to true",
			proxyOpts: &proxyOptions{
				port:          80,
				controller:    true,
				disableFilter: true,
			},
			expectedErrLog: "Request filter disabled, your proxy is vulnerable to XSRF attacks, please be cautious",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bufWriter := bytes.NewBuffer(nil)
			klog.SetOutput(bufWriter)
			klog.LogToStderr(false)
			defer func() {
				klog.SetOutput(os.Stderr)
				klog.LogToStderr(true)
			}()
			err := tc.proxyOpts.validateAndComplete()
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			if tc.expectedErrLog != "" {
				assert.Contains(t, bufWriter.String(), tc.expectedErrLog)
			}
		})
	}
}

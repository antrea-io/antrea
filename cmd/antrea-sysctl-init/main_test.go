// Copyright 2026 Antrea Authors
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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name           string
		setupSysctlDir func(t *testing.T) string
		expectWrite    bool
	}{
		{
			name: "sysctl dir does not exist",
			setupSysctlDir: func(t *testing.T) string {
				return filepath.Join(os.TempDir(), "antrea-sysctl-init-not-exist")
			},
			expectWrite: false,
		},
		{
			name: "sysctl path is not a directory",
			setupSysctlDir: func(t *testing.T) string {
				tmpDir := t.TempDir()
				notDir := filepath.Join(tmpDir, "not-a-dir")
				err := os.WriteFile(notDir, []byte("dummy"), 0644)
				require.NoError(t, err)
				return notDir
			},
			expectWrite: false,
		},
		{
			name: "successfully write sysctl config",
			setupSysctlDir: func(t *testing.T) string {
				return t.TempDir()
			},
			expectWrite: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			memFS := afero.NewMemMapFs()
			origFS := defaultFS
			t.Cleanup(func() {
				defaultFS = origFS
			})
			defaultFS = memFS

			sysctlDirPath := tt.setupSysctlDir(t)
			sysctlDir = &sysctlDirPath

			fileName := "99-test-antrea.conf"
			antreaOverwriteFile = &fileName

			run()

			filePath := filepath.Join(sysctlDirPath, fileName)
			exists, err := afero.Exists(memFS, filePath)
			require.NoError(t, err)

			if tt.expectWrite {
				require.True(t, exists)

				content, err := afero.ReadFile(memFS, filePath)
				require.NoError(t, err)
				require.Equal(t, sysctlConfig, string(content))
			} else {
				require.False(t, exists)
			}
		})
	}
}

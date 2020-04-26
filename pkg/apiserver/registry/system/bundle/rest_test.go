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

package bundle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"

	system "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
)

type testExec struct {
	exectesting.FakeExec
}

func (te *testExec) Command(cmd string, args ...string) exec.Cmd {
	fakeCmd := new(exectesting.FakeCmd)
	fakeCmd.CombinedOutputScript = append(fakeCmd.CombinedOutputScript, func() ([]byte, error) {
		return []byte(fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))), nil
	})
	return fakeCmd
}

func TestClean(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultExecutor = new(testExec)
	defer func() {
		defaultFS = afero.NewOsFs()
		defaultExecutor = exec.New()
	}()

	for name, tc := range map[string]struct {
		needCancel bool
		duration   time.Duration
	}{
		"CleanByCancellation": {
			needCancel: true,
			duration:   time.Hour,
		},
		"CleanByTimeout": {
			duration: 10 * time.Millisecond,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := defaultFS.Create("test.tar.gz")
			require.NoError(t, err)
			defer defaultFS.Remove(f.Name())
			require.NoError(t, f.Close())
			storage := NewStorage("agent")
			ctx, cancelFunc := context.WithCancel(context.Background())
			if tc.needCancel {
				cancelFunc()
			}
			go storage.Status.clean(ctx, f.Name(), tc.duration)
			time.Sleep(200 * time.Millisecond)
			exist, err := afero.Exists(defaultFS, f.Name())
			require.NoError(t, err)
			require.False(t, exist)
			require.Equal(t, system.BundleNone, storage.Status.cache.Status)
		})
	}
}

func TestCollect(t *testing.T) {
	storage := NewStorage("controller")
	for name, function := range map[string]func(context.Context) (*system.Bundle, error){
		"Agent":      storage.Status.collectAgent,
		"Controller": storage.Status.collectController,
	} {
		t.Run(name, func(t *testing.T) {
			defaultFS = afero.NewMemMapFs()
			defaultExecutor = new(testExec)
			defer func() {
				defaultFS = afero.NewOsFs()
				defaultExecutor = exec.New()
			}()

			bundle, err := function(context.TODO())
			require.NoError(t, err)
			require.Equal(t, bundle.Status, system.BundleCollected)

			var remainFiles []string
			afero.Walk(defaultFS, "/", func(filepath string, info os.FileInfo, err error) error {
				require.NoError(t, err)
				if info.IsDir() {
					return nil
				}
				remainFiles = append(remainFiles, filepath)
				return nil
			})
			require.Len(t, remainFiles, 1, fmt.Sprintf("Expect only one file remains, got %v", remainFiles))
			require.Equal(t, remainFiles[0], bundle.FilePath)

			targzFile, err := defaultFS.Open(remainFiles[0])
			require.NoError(t, err)
			defer targzFile.Close()
			hasher := sha256.New()
			_, err = io.Copy(hasher, targzFile)
			require.NoError(t, err)
			require.Equal(t, fmt.Sprintf("%x", hasher.Sum(nil)), bundle.Sum)
		})
	}
}

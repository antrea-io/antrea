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

package supportbundle

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"

	system "antrea.io/antrea/pkg/apis/system/v1beta1"
)

type testExec struct {
	exectesting.FakeExec
}

func (te *testExec) Command(cmd string, args ...string) exec.Cmd {
	fakeCmd := new(exectesting.FakeCmd)
	fakeCmd.CombinedOutputScript = append(fakeCmd.CombinedOutputScript, func() ([]byte, []byte, error) {
		return []byte(fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))), nil, nil
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
			storage := NewControllerStorage()
			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()
			if tc.needCancel {
				cancelFunc()
			}
			go storage.SupportBundle.clean(ctx, f.Name(), tc.duration)
			time.Sleep(200 * time.Millisecond)
			exist, err := afero.Exists(defaultFS, f.Name())
			require.NoError(t, err)
			require.False(t, exist)
			require.Equal(t, system.SupportBundleStatusNone, storage.SupportBundle.cache.Status)
		})
	}
}

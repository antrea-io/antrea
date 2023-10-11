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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clockutils "k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/exec"
	exectesting "k8s.io/utils/exec/testing"

	agentquerier "antrea.io/antrea/pkg/agent/querier"
	agentqueriertest "antrea.io/antrea/pkg/agent/querier/testing"
	system "antrea.io/antrea/pkg/apis/system/v1beta1"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
	"antrea.io/antrea/pkg/querier"
	queriertest "antrea.io/antrea/pkg/querier/testing"
	"antrea.io/antrea/pkg/support"
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

func TestREST(t *testing.T) {
	r := &supportBundleREST{}
	assert.Equal(t, &system.SupportBundle{}, r.New())
	assert.False(t, r.NamespaceScoped())
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
			duration:   1 * time.Hour,
		},
		"CleanByTimeout": {
			duration: 1 * time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(time.Now())
			clock = fakeClock
			defer func() {
				clock = clockutils.RealClock{}
			}()
			f, err := defaultFS.Create("test.tar.gz")
			require.NoError(t, err)
			defer defaultFS.Remove(f.Name())
			require.NoError(t, f.Close())
			storage := NewControllerStorage()
			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()
			require.False(t, fakeClock.HasWaiters())
			go storage.SupportBundle.clean(ctx, f.Name(), tc.duration)
			// Wait for the clean function to have called clock.After:
			// until it does, we cannot advance the fake clock.
			require.Eventually(t, func() bool {
				return fakeClock.HasWaiters()
			}, 1*time.Second, 10*time.Millisecond)
			if tc.needCancel {
				cancelFunc()
			} else {
				fakeClock.Step(tc.duration)
			}
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				exist, err := afero.Exists(defaultFS, f.Name())
				require.NoError(t, err)
				assert.False(c, exist)
			}, 1*time.Second, 10*time.Millisecond, "Supportbundle file was not deleted")
			assert.Equal(t, system.SupportBundleStatusNone, storage.SupportBundle.cache.Status)
		})
	}
}

func TestCollect(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultExecutor = new(testExec)
	defer func() {
		defaultFS = afero.NewOsFs()
		defaultExecutor = exec.New()
	}()

	storage := NewControllerStorage()
	dumper1Executed := false
	dumper1 := func(string) error {
		dumper1Executed = true
		return nil
	}
	dumper2Executed := false
	dumper2 := func(string) error {
		dumper2Executed = true
		return nil
	}
	collectedBundle, err := storage.SupportBundle.collect(context.TODO(), dumper1, dumper2)
	require.NoError(t, err)
	require.NotEmpty(t, collectedBundle.Filepath)
	defer defaultFS.Remove(collectedBundle.Filepath)
	assert.Equal(t, system.SupportBundleStatusCollected, collectedBundle.Status)
	assert.NotEmpty(t, collectedBundle.Sum)
	assert.Greater(t, collectedBundle.Size, uint32(0))
	assert.True(t, dumper1Executed)
	assert.True(t, dumper2Executed)
	exist, err := afero.Exists(defaultFS, collectedBundle.Filepath)
	require.NoError(t, err)
	require.True(t, exist)
}

func TestControllerStorage(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultExecutor = new(testExec)
	defer func() {
		defaultFS = afero.NewOsFs()
		defaultExecutor = exec.New()
	}()

	storage := NewControllerStorage()
	_, err := storage.SupportBundle.Create(context.TODO(), &system.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: modeController,
		},
		Status: system.SupportBundleStatusNone,
		Since:  "-1h",
	}, nil, nil)
	require.NoError(t, err)

	var collectedBundle *system.SupportBundle
	assert.Eventually(t, func() bool {
		object, err := storage.SupportBundle.Get(context.TODO(), modeController, nil)
		require.NoError(t, err)
		collectedBundle = object.(*system.SupportBundle)
		return collectedBundle.Status == system.SupportBundleStatusCollected
	}, time.Second*2, time.Millisecond*100)
	filePath := collectedBundle.Filepath
	require.NotEmpty(t, filePath)
	defer defaultFS.Remove(filePath)
	assert.NotEmpty(t, collectedBundle.Sum)
	assert.Greater(t, collectedBundle.Size, uint32(0))
	exist, err := afero.Exists(defaultFS, filePath)
	require.NoError(t, err)
	require.True(t, exist)

	_, err = storage.SupportBundle.Get(context.TODO(), modeAgent, nil)
	assert.Equal(t, errors.NewNotFound(system.Resource("supportBundle"), modeAgent), err)

	_, deleted, err := storage.SupportBundle.Delete(context.TODO(), modeAgent, nil, nil)
	assert.Equal(t, errors.NewNotFound(system.Resource("supportBundle"), modeAgent), err)
	assert.False(t, deleted)

	_, deleted, err = storage.SupportBundle.Delete(context.TODO(), modeController, nil, nil)
	assert.NoError(t, err)
	assert.True(t, deleted)
	object, err := storage.SupportBundle.Get(context.TODO(), modeController, nil)
	assert.NoError(t, err)
	assert.Equal(t, &system.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{Name: modeController},
		Status:     system.SupportBundleStatusNone,
	}, object)
	assert.Eventuallyf(t, func() bool {
		exist, err := afero.Exists(defaultFS, filePath)
		require.NoError(t, err)
		return !exist
	}, time.Second*2, time.Millisecond*100, "Supportbundle file %s was not deleted after deleting the Supportbundle object", filePath)
}

type fakeAgentDumper struct {
	returnErr error
}

func (f *fakeAgentDumper) DumpFlows(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpHostNetworkInfo(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpLog(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpAgentInfo(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpNetworkPolicyResources(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpHeapPprof(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpGoroutinePprof(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpOVSPorts(basedir string) error {
	return f.returnErr
}

func (f *fakeAgentDumper) DumpMemberlist(basedir string) error {
	return f.returnErr
}

func TestAgentStorage(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultExecutor = new(testExec)
	newAgentDumper = func(fs afero.Fs, executor exec.Interface, ovsCtlClient ovsctl.OVSCtlClient, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, since string, v4Enabled, v6Enabled bool) support.AgentDumper {
		return &fakeAgentDumper{}
	}
	defer func() {
		defaultFS = afero.NewOsFs()
		defaultExecutor = exec.New()
		newAgentDumper = support.NewAgentDumper
	}()

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	fakeOVSCtl := ovsctltest.NewMockOVSCtlClient(ctrl)
	fakeAgentQuerier := agentqueriertest.NewMockAgentQuerier(ctrl)
	fakeNetworkPolicyQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	storage := NewAgentStorage(fakeOVSCtl, fakeAgentQuerier, fakeNetworkPolicyQuerier, true, true)
	_, err := storage.SupportBundle.Create(ctx, &system.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: modeAgent,
		},
		Status: system.SupportBundleStatusNone,
		Since:  "-1h",
	}, nil, nil)
	require.NoError(t, err)

	var collectedBundle *system.SupportBundle
	assert.Eventually(t, func() bool {
		object, err := storage.SupportBundle.Get(ctx, modeAgent, nil)
		require.NoError(t, err)
		collectedBundle = object.(*system.SupportBundle)
		return collectedBundle.Status == system.SupportBundleStatusCollected
	}, time.Second*2, time.Millisecond*100)
	require.NotEmpty(t, collectedBundle.Filepath)
	filePath := collectedBundle.Filepath
	defer defaultFS.Remove(filePath)
	assert.NotEmpty(t, collectedBundle.Sum)
	assert.Greater(t, collectedBundle.Size, uint32(0))
	exist, err := afero.Exists(defaultFS, filePath)
	require.NoError(t, err)
	require.True(t, exist)

	_, deleted, err := storage.SupportBundle.Delete(ctx, modeAgent, nil, nil)
	assert.NoError(t, err)
	assert.True(t, deleted)
	object, err := storage.SupportBundle.Get(ctx, modeAgent, nil)
	assert.NoError(t, err)
	assert.Equal(t, &system.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{Name: modeAgent},
		Status:     system.SupportBundleStatusNone,
	}, object)
	assert.Eventuallyf(t, func() bool {
		exist, err := afero.Exists(defaultFS, filePath)
		require.NoError(t, err)
		return !exist
	}, time.Second*2, time.Millisecond*100, "Supportbundle file %s was not deleted after deleting the Supportbundle object", filePath)
}

func TestAgentStorageFailure(t *testing.T) {
	defaultFS = afero.NewMemMapFs()
	defaultExecutor = new(testExec)
	newAgentDumper = func(fs afero.Fs, executor exec.Interface, ovsCtlClient ovsctl.OVSCtlClient, aq agentquerier.AgentQuerier, npq querier.AgentNetworkPolicyInfoQuerier, since string, v4Enabled, v6Enabled bool) support.AgentDumper {
		return &fakeAgentDumper{returnErr: fmt.Errorf("iptables not found")}
	}
	defer func() {
		defaultFS = afero.NewOsFs()
		defaultExecutor = exec.New()
		newAgentDumper = support.NewAgentDumper
	}()

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	fakeOVSCtl := ovsctltest.NewMockOVSCtlClient(ctrl)
	fakeAgentQuerier := agentqueriertest.NewMockAgentQuerier(ctrl)
	fakeNetworkPolicyQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)

	storage := NewAgentStorage(fakeOVSCtl, fakeAgentQuerier, fakeNetworkPolicyQuerier, true, true)
	_, err := storage.SupportBundle.Create(ctx, &system.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: modeAgent,
		},
		Status: system.SupportBundleStatusNone,
		Since:  "-1h",
	}, nil, nil)
	require.NoError(t, err)

	var collectedBundle *system.SupportBundle
	assert.Eventually(t, func() bool {
		object, err := storage.SupportBundle.Get(ctx, modeAgent, nil)
		require.NoError(t, err)
		collectedBundle = object.(*system.SupportBundle)
		return collectedBundle.Status == system.SupportBundleStatusNone
	}, time.Second*2, time.Millisecond*100)
	assert.Empty(t, collectedBundle.Filepath)
	assert.Empty(t, collectedBundle.Sum)
	assert.Empty(t, collectedBundle.Size)

	_, err = storage.SupportBundle.Get(ctx, modeController, nil)
	assert.Equal(t, errors.NewNotFound(system.Resource("supportBundle"), modeController), err)
	_, deleted, err := storage.SupportBundle.Delete(ctx, modeController, nil, nil)
	assert.Equal(t, errors.NewNotFound(system.Resource("supportBundle"), modeController), err)
	assert.False(t, deleted)
}

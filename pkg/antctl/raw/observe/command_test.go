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

package observe

import (
	"context"
	"io"
	"net"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/antctl/runtime"
)

// deploymentWithSelector builds a minimal Deployment matching Pods labeled app=flow-aggregator,
// for findFlowAggregatorByName (exercised here indirectly through resolveTarget).
func deploymentWithSelector(namespace, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "flow-aggregator"}},
		},
	}
}

// withRuntimeMode temporarily overrides the antctl runtime package's Mode/InPod globals for the
// duration of a test, restoring them afterward: inFlowAggregatorPod derives its answer entirely
// from that shared package-level state.
func withRuntimeMode(t *testing.T, mode string, inPod bool) {
	t.Helper()
	origMode, origInPod := runtime.Mode, runtime.InPod
	runtime.Mode, runtime.InPod = mode, inPod
	t.Cleanup(func() { runtime.Mode, runtime.InPod = origMode, origInPod })
}

func TestInFlowAggregatorPod(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		inPod bool
		want  bool
	}{
		{"flow-aggregator mode, in-Pod", runtime.ModeFlowAggregator, true, true},
		{"flow-aggregator mode, not in-Pod", runtime.ModeFlowAggregator, false, false},
		{"controller mode, in-Pod", runtime.ModeController, true, false},
		{"agent mode, in-Pod", runtime.ModeAgent, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withRuntimeMode(t, tc.mode, tc.inPod)
			assert.Equal(t, tc.want, inFlowAggregatorPod())
		})
	}
}

func TestDescribeSearchScope(t *testing.T) {
	assert.Equal(t, "cluster-wide", describeSearchScope(""))
	assert.Equal(t, `Namespace "flow-aggregator"`, describeSearchScope("flow-aggregator"))
}

func TestResolveTarget(t *testing.T) {
	t.Run("by name via --flow-aggregator", func(t *testing.T) {
		origFlowAggregator := o.flowAggregator
		o.flowAggregator = "flow-aggregator/flow-aggregator"
		t.Cleanup(func() { o.flowAggregator = origFlowAggregator })

		deployment := deploymentWithSelector("flow-aggregator", "flow-aggregator")
		pod := flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true)
		client := fake.NewSimpleClientset(deployment, pod)

		target, err := resolveTarget(context.Background(), client, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})

	t.Run("invalid --flow-aggregator format", func(t *testing.T) {
		origFlowAggregator := o.flowAggregator
		o.flowAggregator = "not-namespace-slash-name"
		t.Cleanup(func() { o.flowAggregator = origFlowAggregator })

		_, err := resolveTarget(context.Background(), fake.NewSimpleClientset(), io.Discard)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid --flow-aggregator")
	})

	t.Run("falls back to discovery when --flow-aggregator is unset", func(t *testing.T) {
		origFlowAggregator, origNamespace := o.flowAggregator, o.flowAggregatorNamespace
		o.flowAggregator, o.flowAggregatorNamespace = "", ""
		t.Cleanup(func() { o.flowAggregator, o.flowAggregatorNamespace = origFlowAggregator, origNamespace })

		client := fake.NewSimpleClientset(flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true))
		target, err := resolveTarget(context.Background(), client, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})
}

func TestConnect_FlowAggregatorAddress(t *testing.T) {
	t.Run("reachable address, default Namespace used for TLS", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer lis.Close()
		go func() {
			conn, err := lis.Accept()
			if err == nil {
				conn.Close()
			}
		}()

		origAddr, origNamespace := o.flowAggregatorAddress, o.flowAggregatorNamespace
		o.flowAggregatorAddress, o.flowAggregatorNamespace = lis.Addr().String(), ""
		t.Cleanup(func() { o.flowAggregatorAddress, o.flowAggregatorNamespace = origAddr, origNamespace })

		addr, tlsNamespace, closeFn, err := connect(context.Background(), fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto, io.Discard)
		require.NoError(t, err)
		defer closeFn()
		assert.Equal(t, lis.Addr().String(), addr)
		assert.Equal(t, defaultFlowAggregatorNamespace, tlsNamespace)
	})

	t.Run("explicit --flow-aggregator-namespace overrides the default", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer lis.Close()
		go func() {
			conn, err := lis.Accept()
			if err == nil {
				conn.Close()
			}
		}()

		origAddr, origNamespace := o.flowAggregatorAddress, o.flowAggregatorNamespace
		o.flowAggregatorAddress, o.flowAggregatorNamespace = lis.Addr().String(), "flow-aggregator-2"
		t.Cleanup(func() { o.flowAggregatorAddress, o.flowAggregatorNamespace = origAddr, origNamespace })

		_, tlsNamespace, closeFn, err := connect(context.Background(), fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto, io.Discard)
		require.NoError(t, err)
		defer closeFn()
		assert.Equal(t, "flow-aggregator-2", tlsNamespace)
	})

	t.Run("unreachable address fails outright", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := lis.Addr().String()
		require.NoError(t, lis.Close())

		origAddr := o.flowAggregatorAddress
		o.flowAggregatorAddress = addr
		t.Cleanup(func() { o.flowAggregatorAddress = origAddr })

		_, _, _, err = connect(context.Background(), fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto, io.Discard)
		require.Error(t, err)
	})
}

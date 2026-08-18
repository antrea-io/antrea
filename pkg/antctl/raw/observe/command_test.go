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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/antctl/runtime"
)

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
		opts := &options{flowAggregator: "flow-aggregator/flow-aggregator"}
		service := flowAggregatorService("flow-aggregator", "flow-aggregator", true)
		pod := flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true)
		client := fake.NewSimpleClientset(service, pod)

		target, err := resolveTarget(context.Background(), opts, client, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})

	t.Run("invalid --flow-aggregator format", func(t *testing.T) {
		opts := &options{flowAggregator: "not-namespace-slash-name"}

		_, err := resolveTarget(context.Background(), opts, fake.NewSimpleClientset(), io.Discard)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid --flow-aggregator")
	})

	t.Run("falls back to discovery when --flow-aggregator is unset", func(t *testing.T) {
		client := fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", "10.0.0.5", true))
		target, err := resolveTarget(context.Background(), &options{}, client, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "flow-aggregator-abc", target.podName)
	})

	t.Run("the Service named by --flow-aggregator does not exist", func(t *testing.T) {
		var stderr bytes.Buffer
		_, err := resolveTarget(context.Background(), &options{flowAggregator: "flow-aggregator/flow-aggregator"}, fake.NewSimpleClientset(), &stderr)
		require.Error(t, err)
		assert.ErrorContains(t, err, "error when getting Service flow-aggregator/flow-aggregator")
		assert.Contains(t, stderr.String(), "Looking up Flow Aggregator flow-aggregator/flow-aggregator", "the user is told what is being looked up")
	})

	t.Run("discovery finds no Flow Aggregator", func(t *testing.T) {
		var stderr bytes.Buffer
		_, err := resolveTarget(context.Background(), &options{flowAggregatorNamespace: "somewhere"}, fake.NewSimpleClientset(), &stderr)
		require.Error(t, err)
		assert.ErrorContains(t, err, "no Flow Aggregator Service labeled")
		assert.Contains(t, stderr.String(), `Discovering Flow Aggregator instance (searching Namespace "somewhere")`)
	})
}

func TestConnect_Discovery(t *testing.T) {
	// Nothing is expected to listen at 127.0.0.1:flowStreamPort, so a direct connection to this Pod is
	// refused at once. If something does, it does not pass the TLS verification that tlsConfig asks for,
	// so the direct connection fails all the same.
	const podIP = "127.0.0.1"
	newClient := func() *fake.Clientset {
		return fake.NewSimpleClientset(
			flowAggregatorService("flow-aggregator", "flow-aggregator", true),
			flowAggregatorPod("flow-aggregator", "flow-aggregator-abc", podIP, true))
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	buildTLS := func(string) (*tls.Config, error) { return tlsConfig, nil }

	t.Run("discovery fails", func(t *testing.T) {
		_, _, err := connect(context.Background(), &options{}, fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto, buildTLS, io.Discard)
		require.Error(t, err)
		assert.ErrorContains(t, err, "no Flow Aggregator Service labeled")
	})

	t.Run("the TLS configuration for the discovered Namespace cannot be built", func(t *testing.T) {
		wantErr := errors.New("no CA")
		var gotNamespace string
		_, _, err := connect(context.Background(), &options{}, newClient(), &rest.Config{}, connectionModeAuto,
			func(namespace string) (*tls.Config, error) {
				gotNamespace = namespace
				return nil, wantErr
			}, io.Discard)
		assert.ErrorIs(t, err, wantErr)
		assert.Equal(t, "flow-aggregator", gotNamespace, "the TLS configuration is built for the Namespace discovery found")
	})

	t.Run("direct mode fails when the Pod cannot be reached", func(t *testing.T) {
		_, _, err := connect(context.Background(), &options{}, newClient(), &rest.Config{}, connectionModeDirect, buildTLS, io.Discard)
		require.Error(t, err)
		assert.ErrorContains(t, err, "direct connection to 127.0.0.1:14740 failed")
	})

	t.Run("tunnel mode connects through the API server", func(t *testing.T) {
		restConfig := startPortForwardServer(t, holdConnection)
		var stderr bytes.Buffer
		ep, gotConfig, err := connect(context.Background(), &options{}, newClient(), restConfig, connectionModeTunnel, buildTLS, &stderr)
		require.NoError(t, err)
		defer ep.release()
		assert.Same(t, tlsConfig, gotConfig)
		assert.NotNil(t, ep.lost, "a tunnel must report if it is lost")
		assert.Contains(t, ep.addr, "127.0.0.1:")
		assert.Contains(t, stderr.String(), "Discovered Flow Aggregator Service flow-aggregator/flow-aggregator, Pod flow-aggregator-abc (127.0.0.1)")
		assert.Contains(t, stderr.String(), "Connecting to Flow Aggregator Pod flow-aggregator/flow-aggregator-abc (connection mode: tunnel)")
	})

	t.Run("auto mode falls back to the tunnel when the Pod cannot be reached", func(t *testing.T) {
		restConfig := startPortForwardServer(t, holdConnection)
		var stderr bytes.Buffer
		ep, _, err := connect(context.Background(), &options{}, newClient(), restConfig, connectionModeAuto, buildTLS, &stderr)
		require.NoError(t, err)
		defer ep.release()
		assert.NotNil(t, ep.lost)
		assert.Contains(t, stderr.String(), "falling back to a tunnel through the API server")
	})

	t.Run("--flow-aggregator selects the Service that discovery would not have found", func(t *testing.T) {
		restConfig := startPortForwardServer(t, holdConnection)
		client := fake.NewSimpleClientset(
			flowAggregatorService("proxy-mode", "flow-aggregator", false),
			flowAggregatorPod("proxy-mode", "flow-aggregator-xyz", podIP, true))
		ep, _, err := connect(context.Background(), &options{flowAggregator: "proxy-mode/flow-aggregator"}, client, restConfig,
			connectionModeTunnel, buildTLS, io.Discard)
		require.NoError(t, err)
		ep.release()
	})
}

func TestConnect_FlowAggregatorAddress(t *testing.T) {
	// recordingBuildTLS returns a buildTLS that hands out tlsConfig, and records the Namespace it was
	// asked for.
	recordingBuildTLS := func(tlsConfig *tls.Config, gotNamespace *string) func(string) (*tls.Config, error) {
		return func(namespace string) (*tls.Config, error) {
			*gotNamespace = namespace
			return tlsConfig, nil
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	t.Run("the address is used as is, with the default Namespace for TLS", func(t *testing.T) {
		opts := &options{flowAggregatorAddress: "flow-aggregator.example.com:14740"}

		var tlsNamespace string
		var stderr bytes.Buffer
		ep, gotConfig, err := connect(context.Background(), opts, fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto,
			recordingBuildTLS(tlsConfig, &tlsNamespace), &stderr)
		require.NoError(t, err)
		defer ep.release()
		assert.Equal(t, "flow-aggregator.example.com:14740", ep.addr)
		assert.Nil(t, ep.lost, "there is no tunnel that could be lost")
		assert.Same(t, tlsConfig, gotConfig)
		assert.Equal(t, defaultFlowAggregatorNamespace, tlsNamespace)
		assert.Contains(t, stderr.String(), "Connecting to flow-aggregator.example.com:14740")
	})

	t.Run("explicit --flow-aggregator-namespace overrides the default", func(t *testing.T) {
		opts := &options{flowAggregatorAddress: "127.0.0.1:14740", flowAggregatorNamespace: "flow-aggregator-2"}

		var tlsNamespace string
		ep, _, err := connect(context.Background(), opts, fake.NewSimpleClientset(), &rest.Config{}, connectionModeAuto,
			recordingBuildTLS(tlsConfig, &tlsNamespace), io.Discard)
		require.NoError(t, err)
		defer ep.release()
		assert.Equal(t, "flow-aggregator-2", tlsNamespace)
	})

	t.Run("an address that does not answer is not probed", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := lis.Addr().String()
		require.NoError(t, lis.Close())

		var tlsNamespace string
		ep, _, err := connect(context.Background(), &options{flowAggregatorAddress: addr}, fake.NewSimpleClientset(), &rest.Config{},
			connectionModeAuto, recordingBuildTLS(tlsConfig, &tlsNamespace), io.Discard)
		require.NoError(t, err, "the failure is reported by gRPC, when the stream starts")
		defer ep.release()
		assert.Equal(t, addr, ep.addr)
	})

	t.Run("failure to build the TLS configuration is returned", func(t *testing.T) {
		wantErr := errors.New("no CA")
		_, _, err := connect(context.Background(), &options{flowAggregatorAddress: "127.0.0.1:1"}, fake.NewSimpleClientset(), &rest.Config{},
			connectionModeAuto, func(string) (*tls.Config, error) { return nil, wantErr }, io.Discard)
		assert.ErrorIs(t, err, wantErr)
	})
}

func TestTunnelLostError(t *testing.T) {
	streamErr := status.Error(codes.Unavailable, "error reading from server: EOF")

	t.Run("no tunnel, nothing to report", func(t *testing.T) {
		assert.NoError(t, tunnelLostError(streamErr, nil))
	})

	t.Run("the tunnel broke, and that is what is reported", func(t *testing.T) {
		lost := make(chan error, 1)
		lost <- portforward.ErrLostConnectionToPod
		err := tunnelLostError(streamErr, lost)
		require.Error(t, err)
		assert.ErrorContains(t, err, "the tunnel through the Kubernetes API server")
		assert.ErrorIs(t, err, portforward.ErrLostConnectionToPod)
		assert.ErrorIs(t, err, streamErr, "the failure of the stream is kept too")
	})

	t.Run("the tunnel breaks just after the stream fails", func(t *testing.T) {
		lost := make(chan error, 1)
		go func() {
			time.Sleep(tunnelLostGrace / 10)
			lost <- portforward.ErrLostConnectionToPod
		}()
		assert.ErrorIs(t, tunnelLostError(streamErr, lost), portforward.ErrLostConnectionToPod)
	})

	t.Run("the stream failed but the tunnel is fine, so it is not blamed", func(t *testing.T) {
		start := time.Now()
		assert.NoError(t, tunnelLostError(streamErr, make(chan error)))
		assert.GreaterOrEqual(t, time.Since(start), tunnelLostGrace, "it must give the tunnel time to report first")
	})

	t.Run("an error that a broken connection does not cause is returned at once", func(t *testing.T) {
		start := time.Now()
		assert.NoError(t, tunnelLostError(status.Error(codes.PermissionDenied, "no"), make(chan error)))
		assert.Less(t, time.Since(start), tunnelLostGrace)
	})
}

func TestRejectedRequestError(t *testing.T) {
	t.Run("unauthenticated names what the server accepts", func(t *testing.T) {
		err := rejectedRequestError(status.Error(codes.Unauthenticated, "invalid client credentials"), &options{})
		assert.ErrorContains(t, err, "invalid client credentials", "the server's own message is kept")
		assert.ErrorContains(t, err, "client certificate signed by the cluster's client CA")
		assert.Equal(t, codes.Unauthenticated, status.Code(errors.Unwrap(err)))
	})

	t.Run("permission denied without --namespace points at the cluster-wide permission", func(t *testing.T) {
		err := rejectedRequestError(status.Error(codes.PermissionDenied, "not allowed"), &options{})
		assert.ErrorContains(t, err, "to list the virtual resource")
		assert.ErrorContains(t, err, "cluster-wide, since --namespace was not given")
	})

	t.Run("permission denied names the verb --follow needs, and the Namespace", func(t *testing.T) {
		err := rejectedRequestError(status.Error(codes.PermissionDenied, "not allowed"), &options{follow: true, namespace: "web"})
		assert.ErrorContains(t, err, "to watch the virtual resource")
		assert.ErrorContains(t, err, `in Namespace "web"`)
	})

	t.Run("anything else is reported as a failure to start the stream", func(t *testing.T) {
		err := rejectedRequestError(status.Error(codes.InvalidArgument, "bad scope"), &options{})
		assert.ErrorContains(t, err, "failed to start flow stream")
		assert.ErrorContains(t, err, "bad scope")
	})
}

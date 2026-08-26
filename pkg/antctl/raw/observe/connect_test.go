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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/v2/pkg/util/tlstest"
)

func alwaysReachable(context.Context, string) error { return nil }
func alwaysUnreachable(context.Context, string) error {
	return errors.New("connection refused")
}

func fakeTunnel(t *testing.T, localAddr string) (tunneler, *bool) {
	t.Helper()
	called := false
	return func(_ context.Context, _ *rest.Config, namespace, podName string, targetPort int) (string, func(), error) {
		called = true
		assert.Equal(t, "flow-aggregator", namespace)
		assert.Equal(t, "flow-aggregator-abc", podName)
		assert.Equal(t, flowStreamPort, targetPort)
		return localAddr, func() {}, nil
	}, &called
}

func TestResolveAddress_Auto(t *testing.T) {
	t.Run("direct connection succeeds, tunnel is never opened", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		addr, closeFn, err := resolveAddress(context.Background(), connectionModeAuto, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		defer closeFn()
		assert.Equal(t, "10.0.0.5:14740", addr)
		assert.False(t, *tunnelCalled, "tunnel should not be opened when the direct connection succeeds")
	})

	t.Run("direct connection fails, falls back to tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:54321")
		addr, closeFn, err := resolveAddress(context.Background(), connectionModeAuto, "10.0.0.5:14740",
			alwaysUnreachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		defer closeFn()
		assert.Equal(t, "127.0.0.1:54321", addr)
		assert.True(t, *tunnelCalled, "tunnel should be opened when the direct connection fails")
	})
}

func TestResolveAddress_Direct(t *testing.T) {
	t.Run("succeeds without ever considering a tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		addr, _, err := resolveAddress(context.Background(), connectionModeDirect, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.5:14740", addr)
		assert.False(t, *tunnelCalled)
	})

	t.Run("fails outright, never silently falls back to a tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		_, _, err := resolveAddress(context.Background(), connectionModeDirect, "10.0.0.5:14740",
			alwaysUnreachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.Error(t, err)
		assert.False(t, *tunnelCalled, "connectionModeDirect must never fall back to a tunnel")
	})
}

func TestResolveAddress_Tunnel(t *testing.T) {
	t.Run("always tunnels, even though direct would have succeeded", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:54321")
		addr, _, err := resolveAddress(context.Background(), connectionModeTunnel, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:54321", addr)
		assert.True(t, *tunnelCalled)
	})
}

func TestResolveAddress_InvalidMode(t *testing.T) {
	tunnel, _ := fakeTunnel(t, "127.0.0.1:9999")
	_, _, err := resolveAddress(context.Background(), connectionMode("bogus"), "10.0.0.5:14740",
		alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
	require.Error(t, err)
}

func TestDefaultDirectDialer(t *testing.T) {
	t.Run("reachable address", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer lis.Close()
		go func() {
			conn, err := lis.Accept()
			if err == nil {
				conn.Close()
			}
		}()
		assert.NoError(t, defaultDirectDialer(context.Background(), lis.Addr().String()))
	})

	t.Run("unreachable address", func(t *testing.T) {
		// Open and immediately close a listener: the OS will refuse connections to this
		// now-unused loopback port right away, rather than this test depending on some specific
		// external unreachable address.
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := lis.Addr().String()
		require.NoError(t, lis.Close())
		assert.Error(t, defaultDirectDialer(context.Background(), addr))
	})
}

// fakeCAProvider implements buildTLSConfig's anonymous ConfigMapCA interface for tests.
type fakeCAProvider struct {
	ca  []byte
	err error
}

func (f fakeCAProvider) ConfigMapCA(context.Context, string) ([]byte, error) { return f.ca, f.err }

func TestBuildTLSConfig(t *testing.T) {
	t.Run("insecureSkipVerify bypasses the CA lookup entirely", func(t *testing.T) {
		// erroringCA would fail the test (via require.Fail in ConfigMapCA) if it were ever called.
		erroringCA := fakeCAProvider{err: errors.New("must not be called")}
		cfg, err := buildTLSConfig(context.Background(), erroringCA, "flow-aggregator", "flow-aggregator.flow-aggregator.svc", true)
		require.NoError(t, err)
		assert.True(t, cfg.InsecureSkipVerify)
		assert.Equal(t, "flow-aggregator.flow-aggregator.svc", cfg.ServerName)
	})

	t.Run("CA lookup fails", func(t *testing.T) {
		_, err := buildTLSConfig(context.Background(), fakeCAProvider{err: errors.New("configmap not found")}, "flow-aggregator", "server-name", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--insecure-skip-tls-verify")
	})

	t.Run("CA data is not valid PEM", func(t *testing.T) {
		_, err := buildTLSConfig(context.Background(), fakeCAProvider{ca: []byte("not a cert")}, "flow-aggregator", "server-name", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("valid CA succeeds", func(t *testing.T) {
		certPEM, _, err := tlstest.GenerateCert([]string{"flow-aggregator.flow-aggregator.svc"}, time.Now(), time.Hour, true, false, 0, "P256", false)
		require.NoError(t, err)
		cfg, err := buildTLSConfig(context.Background(), fakeCAProvider{ca: certPEM}, "flow-aggregator", "flow-aggregator.flow-aggregator.svc", false)
		require.NoError(t, err)
		assert.False(t, cfg.InsecureSkipVerify)
		assert.Equal(t, "flow-aggregator.flow-aggregator.svc", cfg.ServerName)
		require.NotNil(t, cfg.RootCAs)
	})
}

func TestConfigMapCAReader(t *testing.T) {
	t.Run("ConfigMap found with the expected key", func(t *testing.T) {
		client := fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator", Name: flowAggregatorCAConfigMapName},
			Data:       map[string]string{flowAggregatorCAConfigMapKey: "ca-pem-bytes"},
		})
		reader := configMapCAReader{client: client}
		ca, err := reader.ConfigMapCA(context.Background(), "flow-aggregator")
		require.NoError(t, err)
		assert.Equal(t, []byte("ca-pem-bytes"), ca)
	})

	t.Run("ConfigMap found but missing the expected key", func(t *testing.T) {
		client := fake.NewSimpleClientset(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "flow-aggregator", Name: flowAggregatorCAConfigMapName},
			Data:       map[string]string{"unrelated-key": "value"},
		})
		reader := configMapCAReader{client: client}
		_, err := reader.ConfigMapCA(context.Background(), "flow-aggregator")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing key")
	})

	t.Run("ConfigMap not found", func(t *testing.T) {
		reader := configMapCAReader{client: fake.NewSimpleClientset()}
		_, err := reader.ConfigMapCA(context.Background(), "flow-aggregator")
		require.Error(t, err)
	})
}

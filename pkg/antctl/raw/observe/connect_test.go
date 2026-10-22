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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"

	"antrea.io/antrea/v2/pkg/util/tlstest"
)

func alwaysReachable(context.Context, string) error { return nil }
func alwaysUnreachable(context.Context, string) error {
	return errors.New("connection refused")
}

func fakeTunnel(t *testing.T, localAddr string) (tunneler, *bool) {
	t.Helper()
	called := false
	return func(_ context.Context, _ *rest.Config, namespace, podName string, targetPort int) (*endpoint, error) {
		called = true
		assert.Equal(t, "flow-aggregator", namespace)
		assert.Equal(t, "flow-aggregator-abc", podName)
		assert.Equal(t, flowStreamPort, targetPort)
		return &endpoint{addr: localAddr, lost: make(chan error), release: func() {}}, nil
	}, &called
}

func TestResolveAddress_Auto(t *testing.T) {
	t.Run("direct connection succeeds, tunnel is never opened", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		ep, err := resolveAddress(context.Background(), connectionModeAuto, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		defer ep.release()
		assert.Equal(t, "10.0.0.5:14740", ep.addr)
		assert.Nil(t, ep.lost, "a direct connection has no tunnel that can be lost")
		assert.False(t, *tunnelCalled, "tunnel should not be opened when the direct connection succeeds")
	})

	t.Run("direct connection fails, falls back to tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:54321")
		ep, err := resolveAddress(context.Background(), connectionModeAuto, "10.0.0.5:14740",
			alwaysUnreachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		defer ep.release()
		assert.Equal(t, "127.0.0.1:54321", ep.addr)
		assert.NotNil(t, ep.lost, "the tunnel must report if it is lost")
		assert.True(t, *tunnelCalled, "tunnel should be opened when the direct connection fails")
	})
}

func TestResolveAddress_Direct(t *testing.T) {
	t.Run("succeeds without ever considering a tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		ep, err := resolveAddress(context.Background(), connectionModeDirect, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.5:14740", ep.addr)
		assert.False(t, *tunnelCalled)
	})

	t.Run("fails outright, never silently falls back to a tunnel", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:9999")
		_, err := resolveAddress(context.Background(), connectionModeDirect, "10.0.0.5:14740",
			alwaysUnreachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.Error(t, err)
		assert.False(t, *tunnelCalled, "connectionModeDirect must never fall back to a tunnel")
	})
}

func TestResolveAddress_Tunnel(t *testing.T) {
	t.Run("always tunnels, even though direct would have succeeded", func(t *testing.T) {
		tunnel, tunnelCalled := fakeTunnel(t, "127.0.0.1:54321")
		ep, err := resolveAddress(context.Background(), connectionModeTunnel, "10.0.0.5:14740",
			alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1:54321", ep.addr)
		assert.True(t, *tunnelCalled)
	})
}

// startPortForwardServer starts what stands in for the Kubernetes API server where a port-forward is
// concerned: it completes the SPDY upgrade of a request to a Pod's portforward subresource, as the
// API server does, and hands its end of the connection to onConn. It returns a configuration for a
// client of that server. It does not forward anything: a test of the tunnel itself needs the
// connection to the "API server" and to see when it breaks, not the traffic through it.
func startPortForwardServer(t *testing.T, onConn func(httpstream.Connection)) *rest.Config {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/portforward") {
			http.NotFound(w, r)
			return
		}
		if _, err := httpstream.Handshake(r, w, []string{portforward.PortForwardProtocolV1Name}); err != nil {
			return
		}
		conn := spdy.NewResponseUpgrader().UpgradeResponse(w, r, func(httpstream.Stream, <-chan struct{}) error { return nil })
		if conn == nil {
			return
		}
		defer conn.Close()
		onConn(conn)
	}))
	t.Cleanup(server.Close)
	return &rest.Config{Host: server.URL}
}

// holdConnection is an onConn for startPortForwardServer that keeps the connection until the client
// closes it.
func holdConnection(conn httpstream.Connection) { <-conn.CloseChan() }

func TestSPDYTunnel(t *testing.T) {
	const timeout = 10 * time.Second

	t.Run("opens a tunnel on a local port and releases it", func(t *testing.T) {
		serverDone := make(chan struct{})
		restConfig := startPortForwardServer(t, func(conn httpstream.Connection) {
			<-conn.CloseChan()
			close(serverDone)
		})

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ep, err := spdyTunnel(ctx, restConfig, "flow-aggregator", "flow-aggregator-abc", flowStreamPort)
		require.NoError(t, err)
		host, port, err := net.SplitHostPort(ep.addr)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", host, "the tunnel must only be reachable from this host")
		assert.NotEqual(t, "0", port, "the port the forwarder picked must be reported, not the one asked for")
		require.NotNil(t, ep.lost)

		ep.release()
		ep.release() // Releasing again must be harmless.
		select {
		case <-serverDone:
		case <-time.After(timeout):
			t.Fatal("releasing the tunnel did not close the connection to the API server")
		}
		select {
		case err := <-ep.lost:
			t.Fatalf("a tunnel that was released on purpose must not be reported as lost, got %v", err)
		case <-time.After(300 * time.Millisecond):
		}
	})

	t.Run("reports the tunnel as lost when the connection to the API server breaks", func(t *testing.T) {
		breakConnection := make(chan struct{})
		restConfig := startPortForwardServer(t, func(conn httpstream.Connection) {
			<-breakConnection
			conn.Close()
		})

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ep, err := spdyTunnel(ctx, restConfig, "flow-aggregator", "flow-aggregator-abc", flowStreamPort)
		require.NoError(t, err)
		defer ep.release()

		close(breakConnection)
		select {
		case err := <-ep.lost:
			assert.ErrorIs(t, err, portforward.ErrLostConnectionToPod)
		case <-time.After(timeout):
			t.Fatal("a tunnel whose connection broke was never reported as lost")
		}
	})

	t.Run("the API server refuses the port-forward", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(http.NotFound))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err := spdyTunnel(ctx, &rest.Config{Host: server.URL}, "flow-aggregator", "flow-aggregator-abc", flowStreamPort)
		require.Error(t, err)
		assert.ErrorContains(t, err, "port forwarding to flow-aggregator/flow-aggregator-abc failed")
	})

	t.Run("gives up when the context ends before the tunnel is ready", func(t *testing.T) {
		unblock := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-unblock }))
		// Cleanups run last in, first out: the handler is let go before the server waits for it.
		t.Cleanup(server.Close)
		t.Cleanup(func() { close(unblock) })

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := spdyTunnel(ctx, &rest.Config{Host: server.URL}, "flow-aggregator", "flow-aggregator-abc", flowStreamPort)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("a configuration that cannot make a client", func(t *testing.T) {
		restConfig := &rest.Config{
			Host:            "http://127.0.0.1:1",
			TLSClientConfig: rest.TLSClientConfig{Insecure: true, CAFile: "/does/not/matter"},
		}
		_, err := spdyTunnel(context.Background(), restConfig, "flow-aggregator", "flow-aggregator-abc", flowStreamPort)
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to create Kubernetes client")
	})
}

func TestResolveAddress_TunnelFails(t *testing.T) {
	tunnelErr := errors.New("port forwarding refused")
	failingTunnel := func(context.Context, *rest.Config, string, string, int) (*endpoint, error) { return nil, tunnelErr }

	for _, tc := range []struct {
		mode connectionMode
		dial directDialer
	}{
		{connectionModeTunnel, alwaysReachable},
		{connectionModeAuto, alwaysUnreachable},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			var stderr strings.Builder
			ep, err := resolveAddress(context.Background(), tc.mode, "10.0.0.5:14740",
				tc.dial, failingTunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", &stderr)
			assert.Nil(t, ep)
			assert.ErrorIs(t, err, tunnelErr)
			assert.Contains(t, stderr.String(), "Tunneling to flow-aggregator/flow-aggregator-abc through the API server")
			assert.NotContains(t, stderr.String(), "Connected via tunnel")
		})
	}
}

func TestResolveAddress_InvalidMode(t *testing.T) {
	tunnel, _ := fakeTunnel(t, "127.0.0.1:9999")
	_, err := resolveAddress(context.Background(), connectionMode("bogus"), "10.0.0.5:14740",
		alwaysReachable, tunnel, &rest.Config{}, "flow-aggregator", "flow-aggregator-abc", io.Discard)
	require.Error(t, err)
}

// tlsTestServer starts a server that speaks TLS with HTTP/2 negotiated through ALPN, like the Flow
// Aggregator's gRPC server does. It returns the server's address, and a TLS configuration under
// which its certificate verifies.
func tlsTestServer(t *testing.T) (string, *tls.Config) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	// Tests that make the client reject the certificate would otherwise log a handshake error each.
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	// httptest's certificate is issued for example.com, and for the loopback addresses.
	return server.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}
}

func TestTLSDirectDialer(t *testing.T) {
	t.Run("peer passes TLS verification", func(t *testing.T) {
		addr, tlsConfig := tlsTestServer(t)
		assert.NoError(t, tlsDirectDialer(tlsConfig)(context.Background(), addr))
	})

	t.Run("peer fails TLS verification", func(t *testing.T) {
		// A host that answers at the address, but is not the Flow Aggregator: it is reachable at the
		// TCP level, and must still not count as reachable.
		addr, tlsConfig := tlsTestServer(t)
		tlsConfig.RootCAs = x509.NewCertPool()
		err := tlsDirectDialer(tlsConfig)(context.Background(), addr)
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate")
	})

	t.Run("peer is not verified when verification is disabled", func(t *testing.T) {
		addr, _ := tlsTestServer(t)
		//nolint:gosec // The test needs a configuration that does not verify the peer.
		assert.NoError(t, tlsDirectDialer(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})(context.Background(), addr))
	})

	t.Run("peer that does not speak TLS", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer lis.Close()
		go func() {
			conn, err := lis.Accept()
			if err == nil {
				conn.Close()
			}
		}()
		assert.Error(t, tlsDirectDialer(&tls.Config{MinVersion: tls.VersionTLS12})(context.Background(), lis.Addr().String()))
	})

	t.Run("unreachable address", func(t *testing.T) {
		// Open and immediately close a listener: the OS will refuse connections to this
		// now-unused loopback port right away, rather than this test depending on some specific
		// external unreachable address.
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := lis.Addr().String()
		require.NoError(t, lis.Close())
		assert.Error(t, tlsDirectDialer(&tls.Config{MinVersion: tls.VersionTLS12})(context.Background(), addr))
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
		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
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

func TestFlowAggregatorServerName(t *testing.T) {
	assert.Equal(t, "flow-aggregator.flow-aggregator.svc", flowAggregatorServerName("flow-aggregator"))
	assert.Equal(t, "flow-aggregator.fa-2.svc", flowAggregatorServerName("fa-2"))
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

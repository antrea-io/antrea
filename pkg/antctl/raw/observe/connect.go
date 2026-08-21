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
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// flowStreamPort is the port on which every Flow Aggregator instance serves FlowStreamService.
// See pkg/flowaggregator/flowstreamservice/service.go.
const flowStreamPort = 14740

// connectionMode controls how observe reaches the Flow Aggregator's FlowStreamService.
type connectionMode string

const (
	// connectionModeAuto tries a direct connection first and falls back to a tunnel through the
	// API server only if that fails. This is the default: it is free when observe happens to run
	// somewhere with real network access to the Pod (e.g. a debug Pod, a bastion host with routed
	// Pod CIDRs), and it degrades gracefully everywhere else.
	connectionModeAuto connectionMode = "auto"
	// connectionModeDirect never tunnels: a failed direct connection is a hard error, not a
	// silent fallback. Useful for diagnosing connectivity issues.
	connectionModeDirect connectionMode = "direct"
	// connectionModeTunnel always tunnels through the API server's /portforward subresource,
	// skipping the direct-connection attempt entirely.
	connectionModeTunnel connectionMode = "tunnel"
)

// directDialTimeout bounds how long "auto" mode waits for a direct connection to succeed before
// falling back to a tunnel. It only needs to distinguish "actively unreachable" from "reachable";
// a real connection to a Pod IP on a shared network completes far faster than this.
const directDialTimeout = 2 * time.Second

// directDialer abstracts "is addr reachable" so that tests can force either branch of
// resolveAddress deterministically, without depending on the real network topology the test
// happens to run under.
type directDialer func(ctx context.Context, addr string) error

func defaultDirectDialer(ctx context.Context, addr string) error {
	dialCtx, cancel := context.WithTimeout(ctx, directDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// tunneler abstracts opening a tunnel to a Pod's port, returning a local address to dial instead
// and a function to close the tunnel. Tests can substitute a fake implementation.
type tunneler func(ctx context.Context, restConfig *rest.Config, namespace, podName string, targetPort int) (localAddr string, closeFn func(), err error)

// resolveAddress decides, and if needed opens, how to reach the Flow Aggregator, implementing the
// three connectionMode values. It deliberately never mixes direct and tunnel within a single
// mode: "direct" fails outright rather than silently tunneling, so connectivity problems remain
// visible instead of being papered over.
func resolveAddress(
	ctx context.Context,
	mode connectionMode,
	directAddr string,
	dial directDialer,
	tunnel tunneler,
	restConfig *rest.Config,
	namespace, podName string,
	stderr io.Writer,
) (addr string, closeFn func(), err error) {
	switch mode {
	case connectionModeDirect:
		fmt.Fprintf(stderr, "Connecting directly to %s...\n", directAddr)
		if err := dial(ctx, directAddr); err != nil {
			return "", nil, fmt.Errorf("direct connection to %s failed: %w", directAddr, err)
		}
		fmt.Fprintf(stderr, "Connected directly to %s\n", directAddr)
		return directAddr, func() {}, nil
	case connectionModeTunnel:
		return openTunnel(ctx, tunnel, restConfig, namespace, podName, stderr)
	case connectionModeAuto, "":
		fmt.Fprintf(stderr, "Attempting a direct connection to %s...\n", directAddr)
		if err := dial(ctx, directAddr); err == nil {
			fmt.Fprintf(stderr, "Connected directly to %s\n", directAddr)
			return directAddr, func() {}, nil
		}
		fmt.Fprintf(stderr, "Direct connection to %s failed, falling back to a tunnel through the API server\n", directAddr)
		return openTunnel(ctx, tunnel, restConfig, namespace, podName, stderr)
	default:
		return "", nil, fmt.Errorf("invalid connection mode %q, must be one of auto, direct, tunnel", mode)
	}
}

func openTunnel(ctx context.Context, tunnel tunneler, restConfig *rest.Config, namespace, podName string, stderr io.Writer) (string, func(), error) {
	fmt.Fprintf(stderr, "Tunneling to %s/%s through the API server...\n", namespace, podName)
	addr, closeFn, err := tunnel(ctx, restConfig, namespace, podName, flowStreamPort)
	if err != nil {
		return "", nil, err
	}
	fmt.Fprintf(stderr, "Connected via tunnel (local address %s)\n", addr)
	return addr, closeFn, nil
}

// spdyTunnel is the production tunneler. It goes through the API server's /portforward
// subresource rather than dialing the Pod IP directly, so it works even when the caller has no
// route to the cluster's Pod network at all. It mirrors
// test/e2e/utils/portforwarder/portforwarder.go, trimmed to a single ephemeral local port.
func spdyTunnel(ctx context.Context, restConfig *rest.Config, namespace, podName string, targetPort int) (string, func(), error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	reqURL := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create SPDY dialer: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", reqURL)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	errCh := make(chan error, 1)

	// Port 0 asks the forwarder to pick a free local port; the actual port is read back via
	// GetPorts() once ForwardPorts() signals readiness.
	ports := []string{fmt.Sprintf("0:%d", targetPort)}
	pf, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, ports, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		close(stopCh)
		return "", nil, fmt.Errorf("failed to set up port forwarding to %s/%s: %w", namespace, podName, err)
	}

	go func() { errCh <- pf.ForwardPorts() }()

	select {
	case err := <-errCh:
		return "", nil, fmt.Errorf("port forwarding to %s/%s failed: %w", namespace, podName, err)
	case <-readyCh:
	case <-ctx.Done():
		close(stopCh)
		return "", nil, ctx.Err()
	}

	forwardedPorts, err := pf.GetPorts()
	if err != nil || len(forwardedPorts) == 0 {
		close(stopCh)
		return "", nil, fmt.Errorf("failed to determine the forwarded local port for %s/%s: %w", namespace, podName, err)
	}

	localAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(forwardedPorts[0].Local))
	closed := false
	closeFn := func() {
		if !closed {
			closed = true
			close(stopCh)
		}
	}
	return localAddr, closeFn, nil
}

// buildTLSConfig builds the client-side TLS configuration used to verify the Flow Aggregator's
// server certificate. FlowStreamService uses server-side TLS only (see PR #8191 and
// pkg/flowaggregator/flowstreamservice/service.go): there is no client certificate to present at
// the TLS layer, so this only ever configures server-verification material, never a client cert.
// Caller identity is instead carried as gRPC metadata (see auth.go) and validated by the server
// itself against the Kubernetes API.
func buildTLSConfig(ctx context.Context, k8sClient interface {
	ConfigMapCA(ctx context.Context, namespace string) ([]byte, error)
}, namespace string, serverName string, insecureSkipVerify bool) (*tls.Config, error) {
	if insecureSkipVerify {
		//nolint:gosec // explicit user opt-in via --insecure-skip-tls-verify, documented as dev/test only.
		return &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, nil
	}
	caPEM, err := k8sClient.ConfigMapCA(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to retrieve the Flow Aggregator's CA certificate (needed to verify its identity): %w\n"+
				"You can try running the command again with --insecure-skip-tls-verify", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse the Flow Aggregator's CA certificate")
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
}

// configMapCAReader fetches the flow-aggregator-ca ConfigMap's "ca.crt" key, the same ConfigMap
// and key antrea-ui's backend reads for the same purpose (see build/charts/antrea-ui's
// flowAggregator.caConfigMap value).
type configMapCAReader struct {
	client kubernetes.Interface
}

const (
	flowAggregatorCAConfigMapName = "flow-aggregator-ca"
	flowAggregatorCAConfigMapKey  = "ca.crt"
)

func (r configMapCAReader) ConfigMapCA(ctx context.Context, namespace string) ([]byte, error) {
	cm, err := r.client.CoreV1().ConfigMaps(namespace).Get(ctx, flowAggregatorCAConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	ca, ok := cm.Data[flowAggregatorCAConfigMapKey]
	if !ok {
		return nil, fmt.Errorf("missing key %q in ConfigMap %s/%s", flowAggregatorCAConfigMapKey, namespace, flowAggregatorCAConfigMapName)
	}
	return []byte(ca), nil
}

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
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
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

// directDialer abstracts "is addr reachable, and is it the Flow Aggregator" so that tests can force
// either branch of resolveAddress deterministically, without depending on the real network topology
// the test happens to run under.
type directDialer func(ctx context.Context, addr string) error

// tlsDirectDialer returns the production directDialer. It completes a TLS handshake with addr,
// verifying the peer with tlsConfig, rather than just opening a TCP connection. A TCP connection
// alone proves nothing about who answered: a Pod IP can be routable, but belong to a different host,
// from where observe runs (for example a laptop on a network that overlaps the Pod CIDR). Treating
// that as "reachable" would skip the tunnel, and send the caller's credentials to that host as soon
// as TLS verification is off. A peer that fails the handshake is reported as unreachable, so that
// "auto" mode falls back to the tunnel, and "direct" mode fails with the verification error.
func tlsDirectDialer(tlsConfig *tls.Config) directDialer {
	return func(ctx context.Context, addr string) error {
		dialCtx, cancel := context.WithTimeout(ctx, directDialTimeout)
		defer cancel()
		probeConfig := tlsConfig.Clone()
		// The server only accepts gRPC connections, which negotiate HTTP/2 through ALPN.
		probeConfig.NextProtos = []string{"h2"}
		conn, err := (&tls.Dialer{Config: probeConfig}).DialContext(dialCtx, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}

// endpoint is the address observe dials to reach the Flow Aggregator, and what has to be done once
// it is no longer needed.
type endpoint struct {
	addr string
	// lost delivers the error that broke the tunnel addr points at, if addr is a tunnel and it
	// breaks while in use. It is nil when observe connects directly.
	lost <-chan error
	// release frees what was opened to reach addr, such as a tunnel. It is safe to call more than
	// once.
	release func()
}

// directEndpoint is the endpoint for an address that is dialed as it is: there is nothing to
// release, and nothing that can break besides the connection itself.
func directEndpoint(addr string) *endpoint {
	return &endpoint{addr: addr, release: func() {}}
}

// tunneler abstracts opening a tunnel to a Pod's port, returning the local address to dial instead.
// Tests can substitute a fake implementation.
type tunneler func(ctx context.Context, restConfig *rest.Config, namespace, podName string, targetPort int) (*endpoint, error)

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
) (*endpoint, error) {
	switch mode {
	case connectionModeDirect:
		fmt.Fprintf(stderr, "Connecting directly to %s...\n", directAddr)
		if err := dial(ctx, directAddr); err != nil {
			return nil, fmt.Errorf("direct connection to %s failed: %w", directAddr, err)
		}
		fmt.Fprintf(stderr, "Connected directly to %s\n", directAddr)
		return directEndpoint(directAddr), nil
	case connectionModeTunnel:
		return openTunnel(ctx, tunnel, restConfig, namespace, podName, stderr)
	case connectionModeAuto, "":
		fmt.Fprintf(stderr, "Attempting a direct connection to %s...\n", directAddr)
		if err := dial(ctx, directAddr); err == nil {
			fmt.Fprintf(stderr, "Connected directly to %s\n", directAddr)
			return directEndpoint(directAddr), nil
		}
		fmt.Fprintf(stderr, "Direct connection to %s failed, falling back to a tunnel through the API server\n", directAddr)
		return openTunnel(ctx, tunnel, restConfig, namespace, podName, stderr)
	default:
		return nil, fmt.Errorf("invalid connection mode %q, must be one of auto, direct, tunnel", mode)
	}
}

func openTunnel(ctx context.Context, tunnel tunneler, restConfig *rest.Config, namespace, podName string, stderr io.Writer) (*endpoint, error) {
	fmt.Fprintf(stderr, "Tunneling to %s/%s through the API server...\n", namespace, podName)
	ep, err := tunnel(ctx, restConfig, namespace, podName, flowStreamPort)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "Connected via tunnel (local address %s)\n", ep.addr)
	return ep, nil
}

// spdyTunnel is the production tunneler. It goes through the API server's /portforward
// subresource rather than dialing the Pod IP directly, so it works even when the caller has no
// route to the cluster's Pod network at all. It mirrors
// test/e2e/utils/portforwarder/portforwarder.go, trimmed to a single ephemeral local port.
func spdyTunnel(ctx context.Context, restConfig *rest.Config, namespace, podName string, targetPort int) (*endpoint, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	reqURL := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SPDY dialer: %w", err)
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
		return nil, fmt.Errorf("failed to set up port forwarding to %s/%s: %w", namespace, podName, err)
	}

	go func() { errCh <- pf.ForwardPorts() }()

	select {
	case err := <-errCh:
		return nil, fmt.Errorf("port forwarding to %s/%s failed: %w", namespace, podName, err)
	case <-readyCh:
	case <-ctx.Done():
		close(stopCh)
		return nil, ctx.Err()
	}

	forwardedPorts, err := pf.GetPorts()
	if err != nil || len(forwardedPorts) == 0 {
		close(stopCh)
		return nil, fmt.Errorf("failed to determine the forwarded local port for %s/%s: %w", namespace, podName, err)
	}

	localAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(forwardedPorts[0].Local))

	// ForwardPorts keeps running for as long as the tunnel lives, and only returns when it ends: with
	// no error when stopCh was closed, that is, by release below, and with an error otherwise, most
	// notably portforward.ErrLostConnectionToPod when the connection to the API server breaks.
	// Nobody else is waiting for it any more at this point, so without this, a tunnel that breaks
	// would go unnoticed here, and show up only as a generic failure of the flow stream running over it.
	lost := make(chan error, 1)
	go func() {
		err := <-errCh
		select {
		case <-stopCh:
			// release was called: the tunnel ended on purpose.
		default:
			if err == nil {
				err = errors.New("the port forwarder stopped")
			}
			lost <- err
		}
	}()

	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(stopCh) }) }
	return &endpoint{addr: localAddr, lost: lost, release: release}, nil
}

// flowAggregatorServerName is the name the Flow Aggregator's server certificate is issued for, and
// that observe verifies it against. It depends only on the Flow Aggregator's Namespace, not on the
// Helm release name (see getFlowAggregatorServerNames in
// pkg/flowaggregator/certificate/provider.go), so it is not the name of whichever Service was
// discovered.
func flowAggregatorServerName(namespace string) string {
	return fmt.Sprintf("flow-aggregator.%s.svc", namespace)
}

// buildTLSConfig builds the client-side TLS configuration used to verify the Flow Aggregator's
// server certificate. It only configures server-verification material: when the caller
// authenticates with a client certificate, the caller sets GetClientCertificate on the returned
// config (see auth.go), since FlowStreamService requests but does not require a client certificate
// at the TLS layer. A bearer token is carried as gRPC metadata instead.
func buildTLSConfig(ctx context.Context, k8sClient interface {
	ConfigMapCA(ctx context.Context, namespace string) ([]byte, error)
}, namespace string, serverName string, insecureSkipVerify bool) (*tls.Config, error) {
	if insecureSkipVerify {
		//nolint:gosec // explicit user opt-in via --insecure-skip-tls-verify, documented as dev/test only.
		return &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
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

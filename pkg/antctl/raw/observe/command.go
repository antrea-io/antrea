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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/v2/pkg/antctl/raw"
	"antrea.io/antrea/v2/pkg/antctl/runtime"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/util/env"
)

// Command is the observe command implementation.
var Command *cobra.Command

// flowStreamKeepaliveTime is how often the client sends an HTTP/2 keepalive ping while connected
// to the Flow Aggregator's FlowStreamService.
//
// This value is set as low as it safely can be, not as low as would be ideal: the FlowStreamService
// gRPC server (pkg/flowaggregator/flowstreamservice/service.go) never configures its own
// grpc.KeepaliveEnforcementPolicy, so it runs on grpc-go's built-in default of
// EnforcementPolicy{MinTime: 5 * time.Minute} (google.golang.org/grpc/internal/transport/defaults.go,
// defaultKeepalivePolicyMinTime). Pinging more often than that trips the server's ping-abuse
// protection after a couple of strikes: GOAWAY(ENHANCE_YOUR_CALM, "too_many_pings"), which tears
// down the connection outright.
//
// TODO: this is a stopgap, not the intended value. Consider adding an explicit KeepaliveEnforcementPolicy
// on the FlowStreamService server, sized to accommodate a short client-side interval.
// Until then, a Flow Aggregator that disappears without a clean TCP close (e.g. a genuine silent network
// partition, as opposed to a normal Pod deletion) can leave antctl observe hanging for up to
// this long before it notices and exits.
const flowStreamKeepaliveTime = 5*time.Minute + 30*time.Second

// defaultFlowAggregatorNamespace is used only as a fallback when --flow-aggregator-address
// bypasses discovery and the user did not also set --flow-aggregator-namespace: there is no
// discovered Pod to read a Namespace from, but a Namespace is still needed to fetch the
// flow-aggregator-ca ConfigMap for TLS verification. It is NOT the default for discovery itself
// (see discoverFlowAggregator): that default must remain cluster-wide, otherwise silently
// narrowing the search to this one Namespace could hide a second instance in another Namespace
// entirely, which is exactly the "silently pick one when several exist" behavior multi-instance
// discovery is meant to avoid.
const defaultFlowAggregatorNamespace = "flow-aggregator"

type options struct {
	namespace string
	podNames  []string
	selector  string
	services  []string
	flowTypes []string
	ips       []string
	direction string

	since    string
	maxCount uint32
	follow   bool

	output        string
	humanReadable bool

	// flowAggregatorAddress, when set, bypasses discovery and the tunnel fallback entirely: the
	// user is asserting they already have a reachable address.
	flowAggregatorAddress string
	// flowAggregator, when set as "<namespace>/<service-name>", skips only the discovery
	// search, not the direct-dial/tunnel connection logic.
	flowAggregator          string
	flowAggregatorNamespace string
	connectionMode          string
	insecureSkipTLSVerify   bool
}

var o = &options{}

func init() {
	Command = &cobra.Command{
		Use:   "observe",
		Short: "Stream live flow records from a Flow Aggregator",
		Long: "Stream live flow records from a Flow Aggregator's FlowStreamService. " +
			"Supports two modes: remote, which runs out-of-cluster, discovering and " +
			"connecting to the Flow Aggregator through the Kubernetes API " +
			"server rather than requiring a direct network route to its Pod; and in-Pod, when " +
			"run from inside the Flow Aggregator's own Pod, which connects directly to its own " +
			"FlowStreamService using the Pod's own ServiceAccount credentials, with no " +
			"discovery or tunneling involved. Discovery-related flags " +
			"(--flow-aggregator-address, --flow-aggregator, --flow-aggregator-namespace, " +
			"--connection-mode) are rejected in-Pod.",
		Example: strings.Trim(`
  Stream all flows involving Namespace "default"
  $ antctl observe -n default
  Stream flows to/from Pods matching a label selector, as JSON
  $ antctl observe -l app=frontend -o json
  Show flows from the last 5 minutes, then keep streaming new ones
  $ antctl observe --since 5m --follow
  Connect to a specific Flow Aggregator instance when more than one exists
  $ antctl observe --flow-aggregator flow-aggregator-2/flow-aggregator
  From inside the Flow Aggregator Pod itself, observing its own flows
  $ antctl observe
`, "\n"),
		RunE: runE,
		Args: cobra.NoArgs,
	}

	Command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Observe flows where the source or destination Pod is in this Namespace (default: all Namespaces, which needs permission cluster-wide)")
	Command.Flags().StringSliceVar(&o.podNames, "pod", nil, "Match flows where the source or destination Pod name is in this list")
	Command.Flags().StringVarP(&o.selector, "selector", "l", "", "Match flows where the source or destination Pod labels match this selector")
	Command.Flags().StringSliceVar(&o.services, "service", nil, "Match flows where the destination Service name is in this list")
	Command.Flags().StringSliceVar(&o.flowTypes, "flow-type", nil, "Match flows of this type: intra-node, inter-node, to-external, from-external")
	Command.Flags().StringSliceVar(&o.ips, "ip", nil, "Match flows where the source or destination IP is in this list (CIDR notation supported)")
	Command.Flags().StringVar(&o.direction, "direction", "both", "Which side of a flow the other filters are matched against: both, from, to")

	Command.Flags().StringVar(&o.since, "since", "", "Only show flows ending after this time: a duration (e.g. \"5m\") or an RFC3339 timestamp")
	Command.Flags().Uint32Var(&o.maxCount, "max-count", 0, "Maximum number of flows to show in total (0 means unlimited)")
	Command.Flags().BoolVarP(&o.follow, "follow", "f", false, "Keep streaming new flows after historical flows are shown, like \"kubectl logs -f\" (default: exit once historical flows are shown)")

	Command.Flags().StringVarP(&o.output, "output", "o", "text", "Output format: text, json")
	Command.Flags().BoolVar(&o.humanReadable, "human-readable", false, "Show the TOTAL BYTES column in text output using KB/MB/GB/... units instead of raw bytes (text output only; ignored with -o json)")

	Command.Flags().StringVar(&o.flowAggregatorAddress, "flow-aggregator-address", "", "Connect directly to this address (host:port), bypassing discovery and the tunnel fallback")
	Command.Flags().StringVar(&o.flowAggregator, "flow-aggregator", "", "Connect to the Flow Aggregator behind this Service, as <namespace>/<service-name>, bypassing discovery")
	Command.Flags().StringVar(&o.flowAggregatorNamespace, "flow-aggregator-namespace", "", "Namespace to search for a Flow Aggregator Service labeled observability.antrea.io/flow-stream-service=true (default: search cluster-wide); also used to read its CA certificate from when combined with --flow-aggregator-address (in which case it defaults to flow-aggregator)")
	Command.Flags().StringVar(&o.connectionMode, "connection-mode", string(connectionModeAuto), "How to connect to the Flow Aggregator: auto, direct, tunnel")
	Command.Flags().BoolVar(&o.insecureSkipTLSVerify, "insecure-skip-tls-verify", false, "Skip verification of the Flow Aggregator's TLS certificate (dev/test only)")
}

// inFlowAggregatorPod is true when observe is running as the Flow Aggregator itself would run
// antctl in-Pod (POD_NAME prefixed "flow-aggregator", see pkg/antctl/runtime): observing its own
// FlowStreamService, not someone else's. This is the only in-Pod case this command supports —
// running from inside an Agent or Controller Pod has no co-located FlowStreamService to observe,
// so remote mode (discovery + tunnel/direct-dial) remains the only option there.
func inFlowAggregatorPod() bool {
	return runtime.Mode == runtime.ModeFlowAggregator && runtime.InPod
}

func runE(cmd *cobra.Command, _ []string) error {
	inPod := inFlowAggregatorPod()
	if !inPod && (runtime.Mode != runtime.ModeController || runtime.InPod) {
		return fmt.Errorf("observe only supports remote mode, or running inside the Flow Aggregator Pod")
	}
	mode := connectionMode(o.connectionMode)
	if inPod {
		// None of these mean anything once there is nothing to discover and nowhere to tunnel
		// to: silently ignoring them would be more surprising than rejecting them outright.
		for _, flag := range []string{"flow-aggregator-address", "flow-aggregator", "flow-aggregator-namespace", "connection-mode"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("--%s cannot be used when running inside the Flow Aggregator Pod: "+
					"there is nothing to discover or connect to but this instance's own FlowStreamService", flag)
			}
		}
	} else {
		if o.flowAggregatorAddress != "" && o.flowAggregator != "" {
			return fmt.Errorf("--flow-aggregator-address and --flow-aggregator are mutually exclusive")
		}
		if o.flowAggregatorAddress != "" && mode == connectionModeTunnel {
			return fmt.Errorf("--connection-mode=tunnel cannot be used with --flow-aggregator-address: there is no Pod to tunnel to; " +
				"omit --flow-aggregator-address, or use --flow-aggregator <namespace>/<service-name> instead")
		}
	}
	switch outputFormat(o.output) {
	case outputText, outputJSON:
	default:
		return fmt.Errorf("invalid --output %q, must be one of text, json", o.output)
	}

	ctx := cmd.Context()

	// In-Pod, use the Pod's own ServiceAccount identity directly rather than resolving a
	// kubeconfig (there is no kubeconfig file to find, and none should be looked for): this is
	// also what makes credentialForFlowAggregator forward this Pod's own ServiceAccount token
	// as-is below (the in-cluster config sets BearerToken), rather than laundering any other
	// credential through it.
	var kubeconfig *rest.Config
	var err error
	if inPod {
		kubeconfig, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("failed to load in-cluster config: %w", err)
		}
	} else {
		kubeconfig, err = raw.ResolveKubeconfig(cmd)
		if err != nil {
			return err
		}
	}
	k8sClientset, _, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	req, err := buildRequest(o)
	if err != nil {
		return err
	}
	if warning := futureSinceWarning(req, o.since, time.Now()); warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), warning)
	}

	if o.insecureSkipTLSVerify {
		fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: --insecure-skip-tls-verify is set: the identity of the Flow Aggregator is not "+
			"verified, so whoever answers at the address used receives your credentials, including a bearer token")
	}
	// The TLS configuration is needed before connecting, because a direct connection is only
	// accepted once the peer has passed TLS verification (see tlsDirectDialer). It depends on the
	// Flow Aggregator's Namespace, which discovery may be what finds out.
	buildTLS := func(namespace string) (*tls.Config, error) {
		return buildTLSConfig(ctx, configMapCAReader{client: k8sClientset}, namespace,
			flowAggregatorServerName(namespace), o.insecureSkipTLSVerify)
	}

	var ep *endpoint
	var tlsConfig *tls.Config
	if inPod {
		ep = directEndpoint(net.JoinHostPort("127.0.0.1", fmt.Sprint(flowStreamPort)))
		// The CA ConfigMap and the server certificate's SAN both live in/name this Pod's own
		// Namespace (see getFlowAggregatorServerNames in pkg/flowaggregator/certificate/provider.go,
		// which reads the same POD_NAMESPACE env var env.GetPodNamespace does) — there is no
		// discovery step here to have found it another way.
		tlsConfig, err = buildTLS(env.GetPodNamespace())
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Running inside the Flow Aggregator Pod; connecting to its own FlowStreamService at %s\n", ep.addr)
	} else {
		ep, tlsConfig, err = connect(ctx, o, k8sClientset, kubeconfig, mode, buildTLS, cmd.ErrOrStderr())
		if err != nil {
			return fmt.Errorf("failed to connect to the Flow Aggregator: %w", err)
		}
	}
	defer ep.release()

	cred, err := credentialForFlowAggregator(ctx, kubeconfig)
	if err != nil {
		return err
	}
	// A client certificate is presented during the TLS handshake. It is end to end between observe
	// and the Flow Aggregator, so it works unchanged through the tunnel.
	tlsConfig.GetClientCertificate = cred.getClientCertificate

	// Keepalives matter here specifically because observe must exit promptly on disconnect.
	// Without them, a peer that disappears without a clean TCP close (e.g. its Pod is deleted outright, rather
	// than given time to send a FIN) can leave this connection looking alive indefinitely: with
	// no data flowing and no keepalive probes, nothing tells the client the peer is gone. PermitWithoutStream
	// is required because between historical-flow batches (or with a static --since/--max-count
	// query already answered) there may be no active stream for seconds at a time.
	conn, err := grpc.NewClient(ep.addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                flowStreamKeepaliveTime,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer conn.Close()

	client := flowpb.NewFlowStreamServiceClient(conn)
	stream, err := client.GetFlows(metadata.NewOutgoingContext(ctx, cred.metadata), req)
	if err != nil {
		return fmt.Errorf("failed to start flow stream: %w", err)
	}

	out := newRenderer(outputFormat(o.output), cmd.OutOrStdout(), cmd.ErrOrStderr(), o.humanReadable)
	// The server sends an empty first response once it has authenticated and authorized the
	// request, before it reads any flow. An error before it is therefore the server rejecting this
	// request, not a stream that broke.
	established := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			// io.EOF: the server closed the stream on its own (e.g. --follow was omitted so
			// draining history finished, or --max-count was reached) — a normal, successful exit.
			// Anything else, including the connection dropping mid-stream, is surfaced as an error.
			if errors.Is(err, io.EOF) {
				return nil
			}
			if tunnelErr := tunnelLostError(err, ep.lost); tunnelErr != nil {
				return tunnelErr
			}
			if !established {
				return rejectedRequestError(err, o)
			}
			return fmt.Errorf("flow stream ended unexpectedly: %w", err)
		}
		established = true
		if err := out.render(resp.GetFlows(), resp.GetDroppedCount()); err != nil {
			return err
		}
	}
}

// tunnelLostGrace is how long observe waits, after the flow stream broke, to learn whether the
// tunnel it runs over broke too. A broken tunnel and the failure of the stream over it are one
// event seen from two sides, and which side notices first is not determined.
const tunnelLostGrace = time.Second

// tunnelLostError reports a failure of the flow stream as what it is, when it was caused by the
// tunnel through the Kubernetes API server breaking: without it, the user would see only a
// transport error of the stream, with nothing to say that it is the path to the Flow Aggregator,
// and not the Flow Aggregator, that went away. It returns nil when there is no tunnel, when err is
// not the kind of error that a broken connection causes, or when the tunnel did not break.
func tunnelLostError(err error, tunnelLost <-chan error) error {
	if tunnelLost == nil || status.Code(err) != codes.Unavailable {
		return nil
	}
	select {
	case lostErr := <-tunnelLost:
		return fmt.Errorf("the tunnel through the Kubernetes API server to the Flow Aggregator was lost (%w), "+
			"which ended the flow stream: %w", lostErr, err)
	case <-time.After(tunnelLostGrace):
		return nil
	}
}

// rejectedRequestError explains a failure that arrived before the server confirmed the stream, i.e.
// the Flow Aggregator refused this request rather than a working stream breaking. The server's own
// message is always kept; what is added is what the user can do about it.
func rejectedRequestError(err error, o *options) error {
	switch status.Code(err) {
	case codes.Unauthenticated:
		return fmt.Errorf("the Flow Aggregator did not accept the credentials in your kubeconfig: %w\n"+
			"It accepts a bearer token, or a client certificate signed by the cluster's client CA", err)
	case codes.PermissionDenied:
		verb, scope := "list", "cluster-wide, since --namespace was not given"
		if o.follow {
			verb = "watch"
		}
		if o.namespace != "" {
			scope = fmt.Sprintf("in Namespace %q", o.namespace)
		}
		return fmt.Errorf("%w\nObserving flows needs RBAC permission to %s the virtual resource "+
			"\"flows\" in API group \"observability.antrea.io\", %s", err, verb, scope)
	default:
		return fmt.Errorf("failed to start flow stream: %w", err)
	}
}

// connect resolves how to reach the Flow Aggregator's FlowStreamService and, when a tunnel is
// needed, opens it. buildTLS is called with the Flow Aggregator's Namespace, once it is known, to
// get the TLS configuration that the peer of a direct connection is verified with. connect returns
// the endpoint to dial, which the caller must release, and that TLS configuration.
func connect(ctx context.Context, o *options, k8sClientset kubernetes.Interface, kubeconfig *rest.Config, mode connectionMode,
	buildTLS func(namespace string) (*tls.Config, error), stderr io.Writer) (*endpoint, *tls.Config, error) {
	if o.flowAggregatorAddress != "" {
		tlsNamespace := o.flowAggregatorNamespace
		if tlsNamespace == "" {
			// Unlike discovery, there is no cluster-wide search happening here to accidentally
			// narrow, so falling back to the conventional Namespace name is safe and just
			// saves typing it in the common case.
			tlsNamespace = defaultFlowAggregatorNamespace
		}
		tlsConfig, err := buildTLS(tlsNamespace)
		if err != nil {
			return nil, nil, err
		}
		// The user asserted a directly-reachable address; there is no discovered Pod to tunnel
		// to, so this always behaves like connectionModeDirect regardless of --connection-mode.
		// The address is not probed first: there is no alternative to fall back to if it does not
		// answer, so a probe would only add a second, independent chance to fail, on a slow link
		// for instance. gRPC reports a failure to connect, or to verify the peer, when the stream
		// starts.
		fmt.Fprintf(stderr, "Connecting to %s (specified via --flow-aggregator-address, bypassing discovery)...\n", o.flowAggregatorAddress)
		return directEndpoint(o.flowAggregatorAddress), tlsConfig, nil
	}

	target, err := resolveTarget(ctx, o, k8sClientset, stderr)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := buildTLS(target.namespace)
	if err != nil {
		return nil, nil, err
	}
	directAddr := net.JoinHostPort(target.podIP, fmt.Sprint(flowStreamPort))
	fmt.Fprintf(stderr, "Connecting to Flow Aggregator Pod %s/%s (connection mode: %s)\n", target.namespace, target.podName, mode)
	ep, err := resolveAddress(ctx, mode, directAddr, tlsDirectDialer(tlsConfig), spdyTunnel, kubeconfig, target.namespace, target.podName, stderr)
	if err != nil {
		return nil, nil, err
	}
	return ep, tlsConfig, nil
}

func resolveTarget(ctx context.Context, o *options, k8sClientset kubernetes.Interface, stderr io.Writer) (*flowAggregatorTarget, error) {
	if o.flowAggregator != "" {
		parts := strings.SplitN(o.flowAggregator, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid --flow-aggregator %q, must be <namespace>/<service-name>", o.flowAggregator)
		}
		fmt.Fprintf(stderr, "Looking up Flow Aggregator %s/%s (specified via --flow-aggregator)...\n", parts[0], parts[1])
		target, err := findFlowAggregatorByName(ctx, k8sClientset, parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(stderr, "Found Flow Aggregator Service %s/%s, Pod %s (%s)\n", target.namespace, target.serviceName, target.podName, target.podIP)
		return target, nil
	}
	fmt.Fprintf(stderr, "Discovering Flow Aggregator instance (searching %s)...\n", describeSearchScope(o.flowAggregatorNamespace))
	target, err := discoverFlowAggregator(ctx, k8sClientset, o.flowAggregatorNamespace)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "Discovered Flow Aggregator Service %s/%s, Pod %s (%s)\n", target.namespace, target.serviceName, target.podName, target.podIP)
	return target, nil
}

// describeSearchScope renders o.flowAggregatorNamespace for the "Discovering..." status message.
func describeSearchScope(namespace string) string {
	if namespace == "" {
		return "cluster-wide"
	}
	return fmt.Sprintf("Namespace %q", namespace)
}

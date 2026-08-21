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
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
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
// down the connection outright — confirmed live, not just from reading the default. 30 seconds of
// margin above the 5-minute floor absorbs timer/scheduling jitter without meaningfully slowing
// detection further.
//
// TODO: this is a stopgap, not the intended value. It was chosen to fit an enforcement policy the
// server never deliberately set with any real client's needs in mind, rather than one sized for
// what observe (or any liveness-conscious client) actually needs. The real fix is most likely an
// explicit, intentional grpc.KeepaliveEnforcementPolicy on the FlowStreamService server itself,
// sized to accommodate a short client-side interval — see the "Termination behavior" section of the
// antctl observe design doc for the original ~10s value this replaces and why prompt disconnect
// detection matters here. That's a change to shared server behavior affecting every FlowStreamService
// client, not just antctl, so it needs review beyond this package before making it. Until then, a
// Flow Aggregator that disappears without a clean TCP close (e.g. a genuine silent network
// partition, as opposed to a normal Pod deletion — which the OS reports as an ordinary
// connection-closed error well before this ever fires) can leave antctl observe hanging for up to
// this long before it notices and exits.
const flowStreamKeepaliveTime = 5*time.Minute + 30*time.Second

type options struct {
	namespaces []string
	podNames   []string
	selector   string
	services   []string
	flowTypes  []string
	ips        []string
	direction  string

	since    string
	maxCount uint32
	follow   bool

	output        string
	humanReadable bool

	// flowAggregatorAddress, when set, bypasses discovery and the tunnel fallback entirely: the
	// user is asserting they already have a reachable address (e.g. their own port-forward, or a
	// NodePort/LoadBalancer they exposed themselves) and takes responsibility for that being
	// true. It is not named --server to avoid colliding with antctl's existing persistent
	// -s/--server flag, which overrides the Kubernetes API server address, not the Flow
	// Aggregator's.
	flowAggregatorAddress string
	// flowAggregator, when set as "<namespace>/<deployment-name>", skips only the discovery
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
			"Supports two modes: remote (the common case), which runs out-of-cluster, " +
			"discovering and connecting to the Flow Aggregator through the Kubernetes API " +
			"server rather than requiring a direct network route to its Pod; and in-Pod, when " +
			"run from inside the Flow Aggregator's own Pod, which connects directly to its own " +
			"FlowStreamService using the Pod's own ServiceAccount credentials, with no " +
			"discovery or tunneling involved. Discovery-related flags " +
			"(--flow-aggregator-address, --flow-aggregator, --flow-aggregator-namespace, " +
			"--connection-mode) are rejected in-Pod: there is nothing to discover or connect " +
			"to but this instance's own FlowStreamService.",
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

	Command.Flags().StringSliceVarP(&o.namespaces, "namespace", "n", nil, "Match flows where the source or destination Pod Namespace is in this list")
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
	Command.Flags().StringVar(&o.flowAggregator, "flow-aggregator", "", "Connect to this Flow Aggregator instance, as <namespace>/<deployment-name>, bypassing discovery")
	Command.Flags().StringVar(&o.flowAggregatorNamespace, "flow-aggregator-namespace", "", "Namespace to search for a Flow Aggregator instance (default: search cluster-wide); also used to read its CA certificate from when combined with --flow-aggregator-address")
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
				"omit --flow-aggregator-address, or use --flow-aggregator <namespace>/<deployment-name> instead")
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
	// also what makes credentialForFlowAggregator's BearerTokenFile branch the one that fires
	// below, forwarding this Pod's own token as-is rather than laundering any other credential
	// through it.
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

	var addr, tlsNamespace string
	var closeConn func()
	if inPod {
		addr = net.JoinHostPort("127.0.0.1", fmt.Sprint(flowStreamPort))
		// The CA ConfigMap and the server certificate's SAN both live in/name this Pod's own
		// Namespace (see getFlowAggregatorServerNames in pkg/flowaggregator/certificate/provider.go,
		// which reads the same POD_NAMESPACE env var env.GetPodNamespace does) — there is no
		// discovery step here to have found it another way.
		tlsNamespace = env.GetPodNamespace()
		closeConn = func() {}
		fmt.Fprintf(cmd.ErrOrStderr(), "Running inside the Flow Aggregator Pod; connecting to its own FlowStreamService at %s\n", addr)
	} else {
		addr, tlsNamespace, closeConn, err = connect(ctx, k8sClientset, kubeconfig, mode, cmd.ErrOrStderr())
		if err != nil {
			return fmt.Errorf("failed to connect to the Flow Aggregator: %w", err)
		}
	}
	defer closeConn()

	tlsConfig, err := buildTLSConfig(ctx, configMapCAReader{client: k8sClientset}, tlsNamespace,
		fmt.Sprintf("flow-aggregator.%s.svc", tlsNamespace), o.insecureSkipTLSVerify)
	if err != nil {
		return err
	}

	creds, err := credentialForFlowAggregator(ctx, kubeconfig)
	if err != nil {
		return err
	}

	// Keepalives matter here specifically because observe must exit promptly on disconnect (§6 of
	// the design doc), not hang waiting for the Flow Aggregator to come back. Without them, a
	// peer that disappears without a clean TCP close (e.g. its Pod is deleted outright, rather
	// than given time to send a FIN) can leave this connection looking alive indefinitely: with
	// no data flowing and no keepalive probes, nothing tells the client the peer is gone. PermitWithoutStream
	// is required because between historical-flow batches (or with a static --since/--max-count
	// query already answered) there may be no active stream for seconds at a time.
	conn, err := grpc.NewClient(addr,
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
	stream, err := client.GetFlows(metadata.NewOutgoingContext(ctx, creds), req)
	if err != nil {
		return fmt.Errorf("failed to start flow stream: %w", err)
	}

	out := newRenderer(outputFormat(o.output), cmd.OutOrStdout(), o.humanReadable)
	for {
		resp, err := stream.Recv()
		if err != nil {
			// io.EOF: the server closed the stream on its own (e.g. --follow was omitted so
			// draining history finished, or --max-count was reached) — a normal, successful exit.
			// Anything else, including the connection dropping mid-stream, is surfaced as an
			// error: observe exits promptly rather than trying to reconnect and resume from the
			// ring buffer's current tail on its own. Retrying, if wanted, is left to the caller.
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("flow stream ended unexpectedly: %w", err)
		}
		if err := out.render(resp.GetFlows(), resp.GetDroppedCount()); err != nil {
			return err
		}
	}
}

// connect resolves how to reach the Flow Aggregator's FlowStreamService and, when a tunnel is
// needed, opens it. It returns the address to dial, the Namespace to use when fetching the CA
// certificate for TLS verification, and a function to release any tunnel that was opened.
func connect(ctx context.Context, k8sClientset kubernetes.Interface, kubeconfig *rest.Config, mode connectionMode, stderr io.Writer) (addr, tlsNamespace string, closeFn func(), err error) {
	if o.flowAggregatorAddress != "" {
		// The user asserted a directly-reachable address; there is no discovered Pod to tunnel
		// to, so this always behaves like connectionModeDirect regardless of --connection-mode
		fmt.Fprintf(stderr, "Connecting to %s (specified via --flow-aggregator-address, bypassing discovery)...\n", o.flowAggregatorAddress)
		if err := defaultDirectDialer(ctx, o.flowAggregatorAddress); err != nil {
			return "", "", nil, fmt.Errorf("direct connection to %s failed: %w", o.flowAggregatorAddress, err)
		}
		fmt.Fprintf(stderr, "Connected to %s\n", o.flowAggregatorAddress)
		tlsNamespace := o.flowAggregatorNamespace
		if tlsNamespace == "" {
			// Unlike discovery, there is no cluster-wide search happening here to accidentally
			// narrow, so falling back to the conventional Namespace name is safe and just
			// saves typing it in the common case.
			tlsNamespace = defaultFlowAggregatorNamespace
		}
		return o.flowAggregatorAddress, tlsNamespace, func() {}, nil
	}

	target, err := resolveTarget(ctx, k8sClientset, stderr)
	if err != nil {
		return "", "", nil, err
	}
	directAddr := net.JoinHostPort(target.podIP, fmt.Sprint(flowStreamPort))
	fmt.Fprintf(stderr, "Connecting to Flow Aggregator Pod %s/%s (connection mode: %s)\n", target.namespace, target.podName, mode)
	addr, closeFn, err = resolveAddress(ctx, mode, directAddr, defaultDirectDialer, spdyTunnel, kubeconfig, target.namespace, target.podName, stderr)
	if err != nil {
		return "", "", nil, err
	}
	return addr, target.namespace, closeFn, nil
}

func resolveTarget(ctx context.Context, k8sClientset kubernetes.Interface, stderr io.Writer) (*flowAggregatorTarget, error) {
	if o.flowAggregator != "" {
		parts := strings.SplitN(o.flowAggregator, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid --flow-aggregator %q, must be <namespace>/<deployment-name>", o.flowAggregator)
		}
		fmt.Fprintf(stderr, "Looking up Flow Aggregator %s/%s (specified via --flow-aggregator)...\n", parts[0], parts[1])
		target, err := findFlowAggregatorByName(ctx, k8sClientset, parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(stderr, "Found Flow Aggregator Pod %s/%s (%s)\n", target.namespace, target.podName, target.podIP)
		return target, nil
	}
	fmt.Fprintf(stderr, "Discovering Flow Aggregator instance (searching %s)...\n", describeSearchScope(o.flowAggregatorNamespace))
	target, err := discoverFlowAggregator(ctx, k8sClientset, o.flowAggregatorNamespace)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "Discovered Flow Aggregator Pod %s/%s (%s)\n", target.namespace, target.podName, target.podIP)
	return target, nil
}

// describeSearchScope renders o.flowAggregatorNamespace for the "Discovering..." status message.
func describeSearchScope(namespace string) string {
	if namespace == "" {
		return "cluster-wide"
	}
	return fmt.Sprintf("Namespace %q", namespace)
}

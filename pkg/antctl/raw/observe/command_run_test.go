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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/antctl/runtime"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/util/tlstest"
)

// These tests run runE itself, as antctl does, against a stand-in for the Flow Aggregator that is a
// real gRPC server speaking TLS, and a stand-in for the Kubernetes API server that serves the CA
// ConfigMap the Flow Aggregator's certificate is verified with. They connect with
// --flow-aggregator-address, since reaching a discovered Flow Aggregator would take its fixed port.
// What is not covered here is covered by the e2e tests: discovery, and the tunnel, carrying a stream.

// runBearerToken is the credential of the kubeconfig that these tests run runE with.
const runBearerToken = "token-of-the-caller"

const testFlowAggregatorNamespace = "flow-aggregator"

// remoteOptions returns the default flags with an explicitly selected, trusted Namespace.
func remoteOptions() options {
	return options{
		direction:               "both",
		output:                  "json",
		connectionMode:          string(connectionModeAuto),
		flowAggregatorNamespace: testFlowAggregatorNamespace,
	}
}

// setOptions replaces the flags that runE reads, which are package state, for the duration of a test.
func setOptions(t *testing.T, opts options) {
	t.Helper()
	saved := *o
	*o = opts
	t.Cleanup(func() { *o = saved })
}

// discoveryFlags are the flags that runE rejects in the Flow Aggregator Pod.
var discoveryFlags = []string{"flow-aggregator-address", "flow-aggregator", "flow-aggregator-namespace", "connection-mode"}

// newRunCommand returns a command to run runE with. It has the flags that runE, and the code it calls,
// read from the command itself rather than from options. Its standard output goes to stdout, and what
// it writes to the standard error is returned.
func newRunCommand(ctx context.Context, kubeconfig string, stdout io.Writer) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	cmd.Flags().String("kubeconfig", kubeconfig, "")
	cmd.Flags().StringSlice("columns", nil, "")
	for _, flag := range discoveryFlags {
		cmd.Flags().String(flag, "", "")
	}
	var stderr bytes.Buffer
	cmd.SetOut(stdout)
	cmd.SetErr(&stderr)
	cmd.SetContext(ctx)
	return cmd, &stderr
}

// flowStreamHandler is what a stand-in Flow Aggregator does with a request.
type flowStreamHandler func(req *flowpb.GetFlowsRequest, stream flowpb.FlowStreamService_GetFlowsServer) error

type fakeFlowStreamService struct {
	flowpb.UnimplementedFlowStreamServiceServer
	handle flowStreamHandler
}

func (s *fakeFlowStreamService) GetFlows(req *flowpb.GetFlowsRequest, stream flowpb.FlowStreamService_GetFlowsServer) error {
	return s.handle(req, stream)
}

// receivedRequest is a request as the stand-in Flow Aggregator saw it.
type receivedRequest struct {
	req           *flowpb.GetFlowsRequest
	authorization []string
	certificates  []*x509.Certificate
}

// serveFlows is a flowStreamHandler that behaves like the Flow Aggregator for a request that is
// accepted: it confirms the stream, sends each batch of flows as a response, and ends the stream.
// What it was asked is reported through received.
func serveFlows(received chan<- receivedRequest, batches ...[]*flowpb.Flow) flowStreamHandler {
	return func(req *flowpb.GetFlowsRequest, stream flowpb.FlowStreamService_GetFlowsServer) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		r := receivedRequest{req: req, authorization: md.Get(authorizationMetadataKey)}
		if p, ok := peer.FromContext(stream.Context()); ok {
			if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				r.certificates = tlsInfo.State.PeerCertificates
			}
		}
		received <- r
		if err := stream.Send(&flowpb.GetFlowsResponse{}); err != nil {
			return err
		}
		for _, flows := range batches {
			if err := stream.Send(&flowpb.GetFlowsResponse{Flows: flows}); err != nil {
				return err
			}
		}
		return nil
	}
}

// startFlowStreamService serves handle over TLS on a loopback port, with a certificate for the name that
// observe verifies the Flow Aggregator in the selected test Namespace by. It returns the address, and the
// PEM encoding of the certificate that verifies it.
func startFlowStreamService(t *testing.T, handle flowStreamHandler) (string, []byte) {
	t.Helper()
	certPEM, keyPEM, err := tlstest.GenerateCert([]string{flowAggregatorServerName(testFlowAggregatorNamespace)},
		time.Now().Add(-time.Minute), time.Hour, true, false, 0, "P256", false)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12,
	})))
	flowpb.RegisterFlowStreamServiceServer(server, &fakeFlowStreamService{handle: handle})
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	return lis.Addr().String(), certPEM
}

// writeKubeconfig writes a kubeconfig for a cluster whose API server serves caPEM as the CA ConfigMap of
// the Flow Aggregator in the selected test Namespace, or knows no such ConfigMap when caPEM is nil, and whose
// user authenticates with runBearerToken. It returns the path of the kubeconfig.
func writeKubeconfig(t *testing.T, caPEM []byte) string {
	t.Helper()
	return writeKubeconfigForUser(t, caPEM, "token: "+runBearerToken)
}

// writeKubeconfigForUser is writeKubeconfig for a user that is described by the given field of a
// kubeconfig, such as "token: <token>" or "tokenFile: <path>".
func writeKubeconfigForUser(t *testing.T, caPEM []byte, userField string) string {
	t.Helper()
	configMapPath := fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", testFlowAggregatorNamespace, flowAggregatorCAConfigMapName)
	// The server has to speak TLS: a kubeconfig's credentials are only read when it does.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if caPEM == nil || r.URL.Path != configMapPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&corev1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
			ObjectMeta: metav1.ObjectMeta{Namespace: testFlowAggregatorNamespace, Name: flowAggregatorCAConfigMapName},
			Data:       map[string]string{flowAggregatorCAConfigMapKey: string(caPEM)},
		})
	}))
	t.Cleanup(server.Close)
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: test
  user:
    %s
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
`, server.URL, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), userField)
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(kubeconfig), 0o600))
	return path
}

// streamFixture is a stand-in Flow Aggregator, and the kubeconfig with which it is reached.
type streamFixture struct {
	addr       string
	kubeconfig string
}

func newStreamFixture(t *testing.T, handle flowStreamHandler) *streamFixture {
	t.Helper()
	addr, caPEM := startFlowStreamService(t, handle)
	return &streamFixture{addr: addr, kubeconfig: writeKubeconfig(t, caPEM)}
}

// runTo runs runE, as the remote command, with opts and the fixture's address, and writes its standard
// output to stdout. It returns what runE wrote to the standard error, and its error.
func (f *streamFixture) runTo(t *testing.T, opts options, stdout io.Writer) (string, error) {
	t.Helper()
	withRuntimeMode(t, runtime.ModeController, false)
	opts.flowAggregatorAddress = f.addr
	setOptions(t, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd, stderr := newRunCommand(ctx, f.kubeconfig, stdout)
	err := runE(cmd, nil)
	return stderr.String(), err
}

func (f *streamFixture) run(t *testing.T, opts options) (stdout, stderr string, err error) {
	t.Helper()
	var out bytes.Buffer
	stderr, err = f.runTo(t, opts, &out)
	return out.String(), stderr, err
}

func receive(t *testing.T, received <-chan receivedRequest) receivedRequest {
	t.Helper()
	select {
	case r := <-received:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("the Flow Aggregator did not receive a request")
		return receivedRequest{}
	}
}

// decodeRecords decodes the line-delimited JSON output of the command.
func decodeRecords(t *testing.T, output string) []record {
	t.Helper()
	var records []record
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var r record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &r), "output line %q", line)
		records = append(records, r)
	}
	return records
}

func TestRunE_RefusesWhatCannotWork(t *testing.T) {
	// run runs runE with opts, and the flags the command line sets, up to the point where it fails.
	run := func(t *testing.T, opts options, kubeconfig string, flags map[string]string) error {
		t.Helper()
		setOptions(t, opts)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd, _ := newRunCommand(ctx, kubeconfig, io.Discard)
		for name, value := range flags {
			require.NoError(t, cmd.Flags().Set(name, value))
		}
		return runE(cmd, nil)
	}

	t.Run("running somewhere that is neither remote nor the Flow Aggregator Pod", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			mode  string
			inPod bool
		}{
			{"agent", runtime.ModeAgent, false},
			{"controller Pod", runtime.ModeController, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				withRuntimeMode(t, tc.mode, tc.inPod)
				err := run(t, remoteOptions(), "", nil)
				assert.ErrorContains(t, err, "observe only supports remote mode, or running inside the Flow Aggregator Pod")
			})
		}
	})

	t.Run("a flag that means nothing in the Flow Aggregator Pod", func(t *testing.T) {
		for _, flag := range discoveryFlags {
			t.Run(flag, func(t *testing.T) {
				withRuntimeMode(t, runtime.ModeFlowAggregator, true)
				err := run(t, remoteOptions(), "", map[string]string{flag: "value"})
				require.Error(t, err)
				assert.ErrorContains(t, err, "--"+flag+" cannot be used when running inside the Flow Aggregator Pod")
			})
		}
	})

	t.Run("the Flow Aggregator Pod without the credentials of its Pod", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeFlowAggregator, true)
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")
		err := run(t, remoteOptions(), "", nil)
		assert.ErrorContains(t, err, "failed to load in-cluster config")
	})

	t.Run("an address and a Service that name the same thing twice", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		opts := remoteOptions()
		opts.flowAggregatorAddress, opts.flowAggregator = "127.0.0.1:14740", "flow-aggregator/flow-aggregator"
		err := run(t, opts, "", nil)
		assert.ErrorContains(t, err, "--flow-aggregator-address and --flow-aggregator are mutually exclusive")
	})

	t.Run("a tunnel to an address", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		opts := remoteOptions()
		opts.flowAggregatorAddress, opts.connectionMode = "127.0.0.1:14740", string(connectionModeTunnel)
		err := run(t, opts, "", nil)
		assert.ErrorContains(t, err, "--connection-mode=tunnel cannot be used with --flow-aggregator-address")
	})

	t.Run("a trusted Namespace must be selected before loading credentials or discovering Services", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		for _, mode := range []connectionMode{connectionModeAuto, connectionModeDirect, connectionModeTunnel} {
			t.Run(string(mode), func(t *testing.T) {
				opts := remoteOptions()
				opts.flowAggregatorNamespace = ""
				opts.namespace = "a-flow-filter-is-not-a-trusted-namespace"
				opts.connectionMode = string(mode)
				err := run(t, opts, filepath.Join(t.TempDir(), "unread-kubeconfig"), nil)
				assert.ErrorContains(t, err, "requires --flow-aggregator-namespace or --flow-aggregator")
			})
		}
	})

	t.Run("an output format that does not exist", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		opts := remoteOptions()
		opts.output = "yaml"
		err := run(t, opts, "", nil)
		assert.ErrorContains(t, err, `invalid --output "yaml"`)
	})

	t.Run("a kubeconfig that does not exist", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		err := run(t, remoteOptions(), filepath.Join(t.TempDir(), "missing"), nil)
		assert.ErrorContains(t, err, "kubeconfig file does not exist")
	})

	t.Run("invalid column selection is rejected before loading credentials", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		for _, tc := range []struct {
			name    string
			output  string
			columns []string
			flags   map[string]string
			err     string
		}{
			{name: "unknown", output: "text", columns: []string{"unknown"}, err: `unknown column "unknown"`},
			{name: "duplicate", output: "text", columns: []string{"source", "source"}, err: `duplicate column "source"`},
			{name: "empty", output: "text", columns: []string{}, err: "requires at least one column"},
			{name: "explicit empty flag", output: "text", flags: map[string]string{"columns": ""}, err: "requires at least one column"},
			{name: "JSON", output: "json", columns: []string{"source"}, err: "--columns can only be used with text output"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				opts := remoteOptions()
				opts.output, opts.columns = tc.output, tc.columns
				err := run(t, opts, filepath.Join(t.TempDir(), "unread-kubeconfig"), tc.flags)
				assert.ErrorContains(t, err, tc.err)
			})
		}
	})

	t.Run("a filter that is wrong is reported before connecting to anything", func(t *testing.T) {
		withRuntimeMode(t, runtime.ModeController, false)
		opts := remoteOptions()
		opts.direction = "sideways"
		opts.flowAggregatorAddress = "127.0.0.1:1"
		err := run(t, opts, writeKubeconfig(t, nil), nil)
		assert.ErrorContains(t, err, `invalid --direction "sideways"`)
	})
}

func TestRunE_Stream(t *testing.T) {
	t.Run("an explicit address alone does not authorize trusting its CA or forwarding credentials", func(t *testing.T) {
		for _, insecure := range []bool{false, true} {
			t.Run(fmt.Sprintf("insecure=%t", insecure), func(t *testing.T) {
				received := make(chan receivedRequest, 1)
				f := newStreamFixture(t, serveFlows(received))
				opts := remoteOptions()
				opts.flowAggregatorNamespace = ""
				opts.insecureSkipTLSVerify = insecure
				stdout, _, err := f.run(t, opts)
				assert.ErrorContains(t, err, "requires --flow-aggregator-namespace or --flow-aggregator")
				assert.Empty(t, stdout)
				assert.Empty(t, received, "the server must not receive credentials without an explicit trust decision")
			})
		}
	})

	t.Run("impersonation is rejected before fetching the CA or contacting the Flow Aggregator", func(t *testing.T) {
		received := make(chan receivedRequest, 1)
		f := newStreamFixture(t, serveFlows(received))
		f.kubeconfig = writeKubeconfigForUser(t, nil, "token: "+runBearerToken+"\n    as: restricted-user\n    as-groups: [restricted-group]\n    as-uid: restricted-uid\n    as-user-extra:\n      scope: [restricted]")
		stdout, _, err := f.run(t, remoteOptions())
		assert.ErrorContains(t, err, "observe does not support kubeconfig impersonation")
		assert.Empty(t, stdout)
		assert.Empty(t, received)
	})

	t.Run("a newline-terminated tokenFile works through the kubeconfig loader and gRPC", func(t *testing.T) {
		received := make(chan receivedRequest, 1)
		addr, caPEM := startFlowStreamService(t, serveFlows(received))
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte(runBearerToken+"\n"), 0o600))
		f := &streamFixture{addr: addr, kubeconfig: writeKubeconfigForUser(t, caPEM, "tokenFile: "+path)}
		_, _, err := f.run(t, remoteOptions())
		require.NoError(t, err)
		assert.Equal(t, []string{"Bearer " + runBearerToken}, receive(t, received).authorization)
	})

	t.Run("both certificate and token are presented for the server to choose the identity", func(t *testing.T) {
		for _, fromFiles := range []bool{false, true} {
			t.Run(fmt.Sprintf("from-files=%t", fromFiles), func(t *testing.T) {
				received := make(chan receivedRequest, 1)
				addr, caPEM := startFlowStreamService(t, serveFlows(received))
				certPEM, keyPEM, certPath, keyPath := writeClientCert(t, t.TempDir())
				userFields := fmt.Sprintf("token: %s\n    client-certificate-data: %s\n    client-key-data: %s",
					runBearerToken, base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM))
				if fromFiles {
					tokenPath := filepath.Join(t.TempDir(), "token")
					require.NoError(t, os.WriteFile(tokenPath, []byte(runBearerToken+"\n"), 0o600))
					userFields = fmt.Sprintf("tokenFile: %s\n    client-certificate: %s\n    client-key: %s", tokenPath, certPath, keyPath)
				}
				f := &streamFixture{addr: addr, kubeconfig: writeKubeconfigForUser(t, caPEM, userFields)}
				_, _, err := f.run(t, remoteOptions())
				require.NoError(t, err)
				got := receive(t, received)
				assert.Equal(t, []string{"Bearer " + runBearerToken}, got.authorization)
				require.Len(t, got.certificates, 1)
				block, _ := pem.Decode(certPEM)
				require.NotNil(t, block)
				assert.Equal(t, block.Bytes, got.certificates[0].Raw)
			})
		}
	})

	t.Run("shows what the Flow Aggregator sends, as the user of the kubeconfig", func(t *testing.T) {
		received := make(chan receivedRequest, 1)
		f := newStreamFixture(t, serveFlows(received, []*flowpb.Flow{testFlow()}, []*flowpb.Flow{testFlow(), testFlow()}))

		stdout, stderr, err := f.run(t, remoteOptions())
		require.NoError(t, err)

		records := decodeRecords(t, stdout)
		require.Len(t, records, 3, "one record for each flow of each batch")
		assert.Equal(t, "perftest-a", records[0].SourcePodName)
		assert.Equal(t, "perftest-b", records[0].DestinationPodName)
		assert.Contains(t, stderr, "Connecting to "+f.addr)

		got := receive(t, received)
		assert.Equal(t, []string{"Bearer " + runBearerToken}, got.authorization, "the Flow Aggregator must see the caller's own credential")
		assert.True(t, got.req.GetClusterWide(), "without --namespace, the scope is the cluster")
		assert.Empty(t, got.req.GetNamespaces())
	})

	t.Run("asks for what the flags say", func(t *testing.T) {
		received := make(chan receivedRequest, 1)
		f := newStreamFixture(t, serveFlows(received))

		opts := remoteOptions()
		opts.namespace, opts.podNames, opts.maxCount, opts.follow = "web", []string{"frontend-1"}, 3, true
		_, _, err := f.run(t, opts)
		require.NoError(t, err)

		got := receive(t, received).req
		assert.Equal(t, []string{"web"}, got.GetNamespaces())
		assert.False(t, got.GetClusterWide())
		assert.True(t, got.GetFollow())
		assert.EqualValues(t, 3, got.GetMaxCount())
		require.Len(t, got.GetFilters(), 1)
		assert.Equal(t, []string{"frontend-1"}, got.GetFilters()[0].GetPodNames())
	})

	t.Run("text output", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1), []*flowpb.Flow{testFlow()}))

		opts := remoteOptions()
		opts.output = "text"
		stdout, _, err := f.run(t, opts)
		require.NoError(t, err)
		assert.Contains(t, stdout, "SOURCE")
		assert.Contains(t, stdout, "default/perftest-a")
		assert.Contains(t, stdout, "default/perftest-b")
	})

	t.Run("selected columns reach the renderer", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1), []*flowpb.Flow{enrichedFlow()}))
		opts := remoteOptions()
		opts.output = "text"
		opts.columns = []string{"tcpState", "sourceNodeName", "ingressNetworkPolicyRuleName"}
		stdout, _, err := f.run(t, opts)
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
		require.Len(t, lines, 2)
		assert.Equal(t, opts.columns, strings.Fields(lines[0]))
		assert.Equal(t, []string{"ESTABLISHED", "worker-1", "http"}, strings.Fields(lines[1]))
	})

	t.Run("a --since in the future is warned about, and not refused", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1)))

		opts := remoteOptions()
		opts.since = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		_, stderr, err := f.run(t, opts)
		require.NoError(t, err)
		assert.Contains(t, stderr, "warning: --since "+opts.since+" is in the future")
	})

	t.Run("--insecure-skip-tls-verify warns that credentials may go to anyone, and needs no CA", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1), []*flowpb.Flow{testFlow()}))
		f.kubeconfig = writeKubeconfig(t, nil) // The CA ConfigMap is not available.

		opts := remoteOptions()
		opts.insecureSkipTLSVerify = true
		stdout, stderr, err := f.run(t, opts)
		require.NoError(t, err)
		assert.Contains(t, stderr, "WARNING: --insecure-skip-tls-verify is set")
		assert.Len(t, decodeRecords(t, stdout), 1)
	})

	t.Run("the CA of the Flow Aggregator cannot be read", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1)))
		f.kubeconfig = writeKubeconfig(t, nil)

		_, _, err := f.run(t, remoteOptions())
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to connect to the Flow Aggregator")
		assert.ErrorContains(t, err, "failed to retrieve the Flow Aggregator's CA certificate")
	})

	t.Run("a server that the CA does not vouch for gets no request and no credential", func(t *testing.T) {
		received := make(chan receivedRequest, 1)
		f := newStreamFixture(t, serveFlows(received, []*flowpb.Flow{testFlow()}))
		_, otherCA := startFlowStreamService(t, serveFlows(make(chan receivedRequest, 1)))
		f.kubeconfig = writeKubeconfig(t, otherCA)

		stdout, _, err := f.run(t, remoteOptions())
		require.Error(t, err)
		assert.ErrorContains(t, err, "certificate")
		assert.Empty(t, stdout)
		assert.Empty(t, received, "the request, and the credential in it, must not reach a server that was not verified")
	})

	t.Run("an address where nothing listens", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1)))
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		f.addr = lis.Addr().String()
		require.NoError(t, lis.Close())

		_, _, err = f.run(t, remoteOptions())
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to start flow stream")
	})

	t.Run("the Flow Aggregator refuses the request", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			code codes.Code
			want string
		}{
			{"unauthenticated", codes.Unauthenticated, "did not accept the credentials in your kubeconfig"},
			{"permission denied", codes.PermissionDenied, "needs RBAC permission to list the virtual resource"},
			{"anything else", codes.Internal, "failed to start flow stream"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newStreamFixture(t, func(*flowpb.GetFlowsRequest, flowpb.FlowStreamService_GetFlowsServer) error {
					return status.Error(tc.code, "refused")
				})
				_, _, err := f.run(t, remoteOptions())
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.want)
				assert.ErrorContains(t, err, "refused", "what the Flow Aggregator said is kept")
			})
		}
	})

	t.Run("the stream breaks after it was confirmed", func(t *testing.T) {
		f := newStreamFixture(t, func(_ *flowpb.GetFlowsRequest, stream flowpb.FlowStreamService_GetFlowsServer) error {
			if err := stream.Send(&flowpb.GetFlowsResponse{}); err != nil {
				return err
			}
			return status.Error(codes.Unavailable, "going away")
		})
		_, _, err := f.run(t, remoteOptions())
		require.Error(t, err)
		assert.ErrorContains(t, err, "flow stream ended unexpectedly")
		assert.ErrorContains(t, err, "going away")
	})

	t.Run("the credential of the kubeconfig cannot be read", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1)))
		missing := filepath.Join(t.TempDir(), "missing-token")
		f.kubeconfig = writeKubeconfigForUser(t, nil, "tokenFile: "+missing)

		opts := remoteOptions()
		opts.insecureSkipTLSVerify = true // So that the credential is not needed to read the CA ConfigMap.
		_, _, err := f.run(t, opts)
		require.Error(t, err)
		assert.ErrorContains(t, err, missing)
	})

	t.Run("the output cannot be written", func(t *testing.T) {
		f := newStreamFixture(t, serveFlows(make(chan receivedRequest, 1), []*flowpb.Flow{testFlow()}))
		_, err := f.runTo(t, remoteOptions(), &erroringWriter{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "write failed")
	})
}

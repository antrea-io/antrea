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

package proxy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/kubectl/pkg/proxy"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/runtime"
)

const (
	defaultPort         = 8001
	defaultStaticPrefix = "/static/"
	defaultAPIPrefix    = "/"
	defaultAddress      = "127.0.0.1"
)

// Command is the proxy command implementation.
var Command *cobra.Command

type proxyOptions struct {
	staticDir     string
	staticPrefix  string
	apiPrefix     string
	acceptPaths   string
	rejectPaths   string
	acceptHosts   string
	rejectMethods string
	port          int
	address       string
	disableFilter bool
	unixSocket    string
	keepalive     time.Duration

	filter *proxy.FilterServer

	controller    bool
	agentNodeName string
	insecure      bool
}

var options *proxyOptions
var defaultFS = afero.NewOsFs()

// validateAndComplete checks the proxyOptions to see if there is sufficient information to run the
// command, and adds default values when needed.
func (o *proxyOptions) validateAndComplete() error {
	if o.port != defaultPort && o.unixSocket != "" {
		return fmt.Errorf("cannot set --unix-socket and --port at the same time")
	}

	if o.controller && o.agentNodeName != "" {
		return fmt.Errorf("cannot use --controller and --agent-node at the same time")
	}
	if !o.controller && o.agentNodeName == "" {
		// default to controller
		o.controller = true
	}

	if o.staticDir != "" {
		fileInfo, err := defaultFS.Stat(o.staticDir)
		if err != nil {
			klog.InfoS("Failed to stat static file directory", "name", o.staticDir, "error", err)
		} else if !fileInfo.IsDir() {
			klog.InfoS("Static file directory is not a directory", "name", o.staticDir)
		}
	}

	if !strings.HasSuffix(o.staticPrefix, "/") {
		o.staticPrefix += "/"
	}

	if !strings.HasSuffix(o.apiPrefix, "/") {
		o.apiPrefix += "/"
	}

	if o.disableFilter {
		if o.unixSocket == "" {
			klog.Warning("Request filter disabled, your proxy is vulnerable to XSRF attacks, please be cautious")
		}
		o.filter = nil
	} else {
		o.filter = &proxy.FilterServer{
			AcceptPaths:   proxy.MakeRegexpArrayOrDie(o.acceptPaths),
			RejectPaths:   proxy.MakeRegexpArrayOrDie(o.rejectPaths),
			AcceptHosts:   proxy.MakeRegexpArrayOrDie(o.acceptHosts),
			RejectMethods: proxy.MakeRegexpArrayOrDie(o.rejectMethods),
		}
	}

	return nil
}

var proxyCommandExample = strings.Trim(`
  Start a reverse proxy for the Antrea Controller API
  $ antctl proxy --controller
  Start a reverse proxy for the API of an Antrea Agent running on a specific Node
  $ antctl proxy --agent-node <Node Name>
`, "\n")

func init() {
	Command = &cobra.Command{
		Use:     "proxy",
		Short:   "Run a reverse proxy to access Antrea API",
		Long:    "Run a reverse proxy to access Antrea API (Controller or Agent). Command only supports remote mode. HTTPS connections between the proxy and the Antrea API will not be secure (no certificate verification).",
		Example: proxyCommandExample,
		RunE:    runE,
		Args:    cobra.NoArgs,
	}

	o := &proxyOptions{}
	options = o
	// These options are the same as for "kubectl proxy".
	// https://github.com/kubernetes/kubectl/blob/v0.19.0/pkg/cmd/proxy/proxy.go
	Command.Flags().StringVarP(&o.staticDir, "www", "w", "", "Also serve static files from the given directory under the specified prefix.")
	Command.Flags().StringVarP(&o.staticPrefix, "www-prefix", "P", defaultStaticPrefix, "Prefix to serve static files under, if static file directory is specified.")
	Command.Flags().StringVarP(&o.apiPrefix, "api-prefix", "", defaultAPIPrefix, "Prefix to serve the proxied API under.")
	Command.Flags().StringVar(&o.acceptPaths, "accept-paths", proxy.DefaultPathAcceptRE, "Regular expression for paths that the proxy should accept.")
	Command.Flags().StringVar(&o.rejectPaths, "reject-paths", proxy.DefaultPathRejectRE, "Regular expression for paths that the proxy should reject. Paths specified here will be rejected even accepted by --accept-paths.")
	Command.Flags().StringVar(&o.acceptHosts, "accept-hosts", proxy.DefaultHostAcceptRE, "Regular expression for hosts that the proxy should accept.")
	Command.Flags().StringVar(&o.rejectMethods, "reject-methods", proxy.DefaultMethodRejectRE, "Regular expression for HTTP methods that the proxy should reject (example --reject-methods='POST,PUT,PATCH'). ")
	Command.Flags().IntVarP(&o.port, "port", "p", defaultPort, "The port on which to run the proxy. Set to 0 to pick a random port.")
	Command.Flags().StringVarP(&o.address, "address", "", defaultAddress, "The IP address on which to serve on.")
	Command.Flags().BoolVar(&o.disableFilter, "disable-filter", false, "If true, disable request filtering in the proxy. This is dangerous, and can leave you vulnerable to XSRF attacks, when used with an accessible port.")
	Command.Flags().StringVarP(&o.unixSocket, "unix-socket", "u", "", "Unix socket on which to run the proxy.")
	Command.Flags().DurationVar(&o.keepalive, "keepalive", 0, "keepalive specifies the keep-alive period for an active network connection. Set to 0 to disable keepalive.")

	// These options are specific to "antctl proxy".
	Command.Flags().BoolVar(&o.controller, "controller", false, "Run proxy for Antrea Controller API. If both --controller and --agent-node are omitted, the proxy will run for the Controller API.")
	Command.Flags().StringVar(&o.agentNodeName, "agent-node", "", "Run proxy for Antrea Agent API on the provided K8s Node.")
	Command.Flags().BoolVar(&o.insecure, "insecure", false, "Skip TLS verification when connecting to Antrea API.")
}

func runE(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if runtime.Mode != runtime.ModeController || runtime.InPod {
		return fmt.Errorf("only remote mode is supported for this command")
	}

	if err := options.validateAndComplete(); err != nil {
		return err
	}

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	if server, _ := Command.Flags().GetString("server"); server != "" {
		kubeconfig.Host = server
	}

	k8sClientset, antreaClientset, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	insecure, _ := Command.Flags().GetBool("insecure")
	var clientCfg *rest.Config
	if options.controller {
		clientCfg, err = raw.CreateControllerClientCfg(ctx, k8sClientset, antreaClientset, kubeconfig, insecure)
		if err != nil {
			return fmt.Errorf("error when creating Controller client config: %w", err)
		}
	} else {
		clientCfg, err = raw.CreateAgentClientCfg(ctx, k8sClientset, antreaClientset, kubeconfig, options.agentNodeName, insecure)
		if err != nil {
			return fmt.Errorf("error when creating Agent client config: %w", err)
		}
	}

	// The last argument is for "appendLocationPath", which for "kubectl proxy" is used as
	// follows: if the Kubeconfig context provides a server URL which includes a Path comppnent
	// (e.g., https://example.com/PATH), then this path is automatically added to all incoming
	// requests to the proxy.
	// See https://github.com/kubernetes/kubernetes/pull/97350
	// In our case, we craft the config manually and clientCfg.Host never includes a Path
	// component, so we always set "appendLocationPath" to "false", and there is no need to
	// expose a flag like --append-server-path for "antctl proxy".
	server, err := proxy.NewServer(options.staticDir, options.apiPrefix, options.staticPrefix, options.filter, clientCfg, options.keepalive, false)

	if err != nil {
		return err
	}

	// Separate listening from serving so we can report the bound port when it is chosen by os
	// (eg: port == 0).
	var l net.Listener
	if options.unixSocket == "" {
		addr := options.address
		if net.ParseIP(addr).To4() == nil {
			addr = fmt.Sprintf("[%s]", addr)
		}
		l, err = server.Listen(addr, options.port)
	} else {
		l, err = server.ListenUnix(options.unixSocket)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Starting to serve on %s\n", l.Addr().String())
	return server.ServeOnListener(l)
}

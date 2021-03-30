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
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"k8s.io/kubectl/pkg/proxy"

	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	clusterinformationv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
	antrea "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
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
}

var options *proxyOptions

// validateAndComplete checks the proxyOptions to see if there is sufficient information to run the
// command, and adds default values when needed.
func (o *proxyOptions) validateAndComplete() error {
	if o.port != 0 && o.unixSocket != "" {
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
		fileInfo, err := os.Stat(o.staticDir)
		if err != nil {
			klog.Warningf("Failed to stat static file directory %s: %v", o.staticDir, err)
		} else if !fileInfo.IsDir() {
			klog.Warningf("Static file directory %s is not a directory", o.staticDir)
		}
	}

	o.port = defaultPort

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

	// Options are the same as for "kubectl proxy"
	// https://github.com/kubernetes/kubectl/blob/v0.19.0/pkg/cmd/proxy/proxy.go
	o := &proxyOptions{}
	options = o
	Command.Flags().StringVarP(&o.staticDir, "www", "w", "", "Also serve static files from the given directory under the specified prefix.")
	Command.Flags().StringVarP(&o.staticPrefix, "www-prefix", "P", defaultStaticPrefix, "Prefix to serve static files under, if static file directory is specified.")
	Command.Flags().StringVarP(&o.apiPrefix, "api-prefix", "", defaultAPIPrefix, "Prefix to serve the proxied API under.")
	Command.Flags().StringVar(&o.acceptPaths, "accept-paths", proxy.DefaultPathAcceptRE, "Regular expression for paths that the proxy should accept.")
	Command.Flags().StringVar(&o.rejectPaths, "reject-paths", proxy.DefaultPathRejectRE, "Regular expression for paths that the proxy should reject. Paths specified here will be rejected even accepted by --accept-paths.")
	Command.Flags().StringVar(&o.acceptHosts, "accept-hosts", proxy.DefaultHostAcceptRE, "Regular expression for hosts that the proxy should accept.")
	Command.Flags().StringVar(&o.rejectMethods, "reject-methods", proxy.DefaultMethodRejectRE, "Regular expression for HTTP methods that the proxy should reject (example --reject-methods='POST,PUT,PATCH'). ")
	Command.Flags().IntVarP(&o.port, "port", "p", o.port, "The port on which to run the proxy. Set to 0 to pick a random port.")
	Command.Flags().StringVarP(&o.address, "address", "", defaultAddress, "The IP address on which to serve on.")
	Command.Flags().BoolVar(&o.disableFilter, "disable-filter", false, "If true, disable request filtering in the proxy. This is dangerous, and can leave you vulnerable to XSRF attacks, when used with an accessible port.")
	Command.Flags().StringVarP(&o.unixSocket, "unix-socket", "u", "", "Unix socket on which to run the proxy.")
	Command.Flags().DurationVar(&o.keepalive, "keepalive", 0, "keepalive specifies the keep-alive period for an active network connection. Set to 0 to disable keepalive.")
	Command.Flags().BoolVar(&o.controller, "controller", false, "Run proxy for Antrea Controller API. If both --controller and --agent-node are omitted, the proxy will run for the Controller API.")
	Command.Flags().StringVar(&o.agentNodeName, "agent-node", "", "Run proxy for Antrea Agent API on the provided K8s Node.")
}

// TODO: enable secure connection. For the Antrea Controller, we can do it by using the CA
// certificate published in the antrea-ca ConfigMap. For Antrea Agents, this is not possible at the
// moment (CA not available).
func setupKubeconfig(kubeconfig *rest.Config) {
	kubeconfig.Insecure = true
	kubeconfig.CAFile = ""
	kubeconfig.CAData = nil
}

func createAgentClientCfg(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config, nodeName string) (*rest.Config, error) {
	node, err := k8sClientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when looking up Node %s: %w", nodeName, err)
	}
	// TODO: filter by Node name, but that would require API support
	agentInfoList, err := antreaClientset.ClusterinformationV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	var agentInfo *clusterinformationv1beta1.AntreaAgentInfo
	for i := range agentInfoList.Items {
		ai := agentInfoList.Items[i]
		if ai.NodeRef.Name == nodeName {
			agentInfo = &ai
			break
		}
	}
	if agentInfo == nil {
		return nil, fmt.Errorf("no Antrea Agent found for Node name %s", nodeName)
	}
	nodeIP, err := noderoute.GetNodeAddr(node)
	if err != nil {
		return nil, fmt.Errorf("error when parsing IP of Node %s", nodeName)
	}
	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP.String(), fmt.Sprint(agentInfo.APIPort)))
	return cfg, nil
}

func createControllerClientCfg(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (*rest.Config, error) {
	controllerInfo, err := antreaClientset.ClusterinformationV1beta1().AntreaControllerInfos().Get(context.TODO(), "antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	controllerNode, err := k8sClientset.CoreV1().Nodes().Get(context.TODO(), controllerInfo.NodeRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when searching the Node of the controller: %w", err)
	}
	var controllerNodeIP net.IP
	controllerNodeIP, err = noderoute.GetNodeAddr(controllerNode)
	if err != nil {
		return nil, fmt.Errorf("error when parsing controller IP: %w", err)
	}

	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(controllerNodeIP.String(), fmt.Sprint(controllerInfo.APIPort)))
	return cfg, nil
}

func runE(cmd *cobra.Command, _ []string) error {
	if runtime.Mode != runtime.ModeController || runtime.InPod {
		return fmt.Errorf("only remote mode is supported for this command")
	}

	if err := options.validateAndComplete(); err != nil {
		return err
	}

	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeconfig, err := runtime.ResolveKubeconfig(kubeconfigPath)
	if err != nil {
		return err
	}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	setupKubeconfig(restconfigTmpl)
	if server, err := Command.Flags().GetString("server"); err != nil {
		kubeconfig.Host = server
	}

	k8sClientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create K8s clientset: %w", err)
	}
	antreaClientset, err := antrea.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating Antrea clientset: %w", err)
	}

	var clientCfg *rest.Config
	if options.controller {
		clientCfg, err = createControllerClientCfg(k8sClientset, antreaClientset, restconfigTmpl)
		if err != nil {
			return fmt.Errorf("error when creating Controller client config: %w", err)
		}
	} else {
		clientCfg, err = createAgentClientCfg(k8sClientset, antreaClientset, restconfigTmpl, options.agentNodeName)
		if err != nil {
			return fmt.Errorf("error when creating Agent client config: %w", err)
		}
	}

	server, err := proxy.NewServer(options.staticDir, options.apiPrefix, options.staticPrefix, options.filter, clientCfg, options.keepalive)

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

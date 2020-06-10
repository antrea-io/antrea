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

package supportbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	agentapiserver "github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	controllerapiserver "github.com/vmware-tanzu/antrea/pkg/apiserver"
	antrea "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

const (
	barTmpl      pb.ProgressBarTemplate = `{{string . "prefix"}}{{bar . }} {{percent . }} {{rtime . "ETA %s"}}` // Example: 'Prefix[-->______] 20%'
	requestRate                         = 50
	requestBurst                        = 100
	timeFormat                          = "20060102T150405Z0700"
)

// Command is the support bundle command implementation.
var Command *cobra.Command

var option = &struct {
	dir            string
	labelSelector  string
	controllerOnly bool
}{}

var remoteControllerLongDescription = strings.TrimSpace(`
Generate support bundles for the cluster, which include: information about each Antrea agent, information about the Antrea controller and general information about the cluster.
The controller support bundle will always be collected no matter whether the master Node is selected or not.
`)

var remoteControllerExample = strings.Trim(`
  Generate support bundles of controller and agent on all Nodes and save them to current working dir
  $ antctl supportbundle
  Generate support bundles of specific Nodes filtered by name, with support for wildcard expressions
  $ antctl supportbundles '*worker*'
  Generate support bundles of specific Nodes filtered by name and label selectors
  $ antctl supportbundles '*worker*' -l kubernetes.io/os=linux
  Generate support bundles of controller and agent on all Nodes and save them to specific dir
  $ antctl supportbundle -d ~/Downloads
`, "\n")

func init() {
	Command = &cobra.Command{
		Use:   "supportbundle",
		Short: "Generate support bundle",
	}

	if runtime.Mode == runtime.ModeAgent {
		Command.RunE = agentRunE
		Command.Long = "Generate the support bundle of current antrea agent."
	} else if runtime.Mode == runtime.ModeController && runtime.InPod {
		Command.RunE = controllerLocalRunE
		Command.Long = "Generate the support bundle of current antrea controller."
	} else if runtime.Mode == runtime.ModeController && !runtime.InPod {
		Command.Args = cobra.MaximumNArgs(1)
		Command.Use += " [nodeName]"
		Command.Long = remoteControllerLongDescription
		Command.Example = remoteControllerExample
		Command.Flags().StringVarP(&option.dir, "dir", "d", "", "support bundles output dir, the path will be created if it doesn't exist")
		Command.Flags().StringVarP(&option.labelSelector, "label-selector", "l", "", "selector (label query) to filter nodes, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
		Command.Flags().BoolVar(&option.controllerOnly, "controller-only", false, "only collect the support bundle of the antrea controller")
		Command.RunE = controllerRemoteRunE
	}
}

// TODO: enable secure connection.
// TODO: generate kubeconfig in antrea agent for antctl in-Pod access.
func setupKubeconfig(kubeconfig *rest.Config) {
	kubeconfig.APIPath = "/apis"
	kubeconfig.GroupVersion = &systemv1beta1.SchemeGroupVersion
	kubeconfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	kubeconfig.Insecure = true
	kubeconfig.CAFile = ""
	kubeconfig.CAData = nil
	if runtime.InPod {
		if runtime.Mode == runtime.ModeAgent {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", "10350")
			kubeconfig.BearerTokenFile = agentapiserver.TokenPath
		} else {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", "10349")
			kubeconfig.BearerTokenFile = controllerapiserver.TokenPath
		}
	}
}

func localSupportBundleRequest(cmd *cobra.Command, mode string) error {
	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeconfig, err := runtime.ResolveKubeconfig(kubeconfigPath)
	if err != nil {
		return err
	}
	setupKubeconfig(kubeconfig)
	client, err := rest.RESTClientFor(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating rest client: %w", err)
	}
	_, err = client.Post().
		Resource("supportbundles").
		Body(&systemv1beta1.SupportBundle{ObjectMeta: metav1.ObjectMeta{Name: mode}}).
		DoRaw()
	if err != nil {
		return fmt.Errorf("error when requesting the agent support bundle: %w", err)
	}
	for {
		var supportBundle systemv1beta1.SupportBundle
		err := client.Get().
			Resource("supportbundles").
			Name(mode).
			Do().
			Into(&supportBundle)
		if err != nil {
			return fmt.Errorf("error when requesting the agent support bundle: %w", err)
		}
		if supportBundle.Status == systemv1beta1.SupportBundleStatusCollected {
			fmt.Printf("Created bundle under %s\n", os.TempDir())
			fmt.Printf("Expire time: %s\n", supportBundle.DeletionTimestamp)
			break
		}
	}
	return nil

}

func agentRunE(cmd *cobra.Command, _ []string) error {
	return localSupportBundleRequest(cmd, runtime.ModeAgent)
}

func controllerLocalRunE(cmd *cobra.Command, _ []string) error {
	return localSupportBundleRequest(cmd, runtime.ModeController)
}

func request(component string, client *rest.RESTClient) error {
	var err error
	_, err = client.Post().
		Resource("supportbundles").
		Body(&systemv1beta1.SupportBundle{ObjectMeta: metav1.ObjectMeta{Name: component}}).
		DoRaw()
	if err == nil {
		return nil
	}
	return err
}

func mapClients(prefix string, agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, bar *pb.ProgressBar, af, cf func(nodeName string, c *rest.RESTClient) error) error {
	bar.Set("prefix", prefix)
	rateLimiter := rate.NewLimiter(requestRate, requestBurst)
	g, ctx := errgroup.WithContext(context.Background())
	for nodeName, client := range agentClients {
		rateLimiter.Wait(ctx)
		nodeName, client := nodeName, client
		g.Go(func() error {
			defer bar.Increment()
			return af(nodeName, client)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	defer bar.Increment()
	return cf("", controllerClient)
}

func requestAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, bar *pb.ProgressBar) error {
	return mapClients(
		"Requesting",
		agentClients,
		controllerClient,
		bar,
		func(nodeName string, c *rest.RESTClient) error {
			return request(runtime.ModeAgent, c)
		},
		func(nodeName string, c *rest.RESTClient) error {
			return request(runtime.ModeController, c)
		},
	)
}

func download(suffix, downloadPath string, client *rest.RESTClient, component string) error {
	for {
		var supportBundle systemv1beta1.SupportBundle
		err := client.Get().Resource("supportbundles").Name(component).Do().Into(&supportBundle)
		if err != nil {
			return fmt.Errorf("error when requesting the agent support bundle: %w", err)
		}
		if supportBundle.Status == systemv1beta1.SupportBundleStatusCollected {
			if len(downloadPath) == 0 {
				break
			}
			var fileName string
			if len(suffix) > 0 {
				fileName = path.Join(downloadPath, fmt.Sprintf("%s_%s.tar.gz", component, suffix))
			} else {
				fileName = path.Join(downloadPath, fmt.Sprintf("%s.tar.gz", component))
			}
			f, err := os.Create(fileName)
			if err != nil {
				return fmt.Errorf("error when creating the support bundle tar gz: %w", err)
			}
			defer f.Close()
			stream, err := client.Get().
				Resource("supportbundles").
				Name(component).
				SubResource("download").
				Stream()
			if err != nil {
				return fmt.Errorf("error when downloading the support bundle: %w", err)
			}
			defer stream.Close()
			if _, err := io.Copy(f, stream); err != nil {
				return fmt.Errorf("error when downloading the support bundle: %w", err)
			}
			break
		}
	}
	return nil
}

func downloadAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, downloadPath string, bar *pb.ProgressBar) error {
	return mapClients(
		"Downloading",
		agentClients,
		controllerClient,
		bar,
		func(nodeName string, c *rest.RESTClient) error {
			return download(nodeName, downloadPath, c, runtime.ModeAgent)
		},
		func(nodeName string, c *rest.RESTClient) error {
			return download("", downloadPath, c, runtime.ModeController)
		},
	)
}

func createSupportBundleClients(filter string, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (map[string]*rest.RESTClient, *rest.RESTClient, error) {
	clients := map[string]*rest.RESTClient{}
	if !option.controllerOnly {
		nodeAgentInfoMap := map[string]string{}
		agentInfoList, err := antreaClientset.ClusterinformationV1beta1().AntreaAgentInfos().List(metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, agentInfo := range agentInfoList.Items {
			nodeAgentInfoMap[agentInfo.NodeRef.Name] = fmt.Sprint(agentInfo.APIPort)
		}
		nodeList, err := k8sClientset.CoreV1().Nodes().List(metav1.ListOptions{LabelSelector: option.labelSelector})
		if err != nil {
			return nil, nil, err
		}
		for _, node := range nodeList.Items {
			if match, _ := filepath.Match(filter, node.Name); !match {
				continue
			}
			port, ok := nodeAgentInfoMap[node.Name]
			if !ok {
				continue
			}
			ip, err := noderoute.GetNodeAddr(&node)
			if err != nil {
				klog.Warningf("Error when parsing IP of Node %s", node.Name)
				continue
			}
			cfg := rest.CopyConfig(cfgTmpl)
			cfg.Host = net.JoinHostPort(ip.String(), port)
			client, err := rest.RESTClientFor(cfg)
			if err != nil {
				klog.Warningf("Error when creating agent client for node: %s", node.Name)
				continue
			}
			clients[node.Name] = client
		}
	}

	controllerInfo, err := antreaClientset.ClusterinformationV1beta1().AntreaControllerInfos().Get("antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	controllerNode, err := k8sClientset.CoreV1().Nodes().Get(controllerInfo.NodeRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("error when searching the Node of the controller: %w", err)
	}
	var controllerNodeIP net.IP
	controllerNodeIP, err = noderoute.GetNodeAddr(controllerNode)
	if err != nil {
		return nil, nil, fmt.Errorf("error when parsing controllre IP: %w", err)
	}

	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = net.JoinHostPort(controllerNodeIP.String(), fmt.Sprint(controllerInfo.APIPort))
	controllerClient, err := rest.RESTClientFor(cfg)
	if err != nil {
		klog.Warningf("Error when creating controller client for node: %s", controllerInfo.NodeRef.Name)
	}
	return clients, controllerClient, nil
}

func getClusterInfo(k8sClient kubernetes.Interface) (io.Reader, error) {
	g := new(errgroup.Group)
	var writeLock sync.Mutex
	w := new(bytes.Buffer)
	format := func(obj interface{}, comment string) error {
		writeLock.Lock()
		defer writeLock.Unlock()
		if _, err := fmt.Fprintf(w, "#%s\n", comment); err != nil {
			return err
		}
		var jsonObj map[string]interface{}
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(obj); err != nil {
			return err
		}
		if err := yaml.Unmarshal(buf.Bytes(), &jsonObj); err != nil {
			return err
		}
		if err := yaml.NewEncoder(w).Encode(jsonObj); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "---"); err != nil {
			return err
		}
		return nil
	}

	g.Go(func() error {
		pods, err := k8sClient.CoreV1().Pods(metav1.NamespaceAll).List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		if err := format(pods, "pods"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		nodes, err := k8sClient.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		if err := format(nodes, "nodes"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		deployments, err := k8sClient.AppsV1().Deployments(metav1.NamespaceAll).List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		if err := format(deployments, "deployments"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		replicas, err := k8sClient.AppsV1().ReplicaSets(metav1.NamespaceAll).List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		if err := format(replicas, "replicas"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		daemonsets, err := k8sClient.AppsV1().DaemonSets(metav1.NamespaceAll).List(metav1.ListOptions{})
		if err != nil {
			return err
		}
		if err := format(daemonsets, "daemonsets"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		configs, err := k8sClient.CoreV1().ConfigMaps(metav1.NamespaceSystem).List(metav1.ListOptions{LabelSelector: "app=antrea"})
		if err != nil {
			return err
		}
		if err := format(configs, "configs"); err != nil {
			return err
		}
		return nil
	})
	return w, g.Wait()
}

func controllerRemoteRunE(cmd *cobra.Command, args []string) error {
	if option.dir == "" {
		cwd, _ := os.Getwd()
		option.dir = filepath.Join(cwd, "support-bundles_"+time.Now().Format(timeFormat))
	}
	dir, err := filepath.Abs(option.dir)
	if err != nil {
		return fmt.Errorf("error when resolving path '%s': %w", option.dir, err)
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
		return fmt.Errorf("failed to create client: %w", err)
	}
	antreaClientset, err := antrea.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating antrea clientset: %w", err)
	}
	filter := "*"
	if len(args) == 1 {
		filter = args[0]
	}
	agentClients, controllerClient, err := createSupportBundleClients(filter, k8sClientset, antreaClientset, restconfigTmpl)
	if err != nil {
		return fmt.Errorf("error when creating system clients: %w", err)
	}
	if err := os.MkdirAll(option.dir, 0700|os.ModeDir); err != nil {
		return fmt.Errorf("error when creating output dir: %w", err)
	}
	amount := len(agentClients) * 2
	if controllerClient != nil {
		amount += 2
	}
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	if reader, err := getClusterInfo(k8sClientset); err != nil {
		return err
	} else {
		f, err := os.Create(filepath.Join(option.dir, "clusterinfo"))
		if err != nil {
			return err
		}
		defer f.Close()
		io.Copy(f, reader)
	}
	if err := requestAll(agentClients, controllerClient, bar); err != nil {
		return err
	}
	return downloadAll(agentClients, controllerClient, dir, bar)
}

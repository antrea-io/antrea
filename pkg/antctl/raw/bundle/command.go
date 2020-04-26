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

package bundle

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/cobra"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	agentapiserver "github.com/vmware-tanzu/antrea/pkg/agent/apiserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	systemv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/system/v1beta1"
	controllerapiserver "github.com/vmware-tanzu/antrea/pkg/apiserver"
	antrea "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

const (
	retryTimes                          = 10
	barTmpl      pb.ProgressBarTemplate = `{{string . "prefix"}}{{bar . }} {{percent . }} {{rtime . "ETA %s"}}` // Example: 'Prefix[-->______] 20%'
	requestRate                         = 100
	requestBurst                        = 150
)

// Command is the bundle command implementation.
var Command *cobra.Command

var option = &struct {
	dir                  string
	labelSelector        string
	fieldSelector        string
	controllerCollectAll bool
}{}

func init() {
	Command = &cobra.Command{
		Use:   "bundle",
		Short: "Generate debug info bundle",
		Long:  "Generate debug info bundle",
	}

	if runtime.Mode == runtime.ModeAgent {
		Command.RunE = agentRunE
	} else if runtime.Mode == runtime.ModeController && runtime.InPod {
		Command.RunE = controllerLocalRunE
	} else if runtime.Mode == runtime.ModeController && !runtime.InPod {
		Command.Args = cobra.MaximumNArgs(1)
		Command.Use += " [nodeName]"
		cwd, _ := os.Getwd()
		Command.Flags().StringVarP(&option.dir, "dir", "d", cwd, "bundle output dir")
		Command.Flags().StringVarP(&option.labelSelector, "label-selector", "l", "", "selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
		Command.Flags().StringVar(&option.fieldSelector, "field-selector", "", "selector (field query) to filter on, supports '=', '==', and '!='.(e.g. --field-selector key1=value1,key2=value2)")
		Command.RunE = controllerRemoteRunE
	}
}

func setupKubeconfig(kubeconfig *rest.Config) {
	kubeconfig.APIPath = "/apis"
	kubeconfig.GroupVersion = &systemv1beta1.SchemeGroupVersion
	kubeconfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	// TODO: enable secure connection in future.
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

func resolveKubeconfig(path string) (*rest.Config, error) {
	var err error
	var kubeconfig *rest.Config
	if _, err = os.Stat(path); path == clientcmd.RecommendedHomeFile && os.IsNotExist(err) {
		kubeconfig, err = rest.InClusterConfig()
		if err != nil {
			err = fmt.Errorf("unable to resolve in-cluster configuration: %v. Please specify the kubeconfig file", err)
		}
	} else {
		kubeconfig, err = clientcmd.BuildConfigFromFlags("", path)
	}
	if err != nil {
		return nil, err
	}
	return kubeconfig, nil
}

func localBundleRequest(cmd *cobra.Command, mode string) error {
	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeconfig, err := resolveKubeconfig(kubeconfigPath)
	if err != nil {
		return err
	}
	setupKubeconfig(kubeconfig)
	client, err := rest.RESTClientFor(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating rest client: %w", err)
	}
	_, err = client.Post().
		Resource("bundles").
		Body(&systemv1beta1.Bundle{ObjectMeta: metav1.ObjectMeta{Name: mode}}).
		DoRaw()
	if err != nil {
		return fmt.Errorf("error when requesting agent bundle: %w", err)
	}
	for {
		var bundleStatus systemv1beta1.Bundle
		err := client.Get().
			Resource("bundles").
			Name(mode).
			Do().
			Into(&bundleStatus)
		if err != nil {
			return fmt.Errorf("error when requesting agent bundle: %w", err)
		}
		if bundleStatus.Status == systemv1beta1.BundleCollected {
			fmt.Printf("Save path: %s\n", bundleStatus.FilePath)
			fmt.Printf("Expire time: %s\n", bundleStatus.DeletionTimestamp)
			break
		}
	}
	return nil

}

func agentRunE(cmd *cobra.Command, _ []string) error {
	return localBundleRequest(cmd, runtime.ModeAgent)
}

func controllerLocalRunE(cmd *cobra.Command, _ []string) error {
	return localBundleRequest(cmd, runtime.ModeController)
}

func request(component string, client *rest.RESTClient, limiter *rate.Limiter) error {
	var err error
	for i := 0; i < retryTimes; i++ {
		_, err = client.Post().
			Resource("bundles").
			Body(&systemv1beta1.Bundle{ObjectMeta: metav1.ObjectMeta{Name: component}}).
			DoRaw()
		if err == nil {
			return nil
		}
		limiter.Wait(context.TODO())
	}
	return err
}

func requestAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, bar *pb.ProgressBar) error {
	bar.Set("prefix", "Requesting ")
	rateLimiter := rate.NewLimiter(requestRate, requestBurst)

	var wg sync.WaitGroup
	wg.Add(len(agentClients))
	var errors sync.Map
	for nodeName, client := range agentClients {
		rateLimiter.Wait(context.TODO())
		go func(nodeName string, client *rest.RESTClient) {
			defer wg.Done()
			defer bar.Increment()
			if err := request(runtime.ModeAgent, client, rateLimiter); err != nil {
				errors.Store(nodeName, fmt.Errorf("error when requesting agent bundle for node %s: %w", nodeName, err))
			}
		}(nodeName, client)
	}
	wg.Wait()

	var err error
	errors.Range(func(k, v interface{}) bool {
		err = v.(error)
		return false
	})
	if err != nil {
		return err
	}

	if controllerClient == nil {
		return nil
	}
	defer bar.Increment()
	return request(runtime.ModeController, controllerClient, rateLimiter)
}

func download(suffix, downloadPath string, client *rest.RESTClient, component string) error {
	for {
		var bundleStatus systemv1beta1.Bundle
		err := client.Get().Resource("bundles").Name(component).Do().Into(&bundleStatus)
		if err != nil {
			return fmt.Errorf("error when requesting agent bundle: %w", err)
		}
		if bundleStatus.Status == systemv1beta1.BundleCollected {
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
				return fmt.Errorf("error when creating bundle tar gz: %w", err)
			}
			defer f.Close()
			stream, err := client.Get().
				Resource("bundles").
				Name("agent").
				SubResource("download").
				Stream()
			if err != nil {
				return fmt.Errorf("error when downloading bundle: %w", err)
			}
			defer stream.Close()
			if _, err := io.Copy(f, stream); err != nil {
				return fmt.Errorf("error when downloading bundle: %w", err)
			}
			break
		}
	}
	return nil
}

func downloadAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, downloadPath string, bar *pb.ProgressBar) error {
	bar.Set("prefix", "Downloading ")
	rateLimiter := rate.NewLimiter(requestRate, requestBurst)
	var wg sync.WaitGroup
	wg.Add(len(agentClients))
	var errors sync.Map
	for nodeName, client := range agentClients {
		rateLimiter.Wait(context.TODO())
		go func(nodeName string, client *rest.RESTClient) {
			defer wg.Done()
			defer bar.Increment()
			if err := download(nodeName, downloadPath, client, runtime.ModeAgent); err != nil {
				errors.Store(nodeName, err)
			}
		}(nodeName, client)
	}
	wg.Wait()
	var err error

	errors.Range(func(k, v interface{}) bool {
		err = v.(error)
		return false
	})
	if err != nil {
		return err
	}

	if controllerClient == nil {
		return nil
	}
	defer bar.Increment()
	return download("", downloadPath, controllerClient, runtime.ModeController)
}

func createBundleClients(filter string, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (map[string]*rest.RESTClient, *rest.RESTClient, error) {
	nodeAgentInfoMap := map[string]string{}
	agentInfoList, err := antreaClientset.ClusterinformationV1beta1().AntreaAgentInfos().List(metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	controllerInfo, err := antreaClientset.ClusterinformationV1beta1().AntreaControllerInfos().Get("antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	for _, agentInfo := range agentInfoList.Items {
		nodeAgentInfoMap[agentInfo.NodeRef.Name] = fmt.Sprint(agentInfo.APIPort)
	}
	nodeList, err := k8sClientset.CoreV1().Nodes().List(metav1.ListOptions{LabelSelector: option.labelSelector, FieldSelector: option.fieldSelector})
	if err != nil {
		return nil, nil, err
	}
	setupKubeconfig(cfgTmpl)

	clients := map[string]*rest.RESTClient{}
	var controllerNodeIP net.IP
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
			klog.Warningf("Error when parsing IP of node %s", node.Name)
			continue
		}
		if node.Name == controllerInfo.NodeRef.Name {
			controllerNodeIP = ip
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
	if controllerNodeIP == nil {
		return clients, nil, nil
	}

	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = net.JoinHostPort(controllerNodeIP.String(), fmt.Sprint(controllerInfo.APIPort))
	controllerClient, err := rest.RESTClientFor(cfg)
	if err != nil {
		klog.Warningf("Error when creating controller client for node: %s", controllerInfo.NodeRef.Name)
	}
	return clients, controllerClient, nil
}

func controllerRemoteRunE(cmd *cobra.Command, args []string) error {
	dir, err := filepath.Abs(option.dir)
	if err != nil {
		return fmt.Errorf("error when resolving path `%s`: %w", option.dir, err)
	}
	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeconfig, err := resolveKubeconfig(kubeconfigPath)
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
	agentClients, controllerClient, err := createBundleClients(filter, k8sClientset, antreaClientset, restconfigTmpl)
	if err != nil {
		return fmt.Errorf("error when creating system clients: %w", err)
	}
	amount := len(agentClients) * 2
	if controllerClient != nil {
		amount += 2
	}
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	if err := requestAll(agentClients, controllerClient, bar); err != nil {
		return err
	}
	return downloadAll(agentClients, controllerClient, dir, bar)
}

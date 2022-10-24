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
	"bufio"
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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/runtime"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	barTmpl pb.ProgressBarTemplate = `{{string . "prefix"}}{{bar . }} {{percent . }} {{rtime . "ETA %s"}}` // Example: 'Prefix[-->______] 20%'

	requestRate  = 50
	requestBurst = 100
	timeFormat   = "20060102T150405Z0700"
)

// Command is the support bundle command implementation.
var Command *cobra.Command

var option = &struct {
	dir            string
	labelSelector  string
	controllerOnly bool
	nodeListFile   string
	since          string
}{}

var remoteControllerLongDescription = strings.TrimSpace(`
Generate support bundles for the cluster, which include: information about each Antrea agent, information about the Antrea controller and general information about the cluster.
`)

var remoteControllerExample = strings.Trim(`
  Generate support bundles of the controller and agents on all Nodes and save them to current working dir
  $ antctl supportbundle
  Generate support bundle of the controller
  $ antctl supportbundle --controller-only
  Generate support bundle of the controller and agents on all Nodes with only the logs generated during the last 1 hour
  $ antctl supportbundle --since 1h
  Generate support bundles of agents on specific Nodes filtered by name list, no wildcard support
  $ antctl supportbundle node_a node_b node_c
  Generate support bundles of agents on specific Nodes filtered by names in a file (one Node name per line)
  $ antctl supportbundle -f ~/nodelistfile
  Generate support bundles of agents on specific Nodes filtered by name, with support for wildcard expressions
  $ antctl supportbundle '*worker*'
  Generate support bundles of agents on specific Nodes filtered by name and label selectors
  $ antctl supportbundle '*worker*' -l kubernetes.io/os=linux
  Generate support bundles of the controller and agents on all Nodes and save them to specific dir
  $ antctl supportbundle -d ~/Downloads
`, "\n")

func init() {
	Command = &cobra.Command{
		Use:   "supportbundle",
		Short: "Generate support bundle",
	}

	if runtime.Mode == runtime.ModeAgent {
		Command.RunE = agentRunE
		Command.Long = "Generate the support bundle of current Antrea agent."
	} else if runtime.Mode == runtime.ModeController && runtime.InPod {
		Command.RunE = controllerLocalRunE
		Command.Long = "Generate the support bundle of current Antrea controller."
	} else if runtime.Mode == runtime.ModeController && !runtime.InPod {
		Command.Use += " [nodeName...]"
		Command.Long = remoteControllerLongDescription
		Command.Example = remoteControllerExample
		Command.Flags().StringVarP(&option.dir, "dir", "d", "", "support bundles output dir, the path will be created if it doesn't exist")
		Command.Flags().StringVarP(&option.labelSelector, "label-selector", "l", "", "selector (label query) to filter Nodes for agent bundles, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
		Command.Flags().BoolVar(&option.controllerOnly, "controller-only", false, "only collect the support bundle of Antrea controller")
		Command.Flags().StringVarP(&option.nodeListFile, "node-list-file", "f", "", "only collect the support bundle of specific nodes filtered by names in a file (one node name per line)")
		Command.Flags().StringVarP(&option.since, "since", "", "", "only return logs newer than a relative duration like 5s, 2m or 3h. Defaults to all logs")
		Command.RunE = controllerRemoteRunE
	}
}

func localSupportBundleRequest(cmd *cobra.Command, mode string) error {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	kubeconfig.APIPath = "/apis"
	kubeconfig.GroupVersion = &systemv1beta1.SchemeGroupVersion
	raw.SetupKubeconfig(kubeconfig)
	client, err := rest.RESTClientFor(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating rest client: %w", err)
	}
	_, err = client.Post().
		Resource("supportbundles").
		Body(&systemv1beta1.SupportBundle{ObjectMeta: metav1.ObjectMeta{Name: mode}}).
		DoRaw(context.TODO())
	if err != nil {
		return fmt.Errorf("error when requesting the agent support bundle: %w", err)
	}
	for {
		var supportBundle systemv1beta1.SupportBundle
		err := client.Get().
			Resource("supportbundles").
			Name(mode).
			Do(context.TODO()).
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
		Body(&systemv1beta1.SupportBundle{ObjectMeta: metav1.ObjectMeta{Name: component}, Since: option.since}).
		DoRaw(context.TODO())
	if err == nil {
		return nil
	}
	return err
}

type result struct {
	nodeName string
	err      error
}

func mapClients(prefix string, agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, bar *pb.ProgressBar, af, cf func(nodeName string, c *rest.RESTClient) error) map[string]error {
	bar.Set("prefix", prefix)
	rateLimiter := rate.NewLimiter(requestRate, requestBurst)
	ch := make(chan result)
	g, ctx := errgroup.WithContext(context.Background())
	for nodeName, client := range agentClients {
		rateLimiter.Wait(ctx)
		nodeName, client := nodeName, client
		g.Go(func() error {
			defer bar.Increment()
			err := af(nodeName, client)
			ch <- result{nodeName: nodeName, err: err}
			return err
		})
	}

	results := make(map[string]error, len(agentClients))
	for i := 0; i < len(agentClients); i++ {
		result := <-ch
		results[result.nodeName] = result.err
	}

	g.Wait()

	if controllerClient != nil {
		defer bar.Increment()
		results[""] = cf("", controllerClient)
	}
	return results
}

func requestAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, bar *pb.ProgressBar) map[string]error {
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
		err := client.Get().Resource("supportbundles").Name(component).Do(context.TODO()).Into(&supportBundle)
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
				Stream(context.TODO())
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

func writeFailedNodes(downloadPath string, nodes []string) error {
	file, err := os.OpenFile(downloadPath+"/failed_nodes", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("err create file for failed nodes: %w", err)
	}
	defer file.Close()

	dataWriter := bufio.NewWriter(file)
	for _, node := range nodes {
		_, _ = dataWriter.WriteString(node + "\n")
	}

	err = dataWriter.Flush()
	if err != nil {
		return err
	}
	return nil
}

// downloadAll will download all supportBundles. preResults is the request results of node/controller supportBundle.
// if err happens for some nodes or controller, the download step will be skipped for the failed nodes or the controller.
func downloadAll(agentClients map[string]*rest.RESTClient, controllerClient *rest.RESTClient, downloadPath string, bar *pb.ProgressBar, preResults map[string]error) map[string]error {
	results := mapClients(
		"Downloading",
		agentClients,
		controllerClient,
		bar,
		func(nodeName string, c *rest.RESTClient) error {
			if preResults[nodeName] == nil {
				return download(nodeName, downloadPath, c, runtime.ModeAgent)
			}
			return preResults[nodeName]

		},
		func(nodeName string, c *rest.RESTClient) error {
			if preResults[""] == nil {
				return download("", downloadPath, c, runtime.ModeController)
			}
			return preResults[nodeName]
		},
	)
	for k, v := range results {
		if v != nil {
			preResults[k] = v
		}
	}
	return preResults
}

// createAgentClients creates clients for agents on specified nodes. If nameList is set, then nameFilter will be ignored.
func createAgentClients(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config, nameFilter string, nameList []string) (map[string]*rest.RESTClient, error) {
	clients := map[string]*rest.RESTClient{}
	nodeAgentInfoMap := map[string]string{}
	agentInfoList, err := antreaClientset.CrdV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	for _, agentInfo := range agentInfoList.Items {
		nodeAgentInfoMap[agentInfo.NodeRef.Name] = fmt.Sprint(agentInfo.APIPort)
	}
	nodeList, err := k8sClientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: option.labelSelector, ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	var matcher func(name string) bool
	if len(nameList) > 0 {
		matchSet := make(map[string]struct{})
		for _, name := range nameList {
			matchSet[name] = struct{}{}
		}
		matcher = func(name string) bool {
			_, ok := matchSet[name]
			return ok
		}
	} else {
		matcher = func(name string) bool {
			hit, _ := filepath.Match(nameFilter, name)
			return hit
		}
	}
	for i := range nodeList.Items {
		node := nodeList.Items[i]
		if !matcher(node.Name) {
			continue
		}
		port, ok := nodeAgentInfoMap[node.Name]
		if !ok {
			continue
		}
		ips, err := k8s.GetNodeAddrs(&node)
		if err != nil {
			klog.Warningf("Error when parsing IP of Node %s", node.Name)
			continue
		}
		cfg := rest.CopyConfig(cfgTmpl)
		var nodeIP string
		if ips.IPv4 != nil {
			nodeIP = ips.IPv4.String()
		} else {
			nodeIP = ips.IPv6.String()
		}
		cfg.Host = net.JoinHostPort(nodeIP, port)
		client, err := rest.RESTClientFor(cfg)
		if err != nil {
			klog.Warningf("Error when creating agent client for node: %s", node.Name)
			continue
		}
		clients[node.Name] = client
	}
	return clients, nil
}

func createControllerClient(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (*rest.RESTClient, error) {
	controllerInfo, err := antreaClientset.CrdV1beta1().AntreaControllerInfos().Get(context.TODO(), "antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	controllerNode, err := k8sClientset.CoreV1().Nodes().Get(context.TODO(), controllerInfo.NodeRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when searching the Node of the controller: %w", err)
	}
	var controllerNodeIPs *ip.DualStackIPs
	controllerNodeIPs, err = k8s.GetNodeAddrs(controllerNode)
	if err != nil {
		return nil, fmt.Errorf("error when parsing controllre IP: %w", err)
	}

	cfg := rest.CopyConfig(cfgTmpl)
	var nodeIP string
	if controllerNodeIPs.IPv4 != nil {
		nodeIP = controllerNodeIPs.IPv4.String()
	} else {
		nodeIP = controllerNodeIPs.IPv6.String()
	}
	cfg.Host = net.JoinHostPort(nodeIP, fmt.Sprint(controllerInfo.APIPort))
	controllerClient, err := rest.RESTClientFor(cfg)
	if err != nil {
		klog.Warningf("Error when creating controller client for node: %s", controllerInfo.NodeRef.Name)
	}
	return controllerClient, nil
}

func getClusterInfo(w io.Writer, k8sClient kubernetes.Interface) error {
	g := new(errgroup.Group)
	var writeLock sync.Mutex

	output := func(list k8sruntime.Object, comment string) error {
		writeLock.Lock()
		defer writeLock.Unlock()
		if _, err := fmt.Fprintf(w, "#%s\n", comment); err != nil {
			return err
		}
		err := meta.EachListItem(list, func(obj k8sruntime.Object) error {
			var jsonObj interface{}
			data, err := json.Marshal(obj)
			if err != nil {
				return err
			}
			if err = yaml.Unmarshal(data, &jsonObj); err != nil {
				return err
			}
			data, err = yaml.Marshal(jsonObj)
			if err != nil {
				return err
			}
			_, err = w.Write(data)
			if err != nil {
				return err
			}
			if _, err = fmt.Fprintln(w, "---"); err != nil {
				return err
			}
			return nil
		})
		return err
	}

	g.Go(func() error {
		pods, err := k8sClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(pods, "pods"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		nodes, err := k8sClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(nodes, "nodes"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		deployments, err := k8sClient.AppsV1().Deployments(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(deployments, "deployments"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		replicas, err := k8sClient.AppsV1().ReplicaSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(replicas, "replicas"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		daemonsets, err := k8sClient.AppsV1().DaemonSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(daemonsets, "daemonsets"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		configs, err := k8sClient.CoreV1().ConfigMaps(metav1.NamespaceSystem).List(context.TODO(), metav1.ListOptions{LabelSelector: "app=antrea", ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := output(configs, "configs"); err != nil {
			return err
		}
		return nil
	})
	return g.Wait()
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

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	kubeconfig.APIPath = "/apis"
	kubeconfig.GroupVersion = &systemv1beta1.SchemeGroupVersion
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)
	if server, _ := Command.Flags().GetString("server"); server != "" {
		kubeconfig.Host = server
	}

	k8sClientset, antreaClientset, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	var controllerClient *rest.RESTClient
	var agentClients map[string]*rest.RESTClient

	// Collect controller bundle when no Node name or label filter is specified, or
	// when --controller-only is set.
	if (len(args) == 0 && len(option.nodeListFile) == 0 && option.labelSelector == "") || option.controllerOnly {
		controllerClient, err = createControllerClient(k8sClientset, antreaClientset, restconfigTmpl)
		if err != nil {
			return fmt.Errorf("error when creating controller client: %w", err)
		}
	}
	if !option.controllerOnly {
		nameFilter := "*"
		var nameList []string
		if len(args) == 1 {
			nameFilter = args[0]
		} else if len(option.nodeListFile) != 0 {
			nodeListFile, err := filepath.Abs(option.nodeListFile)
			if err != nil {
				return fmt.Errorf("error when resolving node-list-file path: %w", err)
			}
			f, err := os.Open(nodeListFile)
			if err != nil {
				return fmt.Errorf("error when opening node-list-file: %w", err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				nameList = append(nameList, strings.TrimSpace(scanner.Text()))
			}
		} else if len(args) > 1 {
			nameList = args
		}
		agentClients, err = createAgentClients(k8sClientset, antreaClientset, restconfigTmpl, nameFilter, nameList)
		if err != nil {
			return fmt.Errorf("error when creating agent clients: %w", err)
		}
	}

	if controllerClient == nil && len(agentClients) == 0 {
		return fmt.Errorf("no matched Nodes found to collect agent bundles")
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
	f, err := os.Create(filepath.Join(option.dir, "clusterinfo"))
	if err != nil {
		return err
	}
	defer f.Close()
	err = getClusterInfo(f, k8sClientset)
	if err != nil {
		return err
	}

	results := requestAll(agentClients, controllerClient, bar)
	results = downloadAll(agentClients, controllerClient, dir, bar, results)
	return processResults(results, dir)
}

func genErrorMsg(resultMap map[string]error) string {
	msg := ""
	for _, v := range resultMap {
		msg += v.Error() + ";"
	}
	return msg
}

// processResults will output the failed nodes and their reasons if any. If no data was collected,
// error is returned, otherwise will return nil.
func processResults(resultMap map[string]error, dir string) error {
	resultStr := ""
	var failedNodes []string
	allFailed := true
	var err error

	for k, v := range resultMap {
		if k != "" && v != nil {
			resultStr += fmt.Sprintf("- %s: %s\n", k, v.Error())
			failedNodes = append(failedNodes, k)
		}
		if v == nil {
			allFailed = false
		}
	}

	if resultMap[""] != nil {
		fmt.Println("Controller Info Failed Reason: " + resultMap[""].Error())
	}

	if resultStr != "" {
		fmt.Println("Failed nodes: ")
		fmt.Print(resultStr)
	}

	if failedNodes != nil {
		err = writeFailedNodes(dir, failedNodes)
	}

	if allFailed {
		return fmt.Errorf("no data was collected: %s", genErrorMsg(resultMap))
	} else {
		return err
	}
}

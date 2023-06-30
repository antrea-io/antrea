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
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	systemclientset "antrea.io/antrea/pkg/client/clientset/versioned/typed/system/v1beta1"
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
	insecure       bool
}{}

var defaultFS = afero.NewOsFs()

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
		Command.Flags().BoolVar(&option.insecure, "insecure", false, "Skip TLS verification when connecting to Antrea API.")
		Command.RunE = controllerRemoteRunE
	}
}

var getSupportBundleClient func(cmd *cobra.Command) (systemclientset.SupportBundleInterface, error) = setupSupportBundleClient

func setupSupportBundleClient(cmd *cobra.Command) (systemclientset.SupportBundleInterface, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, err
	}
	raw.SetupLocalKubeconfig(kubeconfig)
	client, err := systemclientset.NewForConfig(kubeconfig)
	return client.SupportBundles(), err
}

func localSupportBundleRequest(cmd *cobra.Command, mode string, writer io.Writer) error {
	ctx := cmd.Context()
	client, err := getSupportBundleClient(cmd)
	if err != nil {
		return fmt.Errorf("error when creating system client: %w", err)
	}
	if _, err := client.Create(ctx, &systemv1beta1.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: mode,
		},
	}, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating the support bundle: %w", err)
	}
	timer := time.NewTimer(100 * time.Millisecond) // will expire after 100ms
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			supportBundle, err := client.Get(ctx, mode, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("error when getting the support bundle: %w", err)
			}
			if supportBundle.Status == systemv1beta1.SupportBundleStatusCollected {
				fmt.Fprintf(writer, "Created bundle under %s\n", os.TempDir())
				fmt.Fprintf(writer, "Expire time: %s\n", supportBundle.DeletionTimestamp)
				return nil
			}
			// retry again after 500ms
			timer.Reset(500 * time.Millisecond)
		}
	}

}

func agentRunE(cmd *cobra.Command, _ []string) error {
	return localSupportBundleRequest(cmd, runtime.ModeAgent, os.Stdout)
}

func controllerLocalRunE(cmd *cobra.Command, _ []string) error {
	return localSupportBundleRequest(cmd, runtime.ModeController, os.Stdout)
}

func request(ctx context.Context, component string, client systemclientset.SupportBundleInterface) error {
	_, err := client.Create(ctx, &systemv1beta1.SupportBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: component,
		},
		Since: option.since,
	}, metav1.CreateOptions{})
	return err
}

type result struct {
	nodeName string
	err      error
}

func mapClients(
	ctx context.Context,
	prefix string,
	agentClients map[string]systemclientset.SupportBundleInterface,
	controllerClient systemclientset.SupportBundleInterface,
	bar *pb.ProgressBar,
	af, cf func(ctx context.Context, nodeName string, c systemclientset.SupportBundleInterface) error,
) map[string]error {
	bar.Set("prefix", prefix)
	results := make(map[string]error, len(agentClients)+1)

	func() {
		rateLimiter := rate.NewLimiter(requestRate, requestBurst)
		ch := make(chan result)
		g, ctx := errgroup.WithContext(ctx)
		for nodeName, client := range agentClients {
			rateLimiter.Wait(ctx)
			nodeName, client := nodeName, client
			g.Go(func() error {
				defer bar.Increment()
				err := af(ctx, nodeName, client)
				ch <- result{nodeName: nodeName, err: err}
				return err
			})
		}

		for i := 0; i < len(agentClients); i++ {
			result := <-ch
			results[result.nodeName] = result.err
		}

		g.Wait()
	}()

	if controllerClient != nil {
		defer bar.Increment()
		results[""] = cf(ctx, "", controllerClient)
	}
	return results
}

func requestAll(
	ctx context.Context,
	agentClients map[string]systemclientset.SupportBundleInterface,
	controllerClient systemclientset.SupportBundleInterface,
	bar *pb.ProgressBar,
) map[string]error {
	return mapClients(
		ctx,
		"Requesting",
		agentClients,
		controllerClient,
		bar,
		func(ctx context.Context, nodeName string, c systemclientset.SupportBundleInterface) error {
			return request(ctx, runtime.ModeAgent, c)
		},
		func(ctx context.Context, nodeName string, c systemclientset.SupportBundleInterface) error {
			return request(ctx, runtime.ModeController, c)
		},
	)
}

func download(
	ctx context.Context,
	suffix,
	downloadPath string,
	client systemclientset.SupportBundleInterface,
	component string,
) error {
	timer := time.NewTimer(100 * time.Millisecond) // will expire after 100ms
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			supportBundle, err := client.Get(ctx, component, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("error when downloading the support bundle: %w", err)
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
				f, err := defaultFS.Create(fileName)
				if err != nil {
					return fmt.Errorf("error when creating the support bundle tar gz: %w", err)
				}
				defer f.Close()
				stream, err := client.Download(ctx, component)
				if err != nil {
					return fmt.Errorf("error when downloading the support bundle: %w", err)
				}
				defer stream.Close()
				if _, err := io.Copy(f, stream); err != nil {
					return fmt.Errorf("error when downloading the support bundle: %w", err)
				}
				return nil
			}
			// retry again after 500ms
			timer.Reset(500 * time.Millisecond)
		}
	}
}

func writeFailedNodes(downloadPath string, nodes []string) error {
	file, err := defaultFS.OpenFile(filepath.Join(downloadPath, "failed_nodes"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
func downloadAll(
	ctx context.Context,
	agentClients map[string]systemclientset.SupportBundleInterface,
	controllerClient systemclientset.SupportBundleInterface,
	downloadPath string,
	bar *pb.ProgressBar,
	preResults map[string]error,
) map[string]error {
	results := mapClients(
		ctx,
		"Downloading",
		agentClients,
		controllerClient,
		bar,
		func(ctx context.Context, nodeName string, c systemclientset.SupportBundleInterface) error {
			if preResults[nodeName] == nil {
				return download(ctx, nodeName, downloadPath, c, runtime.ModeAgent)
			}
			return preResults[nodeName]

		},
		func(ctx context.Context, nodeName string, c systemclientset.SupportBundleInterface) error {
			if preResults[""] == nil {
				return download(ctx, "", downloadPath, c, runtime.ModeController)
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
func createAgentClients(
	ctx context.Context,
	k8sClientset kubernetes.Interface,
	antreaClientset antrea.Interface,
	kubeconfig *rest.Config,
	nameFilter string,
	nameList []string,
	insecure bool,
) (map[string]systemclientset.SupportBundleInterface, error) {
	clients := map[string]systemclientset.SupportBundleInterface{}
	nodeAgentInfoMap := map[string]*v1beta1.AntreaAgentInfo{}
	agentInfoList, err := antreaClientset.CrdV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	for idx := range agentInfoList.Items {
		agentInfo := &agentInfoList.Items[idx]
		nodeAgentInfoMap[agentInfo.NodeRef.Name] = agentInfo
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
		node := &nodeList.Items[i]
		if !matcher(node.Name) {
			continue
		}
		agentInfo, ok := nodeAgentInfoMap[node.Name]
		if !ok {
			continue
		}
		cfg, err := raw.CreateAgentClientCfgFromObjects(ctx, k8sClientset, kubeconfig, node, agentInfo, insecure)
		if err != nil {
			klog.ErrorS(err, "Error when creating agent client config", "node", node.Name)
			continue
		}
		client, err := systemclientset.NewForConfig(cfg)
		if err != nil {
			klog.ErrorS(err, "Error when creating agent client", "node", node.Name)
			continue
		}
		clients[node.Name] = client.SupportBundles()
	}
	return clients, nil
}

func createControllerClient(
	ctx context.Context,
	k8sClientset kubernetes.Interface,
	antreaClientset antrea.Interface,
	cfgTmpl *rest.Config,
	insecure bool,
) (systemclientset.SupportBundleInterface, error) {
	cfg, err := raw.CreateControllerClientCfg(ctx, k8sClientset, antreaClientset, cfgTmpl, insecure)
	if err != nil {
		return nil, fmt.Errorf("error when creating controller client config: %w", err)
	}
	controllerClient, err := systemclientset.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("error when creating controller client: %w", err)
	}
	return controllerClient.SupportBundles(), nil
}

func getClusterInfo(w io.Writer, k8sClient kubernetes.Interface) error {
	g := new(errgroup.Group)
	var writeLock sync.Mutex

	outputObjects := func(objects []k8sruntime.Object, comment string) error {
		writeLock.Lock()
		defer writeLock.Unlock()
		if _, err := fmt.Fprintf(w, "#%s\n", comment); err != nil {
			return err
		}
		for _, obj := range objects {
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
		}
		return nil
	}
	outputList := func(list k8sruntime.Object, comment string) error {
		objects, err := meta.ExtractList(list)
		if err != nil {
			return err
		}
		return outputObjects(objects, comment)
	}

	g.Go(func() error {
		pods, err := k8sClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := outputList(pods, "pods"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		nodes, err := k8sClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := outputList(nodes, "nodes"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		deployments, err := k8sClient.AppsV1().Deployments(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := outputList(deployments, "deployments"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		replicas, err := k8sClient.AppsV1().ReplicaSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := outputList(replicas, "replicas"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		daemonsets, err := k8sClient.AppsV1().DaemonSets(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return err
		}
		if err := outputList(daemonsets, "daemonsets"); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		// These are the ConfigMaps created by Antrea in the the kube-system Namespace.
		configMapNames := []string{
			"antrea-config",
			"antrea-ca",
			"antrea-ipsec-ca",
			"antrea-cluster-identity",
		}
		var configMaps []k8sruntime.Object
		for _, name := range configMapNames {
			cm, err := k8sClient.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get(context.TODO(), name, metav1.GetOptions{ResourceVersion: "0"})
			if apierrors.IsNotFound(err) {
				continue
			} else if err != nil {
				return err
			}
			configMaps = append(configMaps, cm)
		}
		if err := outputObjects(configMaps, "configs"); err != nil {
			return err
		}
		return nil
	})
	return g.Wait()
}

func controllerRemoteRunE(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
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
	if server, _ := Command.Flags().GetString("server"); server != "" {
		kubeconfig.Host = server
	}

	k8sClientset, antreaClientset, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	var controllerClient systemclientset.SupportBundleInterface
	var agentClients map[string]systemclientset.SupportBundleInterface

	// Collect controller bundle when no Node name or label filter is specified, or
	// when --controller-only is set.
	if (len(args) == 0 && len(option.nodeListFile) == 0 && option.labelSelector == "") || option.controllerOnly {
		controllerClient, err = createControllerClient(ctx, k8sClientset, antreaClientset, kubeconfig, option.insecure)
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
		agentClients, err = createAgentClients(ctx, k8sClientset, antreaClientset, kubeconfig, nameFilter, nameList, option.insecure)
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

	results := requestAll(ctx, agentClients, controllerClient, bar)
	results = downloadAll(ctx, agentClients, controllerClient, dir, bar, results)
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

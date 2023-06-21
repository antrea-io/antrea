// Copyright 2021 Antrea Authors
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

package featuregates

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/apiserver/handlers/featuregates"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
)

var Command *cobra.Command
var getClients = getConfigAndClients
var getRestClient = getRestClientByMode

var option = &struct {
	insecure bool
}{}

func init() {
	Command = &cobra.Command{
		Use:   "featuregates",
		Short: "Print Antrea feature gates",
	}
	if runtime.Mode == runtime.ModeAgent {
		Command.RunE = agentRunE
		Command.Long = "Print current Antrea agent feature gates info"
	} else if runtime.Mode == runtime.ModeController && runtime.InPod {
		Command.RunE = controllerLocalRunE
		Command.Long = "Print Antrea feature gates info including Controller and Agent"
	} else if runtime.Mode == runtime.ModeController && !runtime.InPod {
		Command.Long = "Print Antrea feature gates info including Controller and Agent"
		Command.Flags().BoolVar(&option.insecure, "insecure", false, "Skip TLS verification when connecting to Antrea API.")
		Command.RunE = controllerRemoteRunE
	}
}

func agentRunE(cmd *cobra.Command, _ []string) error {
	return featureGateRequest(cmd, runtime.ModeAgent)
}

func controllerLocalRunE(cmd *cobra.Command, _ []string) error {
	return featureGateRequest(cmd, runtime.ModeController)
}

func controllerRemoteRunE(cmd *cobra.Command, _ []string) error {
	return featureGateRequest(cmd, "remote")
}

func featureGateRequest(cmd *cobra.Command, mode string) error {
	ctx := cmd.Context()
	kubeconfig, k8sClientset, antreaClientset, err := getClients(cmd)
	if err != nil {
		return err
	}

	client, err := getRestClient(ctx, kubeconfig, k8sClientset, antreaClientset, mode)
	if err != nil {
		return err
	}

	var resp []featuregates.Response
	if resp, err = getFeatureGatesRequest(client); err != nil {
		return err
	}
	var agentGates []featuregates.Response
	var controllerGates []featuregates.Response
	for _, v := range resp {
		if v.Component == "agent" {
			agentGates = append(agentGates, v)
		} else {
			controllerGates = append(controllerGates, v)
		}
	}
	if len(agentGates) > 0 {
		output(agentGates, runtime.ModeAgent, cmd.OutOrStdout())
	}
	if len(controllerGates) > 0 {
		fmt.Println()
		output(controllerGates, runtime.ModeController, cmd.OutOrStdout())
	}
	return nil
}

func getConfigAndClients(cmd *cobra.Command) (*rest.Config, kubernetes.Interface, antrea.Interface, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	if server, _ := Command.Flags().GetString("server"); server != "" {
		kubeconfig.Host = server
	}
	k8sClientset, antreaClientset, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return kubeconfig, k8sClientset, antreaClientset, nil
}

func getRestClientByMode(ctx context.Context, kubeconfig *rest.Config, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, mode string) (*rest.RESTClient, error) {
	cfg := rest.CopyConfig(kubeconfig)
	cfg.GroupVersion = &schema.GroupVersion{Group: "", Version: ""}
	var err error
	var client *rest.RESTClient
	switch mode {
	case runtime.ModeAgent, runtime.ModeController:
		raw.SetupLocalKubeconfig(cfg)
		client, err = rest.RESTClientFor(cfg)
	case "remote":
		client, err = getControllerClient(ctx, k8sClientset, antreaClientset, cfg, option.insecure)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create rest client: %w", err)
	}
	return client, nil
}

func getControllerClient(ctx context.Context, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, kubeconfig *rest.Config, insecure bool) (*rest.RESTClient, error) {
	controllerClientCfg, err := raw.CreateControllerClientCfg(ctx, k8sClientset, antreaClientset, kubeconfig, insecure)
	if err != nil {
		return nil, fmt.Errorf("error when creating controller client config: %w", err)
	}
	controllerClient, err := rest.RESTClientFor(controllerClientCfg)
	if err != nil {
		return nil, fmt.Errorf("error when creating controller client: %w", err)
	}
	return controllerClient, nil
}

func getFeatureGatesRequest(client *rest.RESTClient) ([]featuregates.Response, error) {
	var resp []featuregates.Response
	u := url.URL{Path: "/featuregates"}
	getter := client.Get().RequestURI(u.RequestURI())
	rawResp, err := getter.DoRaw(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("error when requesting feature gates list: %w", err)
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal feature gates list: %w", err)
	}
	return resp, nil
}

func output(resps []featuregates.Response, runtimeMode string, output io.Writer) {
	switch runtimeMode {
	case runtime.ModeAgent:
		output.Write([]byte("Antrea Agent Feature Gates\n"))
	case runtime.ModeController:
		output.Write([]byte("Antrea Controller Feature Gates\n"))
	}
	formatter := "%-25s%-15s%-10s\n"
	output.Write([]byte(fmt.Sprintf(formatter, "FEATUREGATE", "STATUS", "VERSION")))
	for _, r := range resps {
		fmt.Fprintf(output, formatter, r.Name, r.Status, r.Version)
	}
}

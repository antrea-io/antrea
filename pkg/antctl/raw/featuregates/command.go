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
	"net/url"
	"strings"

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

func init() {
	Command = &cobra.Command{
		Use:   "featuregates",
		Short: "Get feature gates list",
	}
	if runtime.Mode == runtime.ModeAgent {
		Command.RunE = agentRunE
		Command.Long = "Get current Antrea agent feature gates info"
	} else if runtime.Mode == runtime.ModeController && runtime.InPod {
		Command.RunE = controllerLocalRunE
		Command.Long = "Get Antrea feature gates info including Controller and Agent"
	} else if runtime.Mode == runtime.ModeController && !runtime.InPod {
		Command.Long = "Get Antrea feature gates info including Controller and Agent"
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
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	kubeconfig.GroupVersion = &schema.GroupVersion{Group: "", Version: ""}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)
	if server, err := Command.Flags().GetString("server"); err != nil {
		kubeconfig.Host = server
	}

	k8sClientset, antreaClientset, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	var resp []featuregates.Response
	var client *rest.RESTClient

	switch mode {
	case runtime.ModeAgent, runtime.ModeController:
		client, err = rest.RESTClientFor(restconfigTmpl)
	case "remote":
		client, err = getControllerClient(k8sClientset, antreaClientset, restconfigTmpl)
	}
	if err != nil {
		return fmt.Errorf("fail to create rest client: %w", err)
	}

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
		fmt.Println(output(agentGates, runtime.ModeAgent))
	}
	if len(controllerGates) > 0 {
		fmt.Println(output(controllerGates, runtime.ModeController))
	}
	return nil
}

func getControllerClient(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (*rest.RESTClient, error) {
	controllerClientCfg, err := raw.CreateControllerClientCfg(k8sClientset, antreaClientset, cfgTmpl)
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
		return nil, fmt.Errorf("fail to unmarshal feature gates list: %w", err)
	}
	return resp, nil
}

func output(resps []featuregates.Response, runtimeMode string) string {
	var output strings.Builder
	switch runtimeMode {
	case runtime.ModeAgent:
		output.Write([]byte("Antrea Agent Feature Gates\n"))
	case runtime.ModeController:
		output.Write([]byte("Antrea Controller Feature Gates\n"))
	}
	formatter := "%-25s%-15s%-10s\n"
	output.Write([]byte(fmt.Sprintf(formatter, "FEATUREGATE", "STATUS", "VERSION")))
	for _, r := range resps {
		fmt.Fprintf(&output, formatter, r.Name, r.Status, r.Version)
	}
	return output.String()
}

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

package raw

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	agentapiserver "antrea.io/antrea/pkg/agent/apiserver"
	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/apis"
	clusterinformationv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	controllerapiserver "antrea.io/antrea/pkg/apiserver"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	"antrea.io/antrea/pkg/util/k8s"
)

func SetupClients(kubeconfig *rest.Config) (*kubernetes.Clientset, *antrea.Clientset, error) {
	k8sClientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create K8s clientset: %w", err)
	}
	antreaClientset, err := antrea.NewForConfig(kubeconfig)
	if err != nil {
		return k8sClientset, nil, fmt.Errorf("error when creating Antrea clientset: %w", err)
	}
	return k8sClientset, antreaClientset, nil
}

func ResolveKubeconfig(cmd *cobra.Command) (*rest.Config, error) {
	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return nil, err
	}
	kubeconfig, err := runtime.ResolveKubeconfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return kubeconfig, nil
}

// TODO: generate kubeconfig in Antrea agent for antctl in-Pod access.
func SetupKubeconfig(kubeconfig *rest.Config) {
	kubeconfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	kubeconfig.Insecure = true
	kubeconfig.CAFile = ""
	kubeconfig.CAData = nil
	if runtime.InPod {
		if runtime.Mode == runtime.ModeAgent {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(apis.AntreaAgentAPIPort))
			kubeconfig.BearerTokenFile = agentapiserver.TokenPath
		} else {
			kubeconfig.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(apis.AntreaControllerAPIPort))
			kubeconfig.BearerTokenFile = controllerapiserver.TokenPath
		}
	}
}

func CreateAgentClientCfg(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config, nodeName string) (*rest.Config, error) {
	node, err := k8sClientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when looking up Node %s: %w", nodeName, err)
	}
	// TODO: filter by Node name, but that would require API support
	agentInfoList, err := antreaClientset.CrdV1beta1().AntreaAgentInfos().List(context.TODO(), metav1.ListOptions{ResourceVersion: "0"})
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
	nodeIP, err := k8s.GetNodeAddr(node)
	if err != nil {
		return nil, fmt.Errorf("error when parsing IP of Node %s", nodeName)
	}
	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP.String(), fmt.Sprint(agentInfo.APIPort)))
	return cfg, nil
}

func CreateControllerClientCfg(k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, cfgTmpl *rest.Config) (*rest.Config, error) {
	controllerInfo, err := antreaClientset.CrdV1beta1().AntreaControllerInfos().Get(context.TODO(), "antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	controllerNode, err := k8sClientset.CoreV1().Nodes().Get(context.TODO(), controllerInfo.NodeRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when searching the Node of the controller: %w", err)
	}
	var controllerNodeIP net.IP
	controllerNodeIP, err = k8s.GetNodeAddr(controllerNode)
	if err != nil {
		return nil, fmt.Errorf("error when parsing controller IP: %w", err)
	}

	cfg := rest.CopyConfig(cfgTmpl)
	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(controllerNodeIP.String(), fmt.Sprint(controllerInfo.APIPort)))
	return cfg, nil
}

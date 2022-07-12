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
	controllerapiserver "antrea.io/antrea/pkg/apiserver"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	"antrea.io/antrea/pkg/util/ip"
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
	agentInfo, err := antreaClientset.CrdV1beta1().AntreaAgentInfos().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if agentInfo.NodeRef.Name == "" {
		return nil, fmt.Errorf("AntreaAgentInfo is not ready for Node %s", nodeName)
	}
	nodeIPs, err := k8s.GetNodeAddrs(node)
	if err != nil {
		return nil, fmt.Errorf("error when parsing IP of Node %s", nodeName)
	}
	cfg := rest.CopyConfig(cfgTmpl)

	var nodeIP string
	if nodeIPs.IPv4 != nil {
		nodeIP = nodeIPs.IPv4.String()
	} else if nodeIPs.IPv6 != nil {
		nodeIP = nodeIPs.IPv6.String()
	} else {
		return nil, fmt.Errorf("there is no NodeIP on agent Node")
	}
	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP, fmt.Sprint(agentInfo.APIPort)))
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
	var controllerNodeIPs *ip.DualStackIPs
	controllerNodeIPs, err = k8s.GetNodeAddrs(controllerNode)
	if err != nil {
		return nil, fmt.Errorf("error when parsing controller IP: %w", err)
	}

	cfg := rest.CopyConfig(cfgTmpl)

	var nodeIP string
	if controllerNodeIPs.IPv4 != nil {
		nodeIP = controllerNodeIPs.IPv4.String()
	} else if controllerNodeIPs.IPv6 != nil {
		nodeIP = controllerNodeIPs.IPv6.String()
	} else {
		return nil, fmt.Errorf("there is no NodeIP on controller Node")
	}

	cfg.Host = fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP, fmt.Sprint(controllerInfo.APIPort)))
	return cfg, nil
}

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
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/antctl/runtime"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	antreascheme "antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

func GetNodeAddrs(node *corev1.Node) (*ip.DualStackIPs, error) {
	// We prioritize the external Node IP to support cases where antctl is run outside of the
	// cluster, and the internal Node IP may not be reachable.
	return k8s.GetNodeAddrsWithType(node, []corev1.NodeAddressType{corev1.NodeExternalIP, corev1.NodeInternalIP})
}

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

func SetupLocalKubeconfig(kubeconfig *rest.Config) {
	if !runtime.InPod {
		// We want to avoid accidental uses of this function
		panic("SetupLocalKubeconfig can only be called when running in-pod")
	}
	// TODO: generate kubeconfig in Antrea agent for antctl in-Pod access.
	kubeconfig.NegotiatedSerializer = antreascheme.Codecs.WithoutConversion()
	kubeconfig.Insecure = true
	kubeconfig.CAFile = ""
	kubeconfig.CAData = nil
	kubeconfig.BearerTokenFile = apis.APIServerLoopbackTokenPath
	if runtime.Mode == runtime.ModeAgent {
		kubeconfig.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(apis.AntreaAgentAPIPort))
	} else {
		kubeconfig.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(apis.AntreaControllerAPIPort))
	}
}

func GetControllerCACert(ctx context.Context, client kubernetes.Interface, controllerInfo *v1beta1.AntreaControllerInfo) ([]byte, error) {
	cm, err := client.CoreV1().ConfigMaps(controllerInfo.PodRef.Namespace).Get(ctx, apis.AntreaCAConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	ca, ok := cm.Data[apis.CAConfigMapKey]
	if !ok {
		return nil, fmt.Errorf("missing key '%s' in ConfigMap", apis.CAConfigMapKey)
	}
	return []byte(ca), nil
}

func CreateAgentClientCfgFromObjects(
	ctx context.Context,
	k8sClientset kubernetes.Interface,
	kubeconfig *rest.Config,
	node *corev1.Node,
	agentInfo *v1beta1.AntreaAgentInfo,
	insecure bool,
) (*rest.Config, error) {
	nodeIPs, err := GetNodeAddrs(node)
	if err != nil {
		return nil, fmt.Errorf("error when getting IP of Node %s", node.Name)
	}

	cfg := rest.CopyConfig(kubeconfig)
	cfg.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	if insecure {
		cfg.Insecure = true
		cfg.CAFile = ""
		cfg.CAData = nil
	} else {
		cert := agentInfo.APICABundle
		if len(cert) == 0 {
			fmt.Println("Failed to retrieve certificate for Antrea Agent, which is required to establish a secure connection")
			// v1.13 is when APICABundle was added to the AntreaAgentInfo CRD
			if semver.Compare(agentInfo.Version, "v1.13") < 0 {
				fmt.Println("You may be using a version of the Antrea Agent that does not publish certificate data (< v1.13)")
			}
			fmt.Println("You can try running the command again with '--insecure'")
			return nil, fmt.Errorf("no cert available")
		}
		cfg.Insecure = false
		// The self-signed Agent certificate is only valid for localhost / 127.0.0.1
		cfg.ServerName = "localhost"
		cfg.CAData = cert
	}

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

func CreateAgentClientCfg(
	ctx context.Context,
	k8sClientset kubernetes.Interface,
	antreaClientset antrea.Interface,
	kubeconfig *rest.Config,
	nodeName string,
	insecure bool,
) (*rest.Config, error) {
	node, err := k8sClientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when looking up Node %s: %w", nodeName, err)
	}
	agentInfo, err := antreaClientset.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if agentInfo.NodeRef.Name == "" {
		return nil, fmt.Errorf("AntreaAgentInfo is not ready for Node %s", nodeName)
	}

	return CreateAgentClientCfgFromObjects(ctx, k8sClientset, kubeconfig, node, agentInfo, insecure)
}

func CreateControllerClientCfg(
	ctx context.Context,
	k8sClientset kubernetes.Interface,
	antreaClientset antrea.Interface,
	kubeconfig *rest.Config,
	insecure bool,
) (*rest.Config, error) {
	controllerInfo, err := antreaClientset.CrdV1beta1().AntreaControllerInfos().Get(ctx, "antrea-controller", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	controllerNode, err := k8sClientset.CoreV1().Nodes().Get(ctx, controllerInfo.NodeRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error when searching the Node of the controller: %w", err)
	}
	var controllerNodeIPs *ip.DualStackIPs
	controllerNodeIPs, err = GetNodeAddrs(controllerNode)
	if err != nil {
		return nil, fmt.Errorf("error when getting controller IP: %w", err)
	}

	cfg := rest.CopyConfig(kubeconfig)
	cfg.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	if insecure {
		cfg.Insecure = true
		cfg.CAFile = ""
		cfg.CAData = nil
	} else {
		caCert, err := GetControllerCACert(ctx, k8sClientset, controllerInfo)
		if err != nil {
			fmt.Println("Failed to retrieve certificate for Antrea Controller, which is required to establish a secure connection")
			fmt.Println("You can try running the command again with '--insecure'")
			return nil, fmt.Errorf("error when getting cert: %w", err)
		}
		cfg.Insecure = false
		cfg.ServerName = k8s.GetServiceDNSNames(controllerInfo.PodRef.Namespace, apis.AntreaServiceName)[0]
		cfg.CAData = caCert
	}

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

// Copyright 2019 Antrea Authors
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

package k8s

import (
	"fmt"
	"net"
	"os"
	"strings"

	discovery "k8s.io/api/discovery/v1"
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	policyclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	mcclientset "antrea.io/antrea/multicluster/pkg/client/clientset/versioned"
	crdclientset "antrea.io/antrea/pkg/client/clientset/versioned"
)

const (
	kubeServiceHostEnvKey = "KUBERNETES_SERVICE_HOST"
	kubeServicePortEnvKey = "KUBERNETES_SERVICE_PORT"
)

// CreateClients creates kube clients from the given config.
func CreateClients(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (
	clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, apiextensionclientset.Interface, mcclientset.Interface, policyclient.Interface, error) {
	kubeConfig, err := CreateRestConfig(config, kubeAPIServerOverride)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	aggregatorClient, err := aggregatorclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// Create client for CRD operations.
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// Create client for CRD manipulations.
	apiExtensionClient, err := apiextensionclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	// Create client for multicluster CRD operations.
	mcClient, err := mcclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	policyClient, err := policyclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	return client, aggregatorClient, crdClient, apiExtensionClient, mcClient, policyClient, nil
}

func CreateRestConfig(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (*rest.Config, error) {
	var kubeConfig *rest.Config
	var err error

	if len(config.Kubeconfig) == 0 {
		klog.Info("No kubeconfig file was specified. Falling back to in-cluster config")
		kubeConfig, err = rest.InClusterConfig()
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: config.Kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
	}

	if len(kubeAPIServerOverride) != 0 {
		kubeConfig.Host = kubeAPIServerOverride
	}

	if err != nil {
		return nil, err
	}

	kubeConfig.AcceptContentTypes = config.AcceptContentTypes
	kubeConfig.ContentType = config.ContentType
	kubeConfig.QPS = config.QPS
	kubeConfig.Burst = int(config.Burst)

	return kubeConfig, nil
}

// OverrideKubeAPIServer overrides the env vars related to the kubernetes service used by InClusterConfig.
// It's required because some K8s libraries like DelegatingAuthenticationOptions and DelegatingAuthorizationOptions
// read the information from env vars and don't support overriding via parameters.
func OverrideKubeAPIServer(kubeAPIServerOverride string) {
	if len(kubeAPIServerOverride) == 0 {
		return
	}
	hostPort := strings.Replace(kubeAPIServerOverride, "https://", "", -1)
	var host, port string
	var err error
	if host, port, err = net.SplitHostPort(hostPort); err != nil {
		// if SplitHostPort returns an error, the entire hostport is considered as host
		host = hostPort
		port = "443"
	}
	os.Setenv(kubeServiceHostEnvKey, host)
	os.Setenv(kubeServicePortEnvKey, port)
}

func EndpointSliceAPIAvailable(k8sClient clientset.Interface) (bool, error) {
	resources, err := k8sClient.Discovery().ServerResourcesForGroupVersion(discovery.SchemeGroupVersion.String())
	if err != nil {
		// The group version doesn't exist.
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("error getting server resources for GroupVersion %s: %v", discovery.SchemeGroupVersion.String(), err)
	}
	for _, resource := range resources.APIResources {
		if resource.Kind == "EndpointSlice" {
			return true, nil
		}
	}
	return false, nil
}

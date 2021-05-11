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
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	crdclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	legacycrdclientset "github.com/vmware-tanzu/antrea/pkg/legacyclient/clientset/versioned"
)

// CreateClients creates kube clients from the given config.
func CreateClients(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (clientset.Interface, aggregatorclientset.Interface, crdclientset.Interface, error) {
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
		return nil, nil, nil, err
	}

	kubeConfig.AcceptContentTypes = config.AcceptContentTypes
	kubeConfig.ContentType = config.ContentType
	kubeConfig.QPS = config.QPS
	kubeConfig.Burst = int(config.Burst)

	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	aggregatorClient, err := aggregatorclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	// Create client for crd operations
	crdClient, err := crdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	return client, aggregatorClient, crdClient, nil
}

// CreateLegacyCRDClient creates legacyCRD client from the given config.
func CreateLegacyCRDClient(config componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (legacycrdclientset.Interface, error) {
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

	legacyCrdClient, err := legacycrdclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return legacyCrdClient, nil
}

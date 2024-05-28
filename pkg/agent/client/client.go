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

package client

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis"
	cert "antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
)

// AntreaClientProvider provides a method to get Antrea client.
type AntreaClientProvider interface {
	GetAntreaClient() (versioned.Interface, error)
}

// antreaClientProvider provides an AntreaClientProvider that can dynamically react to CA bundle
// ConfigMap changes, as well as directly resolve the Antrea Service Endpoint when running inside a K8s cluster.
// The consumers of antreaClientProvider are supposed to always call GetAntreaClient() to get a client and not cache it.
type antreaClientProvider struct {
	config config.ClientConnectionConfiguration
	// mutex protects client.
	mutex sync.RWMutex
	// client is the Antrea client that will be returned. It will be updated when caBundle is updated.
	client versioned.Interface
	// caContentProvider provides the very latest content of the ca bundle.
	caContentProvider *dynamiccertificates.ConfigMapCAController
	// endpointResolver provides a known Endpoint for the Antrea Service. There is usually a
	// single Endpoint at any given time, given that the Antrea Controller runs as a
	// single-replica Deployment. By resolving the Endpoint manually and accessing it directly,
	// instead of depending on the ClusterIP functionality provided by the K8s proxy, we get
	// more flexibility when initializing the Antrea Agent. For example, we can retrieve
	// NetworkPolicies from the Controller even if the proxy is not (yet) available.
	// endpointResolver is only used when no kubeconfig is provided (otherwise we honor the
	// provided config).
	endpointResolver *EndpointResolver
}

// antreaClientProvider must implement the dynamiccertificates.Listener interface to be notified of
// CA bundle updates.
var _ dynamiccertificates.Listener = &antreaClientProvider{}

// antreaClientProvider must implement the Listener interface to be notified of an Endpoint change
// for the Antrea Service.
var _ Listener = &antreaClientProvider{}

func NewAntreaClientProvider(config config.ClientConnectionConfiguration, kubeClient kubernetes.Interface) (*antreaClientProvider, error) {
	antreaCAProvider, err := dynamiccertificates.NewDynamicCAFromConfigMapController(
		"antrea-ca",
		cert.GetCAConfigMapNamespace(),
		apis.AntreaCAConfigMapName,
		apis.CAConfigMapKey,
		kubeClient)
	if err != nil {
		return nil, err
	}

	var endpointResolver *EndpointResolver
	if len(config.Kubeconfig) == 0 {
		klog.InfoS("No Antrea kubeconfig file was specified. Falling back to in-cluster config")
		port := os.Getenv("ANTREA_SERVICE_PORT")
		if len(port) == 0 {
			return nil, fmt.Errorf("unable to create Endpoint resolver for Antrea Service, ANTREA_SERVICE_PORT must be defined for in-cluster config")
		}
		servicePort, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid port number stored in ANTREA_SERVICE_PORT: %w", err)
		}
		endpointResolver = NewEndpointResolver(kubeClient, env.GetAntreaNamespace(), apis.AntreaServiceName, int32(servicePort))
	}

	antreaClientProvider := &antreaClientProvider{
		config:            config,
		caContentProvider: antreaCAProvider,
		endpointResolver:  endpointResolver,
	}

	antreaCAProvider.AddListener(antreaClientProvider)
	if endpointResolver != nil {
		endpointResolver.AddListener(antreaClientProvider)
	}

	return antreaClientProvider, nil
}

// RunOnce runs the task a single time synchronously, ensuring client is initialized if kubeconfig is specified.
func (p *antreaClientProvider) RunOnce() error {
	return p.updateAntreaClient()
}

// Run starts the caContentProvider, which watches the ConfigMap and notifies changes
// by calling Enqueue.
func (p *antreaClientProvider) Run(ctx context.Context) {
	go p.caContentProvider.Run(ctx, 1)
	if p.endpointResolver != nil {
		go p.endpointResolver.Run(ctx)
	}
	<-ctx.Done()
}

// Enqueue implements dynamiccertificates.Listener. It will be called by caContentProvider
// when caBundle is updated.
func (p *antreaClientProvider) Enqueue() {
	if err := p.updateAntreaClient(); err != nil {
		klog.ErrorS(err, "Failed to update Antrea client")
	}
}

// GetAntreaClient implements AntreaClientProvider.
func (p *antreaClientProvider) GetAntreaClient() (versioned.Interface, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.client == nil {
		return nil, fmt.Errorf("Antrea client is not ready")
	}
	return p.client, nil
}

func (p *antreaClientProvider) updateAntreaClient() error {
	var kubeConfig *rest.Config
	var err error
	if len(p.config.Kubeconfig) == 0 {
		caBundle := p.caContentProvider.CurrentCABundleContent()
		if caBundle == nil {
			klog.InfoS("Didn't get CA certificate, skip updating Antrea Client")
			return nil
		}
		endpointURL := p.endpointResolver.CurrentEndpointURL()
		if endpointURL == nil {
			klog.InfoS("Didn't get Endpoint URL for Antrea Service, skip updating Antrea Client")
			return nil
		}
		kubeConfig, err = inClusterConfig(caBundle, endpointURL.String())
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: p.config.Kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return err
	}

	// ContentType will be used to define the Accept header if AcceptContentTypes is not set.
	kubeConfig.ContentType = "application/vnd.kubernetes.protobuf"
	kubeConfig.QPS = p.config.QPS
	kubeConfig.Burst = int(p.config.Burst)
	client, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	klog.Info("Updating Antrea client with the new CA bundle")
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.client = client

	return nil
}

// inClusterConfig returns a config object which uses the service account Kubernetes gives to
// Pods. It's intended for clients that expect to be running inside a Pod running on Kubernetes. It
// will return error if called from a process not running in a Kubernetes environment.
func inClusterConfig(caBundle []byte, endpoint string) (*rest.Config, error) {
	// #nosec G101: false positive triggered by variable name which includes "token"
	const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	tlsClientConfig := rest.TLSClientConfig{
		CAData:     caBundle,
		ServerName: k8s.GetServiceDNSNames(env.GetAntreaNamespace(), apis.AntreaServiceName)[0],
	}

	return &rest.Config{
		Host:            endpoint,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(token),
		BearerTokenFile: tokenFile,
	}, nil
}

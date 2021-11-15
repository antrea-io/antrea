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

package agent

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/config"
	"k8s.io/klog/v2"

	cert "antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/client/clientset/versioned"
)

// AntreaClientProvider provides a method to get Antrea client.
type AntreaClientProvider interface {
	GetAntreaClient() (versioned.Interface, error)
}

// antreaClientProvider provides an AntreaClientProvider that can dynamically react to ConfigMap changes.
type antreaClientProvider struct {
	config config.ClientConnectionConfiguration
	// mutex protects client.
	mutex sync.RWMutex
	// client is the Antrea client that will be returned. It will be updated when caBundle is updated.
	client versioned.Interface
	// caContentProvider provides the very latest content of the ca bundle.
	caContentProvider *dynamiccertificates.ConfigMapCAController
}

var _ dynamiccertificates.Listener = &antreaClientProvider{}

func NewAntreaClientProvider(config config.ClientConnectionConfiguration, kubeClient kubernetes.Interface) *antreaClientProvider {
	// The key "ca.crt" may not exist at the beginning, no need to fail as the CA provider will watch the ConfigMap
	// and notify antreaClientProvider of any update. The consumers of antreaClientProvider are supposed to always
	// call GetAntreaClient() to get a client and not cache it.
	antreaCAProvider, _ := dynamiccertificates.NewDynamicCAFromConfigMapController(
		"antrea-ca",
		cert.GetCAConfigMapNamespace(),
		cert.AntreaCAConfigMapName,
		cert.CAConfigMapKey,
		kubeClient)
	antreaClientProvider := &antreaClientProvider{
		config:            config,
		caContentProvider: antreaCAProvider,
	}

	antreaCAProvider.AddListener(antreaClientProvider)
	return antreaClientProvider
}

// RunOnce runs the task a single time synchronously, ensuring client is initialized if kubeconfig is specified.
func (p *antreaClientProvider) RunOnce() error {
	return p.updateAntreaClient()
}

// Run starts the caContentProvider, which watches the ConfigMap and notifies changes
// by calling Enqueue.
func (p *antreaClientProvider) Run(stopCh <-chan struct{}) {
	p.caContentProvider.Run(1, stopCh)
}

// Enqueue implements dynamiccertificates.Listener. It will be called by caContentProvider
// when caBundle is updated.
func (p *antreaClientProvider) Enqueue() {
	if err := p.updateAntreaClient(); err != nil {
		klog.Errorf("Failed to update Antrea client: %v", err)
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
		klog.Info("No antrea kubeconfig file was specified. Falling back to in-cluster config")
		caBundle := p.caContentProvider.CurrentCABundleContent()
		if caBundle == nil {
			klog.Info("Didn't get CA certificate, skip updating Antrea Client")
			return nil
		}
		kubeConfig, err = inClusterConfig(caBundle)
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

// inClusterConfig returns a config object which uses the service account
// kubernetes gives to pods. It's intended for clients that expect to be
// running inside a pod running on kubernetes. It will return error
// if called from a process not running in a kubernetes environment.
func inClusterConfig(caBundle []byte) (*rest.Config, error) {
	// #nosec G101: false positive triggered by variable name which includes "token"
	const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	host, port := os.Getenv("ANTREA_SERVICE_HOST"), os.Getenv("ANTREA_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, fmt.Errorf("unable to load in-cluster configuration, ANTREA_SERVICE_HOST and ANTREA_SERVICE_PORT must be defined")
	}

	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	tlsClientConfig := rest.TLSClientConfig{
		CAData:     caBundle,
		ServerName: cert.GetAntreaServerNames(cert.AntreaServiceName)[0],
	}

	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		TLSClientConfig: tlsClientConfig,
		BearerToken:     string(token),
		BearerTokenFile: tokenFile,
	}, nil
}

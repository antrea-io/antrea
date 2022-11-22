// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"fmt"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	clientset "k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclusterv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	antreacrd "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/util/env"
	// +kubebuilder:scaffold:imports
)

var (
	validationWebhooksNamePattern = "%s%santrea-mc-validating-webhook-configuration"
	mutationWebhooksNamePattern   = "%s%santrea-mc-mutating-webhook-configuration"

	// The unit test code will change the function to set up a mock manager.
	setupManagerAndCertControllerFunc = setupManagerAndCertController
)

const (
	selfSignedCertDir = "/var/run/antrea/multicluster-controller-self-signed"
	certDir           = "/var/run/antrea/multicluster-controller-tls"
	serviceName       = "antrea-mc-webhook-service"
	configMapName     = "antrea-mc-ca"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(scheme))
	utilruntime.Must(multiclusterv1alpha1.AddToScheme(scheme))
	utilruntime.Must(multiclusterv1alpha2.AddToScheme(scheme))
	utilruntime.Must(antreacrd.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

// createClients creates kube clients from the given config.
func createClients(kubeConfig *rest.Config) (
	clientset.Interface, aggregatorclientset.Interface, apiextensionclientset.Interface, error) {
	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	aggregatorClient, err := aggregatorclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	// Create client for crd manipulations
	apiExtensionClient, err := apiextensionclientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	return client, aggregatorClient, apiExtensionClient, nil
}

func getCaConfig(controllerNs string) *certificate.CAConfig {
	return &certificate.CAConfig{
		CAConfigMapName: configMapName,
		// the key pair name has to be "tls" https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/manager/manager.go#L221
		PairName:           "tls",
		CertDir:            certDir,
		ServiceName:        serviceName,
		SelfSignedCertDir:  selfSignedCertDir,
		MutationWebhooks:   getMutationWebhooks(controllerNs),
		ValidatingWebhooks: getValidationWebhooks(controllerNs),
		CertReadyTimeout:   2 * time.Minute,
		MaxRotateDuration:  time.Hour * (24 * 365),
	}
}

func getValidationWebhooks(controllerNs string) []string {
	if controllerNs != "" {
		return []string{fmt.Sprintf(validationWebhooksNamePattern, controllerNs, "-")}
	}
	return []string{fmt.Sprintf(validationWebhooksNamePattern, "", "")}
}

func getMutationWebhooks(controllerNs string) []string {
	if controllerNs != "" {
		return []string{fmt.Sprintf(mutationWebhooksNamePattern, controllerNs, "-")}
	}
	return []string{fmt.Sprintf(mutationWebhooksNamePattern, "", "")}
}

func setupManagerAndCertController(o *Options) (manager.Manager, error) {
	ctrl.SetLogger(klog.NewKlogr())

	// build up cert controller to manage certificate for MC Controller
	k8sConfig := ctrl.GetConfigOrDie()
	client, aggregatorClient, apiExtensionClient, err := createClients(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating K8s clients: %v", err)
	}

	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	caCertController, err := certificate.ApplyServerCert(o.SelfSignedCert, client, aggregatorClient, apiExtensionClient,
		secureServing, getCaConfig(o.options.Namespace))
	if err != nil {
		return nil, fmt.Errorf("error applying server cert: %v", err)
	}
	if err := caCertController.RunOnce(context.TODO()); err != nil {
		return nil, err
	}

	if o.SelfSignedCert {
		o.options.CertDir = selfSignedCertDir
	} else {
		o.options.CertDir = certDir
	}

	mgr, err := ctrl.NewManager(k8sConfig, o.options)
	if err != nil {
		return nil, fmt.Errorf("error starting manager: %v", err)
	}

	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha1-clusterset",
		&webhook.Admission{Handler: &clusterSetValidator{
			Client:    mgr.GetClient(),
			namespace: env.GetPodNamespace()}})
	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha2-clusterclaim",
		&webhook.Admission{Handler: &clusterClaimValidator{
			Client:    mgr.GetClient(),
			namespace: env.GetPodNamespace()}})

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("error setting up health check: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("error setting up ready check: %v", err)
	}
	return mgr, nil
}

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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	clientset "k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	controllerruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	antreacrdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreacrdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/util/env"
	k8sutil "antrea.io/antrea/pkg/util/k8s"
	// +kubebuilder:scaffold:imports
)

var (
	// The unit test code will change the function to set up a mock manager.
	setupManagerAndCertControllerFunc = setupManagerAndCertController
)

const (
	selfSignedCertDir = "/var/run/antrea/multicluster-controller-self-signed"
	certDir           = "/var/run/antrea/multicluster-controller-tls"
	serviceName       = "antrea-mc-webhook-service"
	configMapName     = "antrea-mc-ca"
	leaderRole        = "leader"
	memberRole        = "member"
)

var (
	// mcDefaultServedLabels contains the labels added on the Webhooks which are needed by both leader and member controllers.
	mcDefaultServedLabels = map[string]string{
		"app":       "antrea",
		"served-by": "antrea-mc-controller",
	}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(scheme))
	utilruntime.Must(mcv1alpha1.AddToScheme(scheme))
	utilruntime.Must(mcv1alpha2.AddToScheme(scheme))
	utilruntime.Must(antreacrdv1alpha1.AddToScheme(scheme))
	utilruntime.Must(antreacrdv1beta1.AddToScheme(scheme))
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

func getCaConfig(isLeader bool, controllerNs string) *certificate.CAConfig {
	return &certificate.CAConfig{
		CAConfigMapName: configMapName,
		// the key pair name has to be "tls" https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/manager/manager.go#L221
		PairName:                  "tls",
		CertDir:                   certDir,
		ServiceName:               serviceName,
		SelfSignedCertDir:         selfSignedCertDir,
		MutationWebhookSelector:   getWebhookLabel(isLeader, controllerNs),
		ValidatingWebhookSelector: getWebhookLabel(isLeader, controllerNs),
		CertReadyTimeout:          2 * time.Minute,
		MinValidDuration:          time.Hour * 24 * 90, // Rotate the certificate 90 days in advance.
	}
}

func getWebhookLabel(isLeader bool, controllerNs string) *metav1.LabelSelector {
	labels := mcDefaultServedLabels
	if isLeader {
		labels["role"] = leaderRole
	} else {
		labels["role"] = memberRole
	}
	// It is allowed that multiple leader controllers running in different Namespace in the same cluster.
	// "served-in: $controllerNS" is useful to select the Webhooks managed by the current mc-controller.
	if len(controllerNs) > 0 {
		labels["served-in"] = controllerNs
	}
	return &metav1.LabelSelector{
		MatchLabels: labels,
	}
}

func setupManagerAndCertController(isLeader bool, o *Options) (manager.Manager, error) {
	ctrl.SetLogger(klog.NewKlogr())

	podNamespace := env.GetPodNamespace()

	var caConfig *certificate.CAConfig
	if isLeader {
		caConfig = getCaConfig(isLeader, podNamespace)
	} else {
		caConfig = getCaConfig(isLeader, "")
	}

	// build up cert controller to manage certificate for MC Controller
	k8sConfig := ctrl.GetConfigOrDie()
	k8sConfig.QPS = common.ResourceExchangeQPS
	k8sConfig.Burst = common.ResourceExchangeBurst
	client, aggregatorClient, apiExtensionClient, err := createClients(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating K8s clients: %v", err)
	}

	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	caCertController, err := certificate.ApplyServerCert(o.SelfSignedCert, client, aggregatorClient, apiExtensionClient, secureServing, caConfig)
	if err != nil {
		return nil, fmt.Errorf("error applying server cert: %v", err)
	}
	if err := caCertController.RunOnce(context.TODO()); err != nil {
		return nil, err
	}

	options := o.options
	if o.SelfSignedCert {
		options.Metrics.CertDir = selfSignedCertDir
		o.WebhookConfig.CertDir = selfSignedCertDir
	} else {
		options.Metrics.CertDir = certDir
		o.WebhookConfig.CertDir = certDir
	}
	options.WebhookServer = webhook.NewServer(webhook.Options{
		Port:    *o.WebhookConfig.Port,
		Host:    o.WebhookConfig.Host,
		CertDir: o.WebhookConfig.CertDir,
	})

	cacheOptions := &options.Cache
	if isLeader {
		// For the leader, restrict the cache to the controller's Namespace.
		cacheOptions.DefaultNamespaces = map[string]cache.Config{
			podNamespace: {},
		}
	} else {
		// For a member, restict the cache to the controller's Namespace for the following objects.
		cacheOptions.ByObject = map[controllerruntimeclient.Object]cache.ByObject{
			&mcv1alpha1.Gateway{}: {
				Namespaces: map[string]cache.Config{
					podNamespace: {},
				},
			},
			&mcv1alpha2.ClusterSet{}: {
				Namespaces: map[string]cache.Config{
					podNamespace: {},
				},
			},
		}
	}

	// EndpointSlice is enabled in AntreaProxy by default since v1.11, so Antrea MC
	// will use EndpointSlice API by default to keep consistent with AntreaProxy.
	endpointSliceAPIAvailable, err := k8sutil.EndpointSliceAPIAvailable(client)
	if err != nil {
		return nil, fmt.Errorf("error checking if EndpointSlice v1 API is available")
	}
	if !endpointSliceAPIAvailable {
		klog.InfoS("The EndpointSlice v1 API is not available, falling back to the Endpoints API")
		o.EnableEndpointSlice = false
	} else {
		o.EnableEndpointSlice = true
	}

	// ClusterClaim CRD is removed since v1.13. Check the existence of
	// ClusterClaim API before using ClusterClaim API.
	clusterClaimCRDAvailable, err := clusterClaimCRDAvailable(client)
	if err != nil {
		return nil, fmt.Errorf("error checking if ClusterClaim API is available")
	}
	o.ClusterCalimCRDAvailable = clusterClaimCRDAvailable

	mgr, err := ctrl.NewManager(k8sConfig, options)
	if err != nil {
		return nil, fmt.Errorf("error creating manager: %v", err)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("error setting up health check: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("error setting up ready check: %v", err)
	}
	return mgr, nil
}

func clusterClaimCRDAvailable(k8sClient clientset.Interface) (bool, error) {
	groupVersion := mcv1alpha2.SchemeGroupVersion.String()
	resources, err := k8sClient.Discovery().ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		// The group version doesn't exist.
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("error getting server resources for GroupVersion %s: %v", groupVersion, err)
	}
	for _, resource := range resources.APIResources {
		if resource.Kind == "ClusterClaim" {
			return true, nil
		}
	}
	return false, nil
}

/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"time"

	"k8s.io/klog/v2/klogr"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	apiextensionclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	clientset "k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	aggregatorclientset "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
	"antrea.io/antrea/pkg/apiserver/certificate"
	"antrea.io/antrea/pkg/util/env"
	// +kubebuilder:scaffold:imports
)

var (
	setupLog                      = ctrl.Log.WithName("setup")
	validationWebhooksNamePattern = "antrea-multicluster-%s%svalidating-webhook-configuration"
	mutationWebhooksNamePattern   = "antrea-multicluster-%s%smutating-webhook-configuration"
)

const (
	selfSignedCertDir = "/var/run/antrea/multicluster-controller-self-signed"
	certDir           = "/var/run/antrea/multicluster-controller-tls"
	serviceName       = "antrea-multicluster-webhook-service"
	configMapName     = "antrea-multicluster-ca"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(multiclusterv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func getValidationWebhooks(isLeader bool) []string {
	if isLeader {
		return []string{fmt.Sprintf(validationWebhooksNamePattern, env.GetPodNamespace(), "-")}
	}
	return []string{fmt.Sprintf(validationWebhooksNamePattern, "", "")}
}

func getMutationWebhooks(isLeader bool) []string {
	if isLeader {
		return []string{fmt.Sprintf(mutationWebhooksNamePattern, env.GetPodNamespace(), "-")}
	}
	return []string{fmt.Sprintf(mutationWebhooksNamePattern, "", "")}

}

func run(o *Options) error {
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// build up cert controller to manage certificate for multicluster controller
	k8sConfig := ctrl.GetConfigOrDie()
	client, aggregatorClient, apiExtensionClient, err := createClients(k8sConfig)
	if err != nil {
		return fmt.Errorf("error creating K8s clients: %v", err)
	}

	secureServing := genericoptions.NewSecureServingOptions().WithLoopback()
	caCertController, err := certificate.ApplyServerCert(o.SelfSignedCert, client, aggregatorClient, apiExtensionClient, secureServing, getCAConifg(o.leader))
	if err != nil {
		return fmt.Errorf("error applying server cert: %v", err)
	}
	if err := caCertController.RunOnce(); err != nil {
		return err
	}

	if o.SelfSignedCert {
		o.options.CertDir = selfSignedCertDir
	} else {
		o.options.CertDir = certDir
	}
	// TODO: These leader checks should go once we have a separate command for leader and member controller
	if o.leader {
		// on the leader we want the reconciler to run for a given namspace instead of cluster scope
		o.options.Namespace = env.GetPodNamespace()
	}
	mgr, err := ctrl.NewManager(k8sConfig, o.options)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return fmt.Errorf("unable to start manager, err: %v", err)
	}

	if err = (&multiclustercontrollers.ClusterClaimReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterClaim")
		return fmt.Errorf("unable to create ClusterClaim controller, err: %v", err)
	}
	if err = (&multiclustercontrollers.MemberClusterAnnounceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "MemberClusterAnnounce")
		return fmt.Errorf("unable to create MemberClusterAnnounce controller, err: %v", err)
	}
	if err = (&multiclustercontrollers.ClusterSetReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Log:      klogr.New().WithName("controllers"),
		IsLeader: o.leader,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterSet")
		return fmt.Errorf("unable to create ClusterSet controller, err: %v", err)
	}
	if err = (&multiclustercontrollers.ResourceExportFilterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResourceExportFilter")
		return fmt.Errorf("unable to create ResourceExportFilter controller, err: %v", err)
	}
	if err = (&multiclustercontrollers.ResourceImportFilterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResourceImportFilter")
		return fmt.Errorf("unable to create ResourceImportFilter controller, err: %v", err)
	}
	if err = (&multiclusterv1alpha1.ClusterClaim{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ClusterClaim")
		return fmt.Errorf("unable to create ClusterClaim webhook, err: %v", err)
	}
	if err = (&multiclusterv1alpha1.ClusterSet{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ClusterSet")
		return fmt.Errorf("unable to create ClusterSet webhook, err: %v", err)
	}
	if err = (&multiclusterv1alpha1.MemberClusterAnnounce{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "MemberClusterAnnounce")
		return fmt.Errorf("unable to create MemberClusterAnnounce webhook, err: %v", err)
	}
	if err = (&multiclustercontrollers.ResourceExportReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResourceExport")
		return fmt.Errorf("unable to create ResourceExport controller, err: %v", err)
	}
	if err = (&multiclustercontrollers.ResourceImportReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResourceImport")
		return fmt.Errorf("unable to create ResourceImport controller, err: %v", err)
	}
	if err = (&multiclusterv1alpha1.ResourceImport{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ResourceImport")
		return fmt.Errorf("unable to create ResourceImport webhook, err: %v", err)
	}
	if err = (&multiclusterv1alpha1.ResourceExport{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ResourceExport")
		return fmt.Errorf("unable to create ResourceExport webhook, err: %v", err)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return fmt.Errorf("unable to set up health check, err: %v", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		return fmt.Errorf("unable to set up ready check, err: %v", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		return fmt.Errorf("problem running manager, err: %v", err)
	}
	return nil
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

func getCAConifg(isLeader bool) certificate.CAConfig {
	return certificate.CAConfig{
		CAConfigMapName: configMapName,
		// the key pair name has to be "tls" https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/manager/manager.go#L221
		AntreaPairName:             "tls",
		CertDir:                    certDir,
		AntreaServiceName:          serviceName,
		SelfSignedCertDir:          selfSignedCertDir,
		APIServiceNames:            []string{},
		MutationWebhooks:           getMutationWebhooks(isLeader),
		ValidatingWebhooks:         getValidationWebhooks(isLeader),
		OptionalMutationWebhooks:   []string{},
		CrdsWithConversionWebhooks: []string{},
		CertReadyTimeout:           2 * time.Minute,
		MaxRotateDuration:          time.Hour * (24 * 365),
	}
}

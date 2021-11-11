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

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
	// +kubebuilder:scaffold:imports
)

var (
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(multiclusterv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func run(o *Options) error {
	opts := zap.Options{
		Development: true,
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), o.options)
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
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
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

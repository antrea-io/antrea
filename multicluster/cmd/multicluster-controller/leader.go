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

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
	"antrea.io/antrea/pkg/util/env"
)

func newLeaderCommand() *cobra.Command {
	var leaderCmd = &cobra.Command{
		Use:   "leader",
		Short: "Run the MC controller in leader cluster",
		Long:  "Run the Antrea Multi-Cluster controller for leader cluster",
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.complete(args); err != nil {
				klog.Fatalf("Failed to complete: %v", err)
			}
			if err := runLeader(opts); err != nil {
				klog.Fatalf("Error running controller: %v", err)
			}
		},
	}

	return leaderCmd
}

func runLeader(o *Options) error {
	// on the leader we want the reconciler to run for a given Namespace instead of cluster scope
	o.options.Namespace = env.GetPodNamespace()

	mgr, err := setupManagerAndCertController(o)
	if err != nil {
		return err
	}

	memberClusterStatusManager := multiclustercontrollers.NewMemberClusterAnnounceReconciler(
		mgr.GetClient(), mgr.GetScheme())
	if err = memberClusterStatusManager.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating MemberClusterAnnounce controller: %v", err)
	}
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha1-memberclusterannounce",
		&webhook.Admission{Handler: &memberClusterAnnounceValidator{
			Client:    mgr.GetClient(),
			namespace: env.GetPodNamespace()}})

	clusterSetReconciler := &multiclustercontrollers.LeaderClusterSetReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		StatusManager: memberClusterStatusManager,
	}
	if err = clusterSetReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ClusterSet controller: %v", err)
	}

	resExportReconciler := &multiclustercontrollers.ResourceExportReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme()}
	if err = resExportReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceExport controller: %v", err)
	}
	if err = (&multiclusterv1alpha1.ResourceExport{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceExport webhook: %v", err)
	}

	if err := (&multiclusterv1alpha1.ResourceImport{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceImport webhook: %v", err)
	}

	// Only leader runs the ResourceExportFilterReconciler
	if err = (&multiclustercontrollers.ResourceExportFilterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceExportFilter controller: %v", err)
	}

	klog.InfoS("Leader MC Controller Starting Manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("error running Manager: %v", err)
	}
	return nil
}

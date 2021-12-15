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

	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
)

func newMemberCommand() *cobra.Command {
	var memberCmd = &cobra.Command{
		Use:   "member",
		Short: "Run the MC controller in member cluster",
		Long:  "Run the Antrea Multi-Cluster controller for member cluster",
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.complete(args); err != nil {
				klog.Fatalf("Failed to complete: %v", err)
			}
			if err := runMember(opts); err != nil {
				klog.Fatalf("Error running controller: %v", err)
			}
		},
	}

	return memberCmd
}

func runMember(o *Options) error {
	mgr, err := setupManagerAndCertController(o)
	if err != nil {
		return err
	}

	clusterSetReconciler := &multiclustercontrollers.MemberClusterSetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
	if err = clusterSetReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ClusterSet controller: %v", err)
	}

	svcExportReconciler := &multiclustercontrollers.ServiceExportReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		RemoteCommonAreaManager: &clusterSetReconciler.RemoteCommonAreaManager}
	if err = svcExportReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ServiceExport controller: %v", err)
	}
	// Member runs ResourceImportReconciler from RemoteCommonArea only

	// ResourceImportFilterReconciler is only run on the member cluster
	if err = (&multiclustercontrollers.ResourceImportFilterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceImportFilter controller: %v", err)
	}

	klog.InfoS("Starting Manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("error running Manager: %v", err)
	}
	return nil
}

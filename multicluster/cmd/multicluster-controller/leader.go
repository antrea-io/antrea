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
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/leader"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/env"
)

func newLeaderCommand() *cobra.Command {
	var leaderCmd = &cobra.Command{
		Use:   "leader",
		Short: "Run the MC controller in leader cluster",
		Long:  "Run the Antrea Multi-Cluster controller for leader cluster",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()
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
	podNamespace := env.GetPodNamespace()
	stopCh := signals.RegisterSignalHandlers()

	mgr, err := setupManagerAndCertControllerFunc(true, o)
	if err != nil {
		return err
	}

	mgrClient := mgr.GetClient()
	mgrScheme := mgr.GetScheme()
	memberClusterStatusManager := leader.NewMemberClusterAnnounceReconciler(
		mgrClient, mgrScheme)
	if err = memberClusterStatusManager.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating MemberClusterAnnounce controller: %v", err)
	}

	noCachedClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgrScheme, Mapper: mgr.GetRESTMapper()})
	if err != nil {
		return err
	}
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha1-memberclusterannounce",
		&webhook.Admission{Handler: &memberClusterAnnounceValidator{
			Client:    noCachedClient,
			decoder:   admission.NewDecoder(mgr.GetScheme()),
			namespace: podNamespace,
		}},
	)

	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha2-clusterset",
		&webhook.Admission{Handler: &clusterSetValidator{
			Client:    mgr.GetClient(),
			decoder:   admission.NewDecoder(mgr.GetScheme()),
			namespace: env.GetPodNamespace(),
			role:      leaderRole,
		}},
	)

	clusterSetReconciler := leader.NewLeaderClusterSetReconciler(mgrClient, podNamespace,
		o.ClusterCalimCRDAvailable, memberClusterStatusManager)
	if err := clusterSetReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ClusterSet controller: %v", err)
	}

	resExportReconciler := &leader.ResourceExportReconciler{
		Client: mgrClient,
		Scheme: mgrScheme}
	if err = resExportReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceExport controller: %v", err)
	}
	if o.EnableStretchedNetworkPolicy {
		labelExportReconciler := leader.NewLabelIdentityExportReconciler(
			mgrClient,
			mgrScheme,
			podNamespace)
		if err = labelExportReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("error creating LabelIdentityExport controller: %v", err)
		}
		go labelExportReconciler.Run(stopCh)
	}

	if err = (&multiclusterv1alpha1.ResourceExport{}).SetupWebhookWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ResourceExport webhook: %v", err)
	}

	staleController := leader.NewStaleResCleanupController(
		mgr.GetClient(),
		mgr.GetScheme(),
	)
	if err = staleController.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating StaleResCleanupController: %v", err)
	}
	go staleController.Run(stopCh)

	klog.InfoS("Leader MC Controller Starting Manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("error running Manager: %v", err)
	}
	return nil
}

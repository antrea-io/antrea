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

	multiclustercontrollers "antrea.io/antrea/multicluster/controllers/multicluster"
	"antrea.io/antrea/multicluster/controllers/multicluster/member"
	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/env"
)

func newMemberCommand() *cobra.Command {
	var memberCmd = &cobra.Command{
		Use:   "member",
		Short: "Run the MC controller in member cluster",
		Long:  "Run the Antrea Multi-Cluster controller for member cluster",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			defer log.FlushLogs()
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
	mgr, err := setupManagerAndCertControllerFunc(false, o)
	if err != nil {
		return err
	}

	stopCh := signals.RegisterSignalHandlers()
	hookServer := mgr.GetWebhookServer()
	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha1-gateway",
		&webhook.Admission{Handler: &gatewayValidator{
			Client:    mgr.GetClient(),
			namespace: env.GetPodNamespace()}})

	hookServer.Register("/validate-multicluster-crd-antrea-io-v1alpha2-clusterset",
		&webhook.Admission{Handler: &clusterSetValidator{
			Client:    mgr.GetClient(),
			namespace: env.GetPodNamespace(),
			role:      memberRole},
		})

	clusterSetReconciler := member.NewMemberClusterSetReconciler(mgr.GetClient(),
		mgr.GetScheme(),
		env.GetPodNamespace(),
		o.EnableStretchedNetworkPolicy,
		o.ClusterCalimCRDAvailable,
	)
	if err = clusterSetReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ClusterSet controller: %v", err)
	}

	commonAreaGetter := clusterSetReconciler
	svcExportReconciler := member.NewServiceExportReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		commonAreaGetter,
		o.EndpointIPType,
		o.EnableEndpointSlice,
	)
	if err = svcExportReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating ServiceExport controller: %v", err)
	}
	if o.EnableStretchedNetworkPolicy {
		labelIdentityReconciler := member.NewLabelIdentityReconciler(
			mgr.GetClient(),
			mgr.GetScheme(),
			commonAreaGetter)
		if err = labelIdentityReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("error creating LabelIdentity controller: %v", err)
		}
		go labelIdentityReconciler.Run(stopCh)
	}

	gwReconciler := member.NewGatewayReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		env.GetPodNamespace(),
		opts.PodCIDRs,
		commonAreaGetter)
	if err = gwReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating Gateway controller: %v", err)
	}

	nodeReconciler := member.NewNodeReconciler(
		mgr.GetClient(),
		mgr.GetScheme(),
		env.GetPodNamespace(),
		opts.ServiceCIDR,
		opts.GatewayIPPrecedence)
	if err = nodeReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("error creating Node controller: %v", err)
	}

	staleController := multiclustercontrollers.NewStaleResCleanupController(
		mgr.GetClient(),
		mgr.GetScheme(),
		env.GetPodNamespace(),
		commonAreaGetter,
		multiclustercontrollers.MemberCluster,
	)

	go staleController.Run(stopCh)
	// Member runs ResourceImportReconciler from RemoteCommonArea only

	klog.InfoS("Member MC Controller Starting Manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("error running Manager: %v", err)
	}
	return nil
}

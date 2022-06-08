// Copyright 2022 Antrea Authors
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

package delete

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type memberClusterOptions struct {
	namespace  string
	clusterSet string
}

var memberClusterOpts *memberClusterOptions

var memberClusterExamples = strings.Trim(`
# Delete a member cluster in a ClusterSet
  $ antctl mc delete membercluster <MEMBER_CLUSTER_ID> -n <NAMESPACE> --clusterset <CLUSTERSET_ID>
`, "\n")

func (o *memberClusterOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}
	if o.clusterSet == "" {
		return fmt.Errorf("the ClusterSet cannot be empty")
	}

	return nil
}

func NewMemberClusterCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "membercluster",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Delete a member cluster in a ClusterSet",
		Long:    "Delete a member cluster in a ClusterSet",
		Example: memberClusterExamples,
		RunE:    memberClusterRunE,
	}

	o := &memberClusterOptions{}
	memberClusterOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of member Cluster")
	command.Flags().StringVarP(&o.clusterSet, "clusterset", "", "", "ClusterSet ID of the member Cluster")

	return command
}

func memberClusterRunE(cmd *cobra.Command, args []string) error {
	if err := memberClusterOpts.validateAndComplete(); err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("exactly one ClusterID is required, got %d", len(args))
	}

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)

	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: multiclusterscheme.Scheme})
	if err != nil {
		return err
	}
	memberClusterID := args[0]
	clusterSet := &multiclusterv1alpha1.ClusterSet{}
	if err := k8sClient.Get(context.TODO(), types.NamespacedName{Name: memberClusterOpts.clusterSet, Namespace: memberClusterOpts.namespace}, clusterSet); err != nil {
		return err
	}

	var memberClusters []multiclusterv1alpha1.MemberCluster
	for _, m := range clusterSet.Spec.Members {
		if m.ClusterID != memberClusterID {
			memberClusters = append(memberClusters, m)
		}
	}
	if len(memberClusters) == len(clusterSet.Spec.Members) {
		return fmt.Errorf(`member cluster "%s" not found in ClusterSet "%s"`, memberClusterID, memberClusterOpts.clusterSet)
	}
	clusterSet.Spec.Members = memberClusters
	if err := k8sClient.Update(context.TODO(), clusterSet); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Member cluster \"%s\" deleted\n", memberClusterID)
	return nil
}

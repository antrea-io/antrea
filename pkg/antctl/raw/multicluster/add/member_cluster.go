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

package add

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
	namespace      string
	clusterSet     string
	serviceAccount string
}

var memberClusterOpt *memberClusterOptions

var memberClusterExamples = strings.Trim(`
# Add a new member cluster to a ClusterSet
  $ antctl mc add membercluster <CLUSTER_ID> -n <NAMESPACE> --clusterset <CLUSTERSET_ID> --service-account <SERVICE_ACCOUNT>
`, "\n")

func (o *memberClusterOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}
	if o.clusterSet == "" {
		return fmt.Errorf("the ClusterSet cannot be empty")
	}
	if o.serviceAccount == "" {
		return fmt.Errorf("the ServiceAccount cannot be empty")
	}

	return nil
}

func NewMemberClusterCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "membercluster",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Add a new member cluster to a ClusterSet",
		Long:    "Add a new member cluster to a ClusterSet",
		Example: memberClusterExamples,
		RunE:    memberClusterRunE,
	}

	o := &memberClusterOptions{}
	memberClusterOpt = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of member cluster")
	command.Flags().StringVarP(&o.clusterSet, "clusterset", "", "", "The name of target ClusterSet to add a new member cluster")
	command.Flags().StringVarP(&o.serviceAccount, "service-account", "", "", "ServiceAccount of the member cluster")

	return command
}

func memberClusterRunE(cmd *cobra.Command, args []string) error {
	if err := memberClusterOpt.validateAndComplete(); err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("exactly one NAME is required, got %d", len(args))
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
	if err := k8sClient.Get(context.TODO(), types.NamespacedName{Name: memberClusterOpt.clusterSet, Namespace: memberClusterOpt.namespace}, clusterSet); err != nil {
		return err
	}
	for _, member := range clusterSet.Spec.Members {
		if member.ClusterID == memberClusterID {
			return fmt.Errorf(`the member cluster "%s" was already added to the ClusterSet "%s"`, memberClusterID, memberClusterOpt.clusterSet)
		}
	}
	clusterSet.Spec.Members = append(clusterSet.Spec.Members, multiclusterv1alpha1.MemberCluster{ClusterID: memberClusterID, ServiceAccount: memberClusterOpt.serviceAccount})
	if err := k8sClient.Update(context.TODO(), clusterSet); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "The member cluster \"%s\" is added to the ClusterSet \"%s\" successfully\n", memberClusterID, memberClusterOpt.clusterSet)
	return nil
}

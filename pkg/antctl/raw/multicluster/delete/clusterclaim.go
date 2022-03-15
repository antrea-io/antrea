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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type clusterClaimOptions struct {
	namespace string
}

var clusterClaimOpt *clusterClaimOptions

var clusterClaimExamples = strings.Trim(`
# Delete the two ClusterClaims in a specified Namespace. One for the leader or member cluster, and another for the ClusterSet
  $ antctl mc delete clusterclaims -n <NAMESPACE>
`, "\n")

func (o *clusterClaimOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}

	return nil
}

func NewClusterClaimCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "clusterclaims",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Delete the ClusterClaims in a specified Namespace",
		Long:    "Delete the ClusterClaims in a specified Namespace. One for the leader or member cluster, and another for the ClusterSet",
		Example: clusterClaimExamples,
		RunE:    clusterClaimRunE,
	}

	o := &clusterClaimOptions{}
	clusterClaimOpt = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ClusterClaim")

	return command
}

func clusterClaimRunE(cmd *cobra.Command, args []string) error {
	if err := clusterClaimOpt.validateAndComplete(); err != nil {
		return err
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

	clusterClaims := []*multiclusterv1alpha1.ClusterClaim{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      multiclusterv1alpha1.WellKnownClusterClaimID,
				Namespace: clusterClaimOpt.namespace,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      multiclusterv1alpha1.WellKnownClusterClaimClusterSet,
				Namespace: clusterClaimOpt.namespace,
			},
		},
	}

	for _, clusterClaim := range clusterClaims {
		if err := deleteClusterClaim(cmd, k8sClient, clusterClaim); err != nil {
			return err
		}
	}

	return nil
}

func deleteClusterClaim(cmd *cobra.Command, k8sClient client.Client, clusterClaim *multiclusterv1alpha1.ClusterClaim) error {
	err := k8sClient.Delete(context.TODO(), clusterClaim)
	if err != nil {
		if !errors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ClusterClaim \"%s\", error: %s\n", clusterClaim.ObjectMeta.Name, err.Error())
			return err
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" not found\n", clusterClaim.ObjectMeta.Name)
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" deleted\n", clusterClaim.ObjectMeta.Name)
	}

	return nil
}

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

package create

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
	namespace    string
	clusterSetID string
	clusterID    string
}

var clusterClaimOpt *clusterClaimOptions

var clusterClaimExamples = strings.Trim(`
# Create two ClusterClaims, one for the leader or member cluster and another for the ClusterSet
  $ antctl mc create clusterclaims --cluster-id <CLUSTER_ID> --clusterset <CLUSTERSET_ID> -n <NAMESPACE>
`, "\n")

func (o *clusterClaimOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}
	if o.clusterSetID == "" {
		return fmt.Errorf("the ClusterSet ID cannot be empty")
	}
	if o.clusterID == "" {
		return fmt.Errorf("the cluster ID cannot be empty")
	}

	return nil
}

func NewClusterClaimCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "clusterclaims",
		Args:    cobra.MaximumNArgs(0),
		Short:   "Create two ClusterClaims in a leader or member cluster",
		Long:    "Create two ClusterClaims in a leader or member cluster. One for ClusterSet and another for the leader or member cluster",
		Example: clusterClaimExamples,
		RunE:    clusterClaimRunE,
	}

	o := &clusterClaimOptions{}
	clusterClaimOpt = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterClaim")
	command.Flags().StringVarP(&o.clusterSetID, "clusterset-id", "", "", "ClusterSet ID of the ClusterClaim for the ClusterSet")
	command.Flags().StringVarP(&o.clusterID, "cluster-id", "", "", "cluster ID of the ClusterClaim for the leader or member cluster")

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

	clusterClaim := &multiclusterv1alpha1.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      multiclusterv1alpha1.WellKnownClusterClaimID,
			Namespace: clusterClaimOpt.namespace,
		},
		Value: clusterClaimOpt.clusterID,
		Name:  multiclusterv1alpha1.WellKnownClusterClaimID,
	}

	var createErr error
	createErr = k8sClient.Create(context.TODO(), clusterClaim)
	if createErr != nil {
		if errors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" already exists\n", multiclusterv1alpha1.WellKnownClusterClaimID)
			createErr = nil
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ClusterClaim \"%s\", error: %s\n", multiclusterv1alpha1.WellKnownClusterClaimID, createErr.Error())
			return createErr
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" with Value \"%s\" created\n", multiclusterv1alpha1.WellKnownClusterClaimID, clusterClaimOpt.clusterID)
		defer func() {
			if createErr != nil {
				err := k8sClient.Delete(context.TODO(), clusterClaim)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ClusterClaim \"%s\", error: \n", err.Error())
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" deleted\n", multiclusterv1alpha1.WellKnownClusterClaimID)
				}
			}
		}()
	}

	clustersetClaim := &multiclusterv1alpha1.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      multiclusterv1alpha1.WellKnownClusterClaimClusterSet,
			Namespace: clusterClaimOpt.namespace,
		},
		Value: clusterClaimOpt.clusterSetID,
		Name:  multiclusterv1alpha1.WellKnownClusterClaimClusterSet,
	}

	createErr = k8sClient.Create(context.TODO(), clustersetClaim)
	if createErr != nil {
		if errors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" already exists\n", multiclusterv1alpha1.WellKnownClusterClaimClusterSet)
			createErr = nil
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ClusterClaim \"%s\", start rollback\n", multiclusterv1alpha1.WellKnownClusterClaimClusterSet)
			return createErr
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" with Value \"%s\" created\n", multiclusterv1alpha1.WellKnownClusterClaimClusterSet, clusterClaimOpt.clusterSetID)
	}

	return nil
}

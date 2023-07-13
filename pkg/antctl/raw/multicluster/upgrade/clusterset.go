// Copyright 2023 Antrea Authors
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

package upgrade

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	antctlOutput "antrea.io/antrea/pkg/antctl/output"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type upgradeOptions struct {
	namespace string
	k8sClient client.Client
}

var optionsUpgrade *upgradeOptions

var upgradeExamples = strings.Trim(`
Upgrade the ClusterSet CR in the kube-system Namesapce
$ antctl mc upgrade clusterset
Upgrade the ClusterSet CR in the specified Namespace
$ antctl mc upgrade clusterset -n <NAMESPACE>
`, "\n")

func (o *upgradeOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.namespace == "" {
		o.namespace = metav1.NamespaceSystem
	}
	if o.k8sClient == nil {
		kubeconfig, err := raw.ResolveKubeconfig(cmd)
		if err != nil {
			return err
		}
		o.k8sClient, err = client.New(kubeconfig, client.Options{Scheme: multiclusterscheme.Scheme})
		if err != nil {
			return err
		}
	}
	return nil
}

func NewUpgradeClusterSetCommand() *cobra.Command {
	cmdUpgrade := &cobra.Command{
		Use: "clusterset",
		Aliases: []string{
			"clusterset",
		},
		Short:   "Upgrade Multi-cluster ClusterSets",
		Args:    cobra.MaximumNArgs(1),
		Example: upgradeExamples,
		RunE:    runUpgrade,
	}
	o := &upgradeOptions{}
	optionsUpgrade = o
	cmdUpgrade.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ClusterSets")

	return cmdUpgrade
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	err := optionsUpgrade.validateAndComplete(cmd)
	if err != nil {
		return err
	}

	clusterSets := &mcv1alpha2.ClusterSetList{}
	ctx := context.Background()
	err = optionsUpgrade.k8sClient.List(ctx, clusterSets, &client.ListOptions{Namespace: optionsUpgrade.namespace})
	if err != nil {
		return err
	}
	clusterSetsSize := len(clusterSets.Items)
	if clusterSetsSize == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No ClusterSet found in Namespace %s, skip upgrading\n", optionsUpgrade.namespace)
		return nil
	}

	existingClusterSet := clusterSets.Items[0]

	// Do nothing if the existing ClusterSet already contains ClusterID.
	if existingClusterSet.Spec.ClusterID != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "The ClusterSet %s in Namespace %s is already a new version, skip upgrading\n", existingClusterSet.Name, existingClusterSet.Namespace)
		return nil
	}

	clusterClaims := &mcv1alpha2.ClusterClaimList{}
	err = optionsUpgrade.k8sClient.List(ctx, clusterClaims, &client.ListOptions{Namespace: optionsUpgrade.namespace})
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Error when getting ClusterClaims in Namespace %s, you can retry upgrade later\n", optionsUpgrade.namespace)
		return err
	}

	var clusterID, clusterSetID string
	if len(clusterClaims.Items) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No ClusterClaim found in Namespace %s, skip upgrading\n", optionsUpgrade.namespace)
		return nil
	}
	for _, cc := range clusterClaims.Items {
		if cc.Name == mcv1alpha2.WellKnownClusterClaimID {
			clusterID = cc.Value
		}
		if cc.Name == mcv1alpha2.WellKnownClusterClaimClusterSet {
			clusterSetID = cc.Value
		}
	}

	if clusterID == "" || clusterSetID == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterID or ClusterSet ID is missing in ClusterClaims in Namespace %s, skip upgrading\n", optionsUpgrade.namespace)
		return nil
	}

	if clusterID != "" && clusterSetID != "" {
		oldClusterSet := existingClusterSet
		existingClusterSet.Spec.ClusterID = clusterID
		// Always replace the existing ClusterSet with a new version of ClusterSet
		existingClusterSet.Name = clusterSetID
		existingClusterSet.ResourceVersion = ""
		err = optionsUpgrade.k8sClient.Delete(ctx, &oldClusterSet)
		if err != nil && !apierrors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Error when deleting the existing ClusterSet %s in Namespace %s, you can retry upgrade later\n", existingClusterSet.Name, existingClusterSet.Namespace)
			return err
		}
		err := optionsUpgrade.k8sClient.Create(ctx, &existingClusterSet)
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Error to upgrade ClusterSet %s in Namespace %s, you may recreate a new ClusterSet with the following yaml", existingClusterSet.Name, existingClusterSet.Namespace)
			_ = antctlOutput.YamlOutput(oldClusterSet, cmd.OutOrStdout())
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet upgraded successfully")
	}
	return nil
}

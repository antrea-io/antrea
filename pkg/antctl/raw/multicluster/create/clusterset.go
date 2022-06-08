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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type clusterSetOptions struct {
	leaderCluster          string
	leaderClusterServer    string
	leaderClusterNamespace string
	memberClusters         map[string]string
	namespace              string
	secret                 string
}

var clusterSetOpt *clusterSetOptions

var clusterSetExamples = strings.Trim(`
# Create a ClusterSet in a leader cluster
  $ antctl mc create clusterset <CLUSTERSET_ID> -n <NAMESPACE> --service-account <SERVICE_ACCOUNT> --leader-cluster <LEADER_CLUSTER_ID>
# Create a ClusterSet in a member cluster
  $ antctl mc create clusterset <CLUSTERSET_ID> -n <NAMESPACE> --leader-apiserver <LEADER_SERVER>  --secret <SECRET> --leader-cluster <LEADER_CLUSTER_ID>
`, "\n")

func (o *clusterSetOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}
	if o.leaderClusterNamespace == "" {
		o.leaderClusterNamespace = metav1.NamespaceDefault
	}
	if o.leaderCluster == "" {
		return fmt.Errorf("the leader-cluster-id cannot be empty")
	}
	if o.secret == "" && o.memberClusters == nil {
		return fmt.Errorf("the ServiceAccounts list is required in leader cluster, the secret is required in member cluster")
	}
	if o.secret != "" && o.leaderClusterServer == "" {
		return fmt.Errorf("the leader cluster apiserver is required in member cluster")
	}

	return nil
}

func NewClusterSetCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "clusterset",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Create a ClusterSet in a leader or member cluster",
		Long:    "Create a ClusterSet in a leader or member cluster",
		Example: clusterSetExamples,
		RunE:    clusterSetRunE,
	}

	o := &clusterSetOptions{}
	clusterSetOpt = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	command.Flags().StringVarP(&o.leaderCluster, "leader-cluster", "", "", "leader cluster ID of the ClusterSet")
	command.Flags().StringVarP(&o.leaderClusterServer, "leader-apiserver", "", "", "leader cluster apiserver address of the ClusterSet. It is required only for a member cluster")
	command.Flags().StringVarP(&o.leaderClusterNamespace, "leader-namespace", "", "", "the Namespace where Antrea Multi-cluster Controller is running in leader cluster")
	command.Flags().StringToStringVarP(&o.memberClusters, "member-clusters", "", nil, "a map from cluster ID to ServiceAccount of the member clusters(e.g. --member-clusters member1=sa1,member2=sa2). It is required only for a leader cluster")
	command.Flags().StringVarP(&o.secret, "secret", "", "", "Secret to access the leader cluster. It is required only when creating ClusterSet in a member cluster")

	return command
}

func clusterSetRunE(cmd *cobra.Command, args []string) error {
	if err := clusterSetOpt.validateAndComplete(); err != nil {
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
	clusterSetName := args[0]
	clusterSet := &multiclusterv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterSetName,
			Namespace: clusterSetOpt.namespace,
		},
		Spec: multiclusterv1alpha1.ClusterSetSpec{
			Leaders: []multiclusterv1alpha1.MemberCluster{
				{
					ClusterID: clusterSetOpt.leaderCluster,
					Secret:    clusterSetOpt.secret,
					Server:    fmt.Sprintf("https://%s", strings.Replace(clusterSetOpt.leaderClusterServer, "https://", "", 1)),
				},
			},
			Namespace: clusterSetOpt.leaderClusterNamespace,
		},
	}

	for memberCluster, serviceAccount := range clusterSetOpt.memberClusters {
		clusterSet.Spec.Members = append(clusterSet.Spec.Members, multiclusterv1alpha1.MemberCluster{
			ClusterID:      memberCluster,
			ServiceAccount: serviceAccount,
		})
	}

	if err := k8sClient.Create(context.TODO(), clusterSet); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" created\n", clusterSetName)

	return nil
}

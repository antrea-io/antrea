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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type clusterSetOptions struct {
	namespace string
}

var clusterSetOpt *clusterSetOptions

var clusterSetExamples = strings.Trim(`
# Delete a ClusterSet in a specified Namespace in a leader or member cluster
  $ antctl mc delete clusterset <CLUSTERSET_ID> -n <NAMESPACE>
`, "\n")

func (o *clusterSetOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}

	return nil
}

func NewClusterSetCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "clusterset",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Delete a ClusterSet in a leader or member cluster",
		Long:    "Delete a ClusterSet in a leader or member cluster",
		Example: clusterSetExamples,
		RunE:    clusterSetRunE,
	}

	o := &clusterSetOptions{}
	clusterSetOpt = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ClusterSet")

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
	}
	if err := k8sClient.Delete(context.TODO(), clusterSet); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" deleted\n", clusterSetName)
	return nil
}

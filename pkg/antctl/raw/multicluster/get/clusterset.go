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

package get

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
	"antrea.io/antrea/pkg/antctl/transform/clusterset"
)

type clusterSetOptions struct {
	namespace     string
	outputFormat  string
	allNamespaces bool
	k8sClient     client.Client
}

var optionsClusterSet *clusterSetOptions

var clusterSetExamples = strings.Trim(`
Gel all ClusterSets in the default Namesapce
$ antctl mc get clusterset
Get all ClusterSets in all Namespaces
$ antctl mc get clusterset -A
Get all ClusterSets in the specified Namespace
$ antctl mc get clusterset -n <NAMESPACE>
Get all ClusterSets and print them in JSON format
$ antctl mc get clusterset -o json
Get the specified ClusterSet
$ antctl mc get clusterset <CLUSTERSET_ID>
`, "\n")

func (o *clusterSetOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.allNamespaces {
		o.namespace = metav1.NamespaceAll
	} else if o.namespace == "" {
		o.namespace = metav1.NamespaceDefault
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

func NewClusterSetCommand() *cobra.Command {
	cmdClusterSet := &cobra.Command{
		Use: "clusterset",
		Aliases: []string{
			"clustersets",
		},
		Short:   "Print Multi-cluster ClusterSets",
		Args:    cobra.MaximumNArgs(1),
		Example: clusterSetExamples,
		RunE:    runEClusterSet,
	}
	o := &clusterSetOptions{}
	optionsClusterSet = o
	cmdClusterSet.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ClusterSets")
	cmdClusterSet.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
	cmdClusterSet.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "If present, list ClusterSets across all Namespaces")

	return cmdClusterSet
}

func runEClusterSet(cmd *cobra.Command, args []string) error {
	err := optionsClusterSet.validateAndComplete(cmd)
	if err != nil {
		return err
	}
	var clusterSets []mcv1alpha2.ClusterSet
	if len(args) > 0 {
		clusterSetName := args[0]
		clusterSet := mcv1alpha2.ClusterSet{}
		err = optionsClusterSet.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: optionsClusterSet.namespace,
			Name:      clusterSetName,
		}, &clusterSet)
		if err != nil {
			return err
		}
		gvks, unversioned, err := optionsClusterSet.k8sClient.Scheme().ObjectKinds(&clusterSet)
		if err != nil {
			return err
		}
		if !unversioned && len(gvks) == 1 {
			clusterSet.SetGroupVersionKind(gvks[0])
		}
		clusterSets = append(clusterSets, clusterSet)
	} else {
		clusterSetList := &mcv1alpha2.ClusterSetList{}
		err = optionsClusterSet.k8sClient.List(context.TODO(), clusterSetList, &client.ListOptions{Namespace: optionsClusterSet.namespace})
		if err != nil {
			return err
		}
		clusterSets = clusterSetList.Items
	}

	if len(clusterSets) == 0 {
		if optionsClusterSet.namespace != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "No ClusterSet found in Namespace %s\n", optionsClusterSet.namespace)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No ClusterSet found")
		}
		return nil
	}

	err = output(clusterSets, false, optionsClusterSet.outputFormat, cmd.OutOrStdout(), clusterset.Transform)
	if err != nil {
		return err
	}
	return nil
}

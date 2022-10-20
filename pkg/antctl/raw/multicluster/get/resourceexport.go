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

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
	"antrea.io/antrea/pkg/antctl/transform/resourceexport"
)

type resourceExportOptions struct {
	namespace     string
	outputFormat  string
	allNamespaces bool
	clusterID     string
	k8sClient     client.Client
}

var optionsResourceExport *resourceExportOptions

var resourceExportExamples = strings.Trim(`
Get all ResourceExports of ClusterSet in default Namesapce
$ antctl mc get resourceexport
Get all ResourceExports of ClusterSet in all Namespaces
$ antctl mc get resourceexport -A
Get all ResourceExports in the specified Namespace
$ antctl mc get resourceexport -n <NAMESPACE>
Get all ResourceExports and print them in JSON format
$ antctl mc get resourceexport -o json
Get the specified ResourceExport
$ antctl mc get resourceexport <RESOURCEEXPORT> -n <NAMESPACE>
`, "\n")

func (o *resourceExportOptions) validateAndComplete(cmd *cobra.Command) error {
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

func NewResourceExportCommand() *cobra.Command {
	cmdResourceExport := &cobra.Command{
		Use: "resourceexport",
		Aliases: []string{
			"resourceexports",
			"re",
		},
		Short:   "Print Multi-cluster ResourceExports",
		Args:    cobra.MaximumNArgs(1),
		Example: resourceExportExamples,
		RunE:    runEResourceExport,
	}
	o := &resourceExportOptions{}
	optionsResourceExport = o
	cmdResourceExport.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ResourceExport")
	cmdResourceExport.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
	cmdResourceExport.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "If present, list ResourceExport across all namespaces")
	cmdResourceExport.Flags().StringVarP(&o.clusterID, "cluster-id", "", "", "List of the ResourceExport of specific clusterID")

	return cmdResourceExport
}

func runEResourceExport(cmd *cobra.Command, args []string) error {
	err := optionsResourceExport.validateAndComplete(cmd)
	if err != nil {
		return err
	}

	var resExports interface{}
	singleResource := false
	if len(args) > 0 {
		singleResource = true
	}

	if optionsResourceExport.allNamespaces && singleResource {
		return fmt.Errorf("a resource cannot be retrieved by name across all Namespaces")
	}

	if singleResource {
		resourceExportName := args[0]
		resourceExport := multiclusterv1alpha1.ResourceExport{}
		err = optionsResourceExport.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: optionsResourceExport.namespace,
			Name:      resourceExportName,
		}, &resourceExport)
		if err != nil {
			return err
		}
		gvks, unversioned, err := optionsResourceExport.k8sClient.Scheme().ObjectKinds(&resourceExport)
		if err != nil {
			return err
		}
		if !unversioned && len(gvks) == 1 {
			resourceExport.SetGroupVersionKind(gvks[0])
		}
		resExports = resourceExport
	} else {
		var labels map[string]string
		if optionsResourceExport.clusterID != "" {
			labels = map[string]string{"sourceClusterID": optionsResourceExport.clusterID}
		}
		selector := metav1.LabelSelector{MatchLabels: labels}
		labelSelector, _ := metav1.LabelSelectorAsSelector(&selector)
		resourceExportList := &multiclusterv1alpha1.ResourceExportList{}
		err = optionsResourceExport.k8sClient.List(context.TODO(), resourceExportList, &client.ListOptions{
			Namespace:     optionsResourceExport.namespace,
			LabelSelector: labelSelector,
		})
		if err != nil {
			return err
		}
		if len(resourceExportList.Items) == 0 {
			if optionsResourceExport.namespace != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "No ResourceExport found in Namespace %s\n", optionsResourceExport.namespace)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "No ResourceExport found")
			}
			return nil
		}
		resExports = resourceExportList.Items
	}

	return output(resExports, singleResource, optionsResourceExport.outputFormat, cmd.OutOrStdout(), resourceexport.Transform)
}

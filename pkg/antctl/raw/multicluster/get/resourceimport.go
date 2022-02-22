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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
	"antrea.io/antrea/pkg/antctl/transform/resourceimport"
)

type resourceImportOptions struct {
	namespace     string
	outputFormat  string
	allNamespaces bool
}

var options *resourceImportOptions

var resourceImportExamples = strings.Trim(`
Gel all ResourceImports of a ClusterSet in default Namespace
$ antctl mc get resourceimport
Get all ResourceImports of a ClusterSet in all Namespaces
$ antctl mc get resourceimport -A
Get all ResourceImports in the specified Namespace
$ antctl mc get resourceimport -n <NAMESPACE>
Get all ResourceImports and print them in JSON format
$ antctl mc get resourceimport -o json
Get the specified ResourceImport
$ antctl mc get resourceimport <RESOURCEIMPORT> -n <NAMESPACE>
`, "\n")

func (o *resourceImportOptions) validateAndComplete() {
	if o.allNamespaces {
		o.namespace = metav1.NamespaceAll
		return
	}
	if o.namespace == "" {
		o.namespace = metav1.NamespaceDefault
		return
	}
}

func NewResourceImportCommand() *cobra.Command {
	command := &cobra.Command{
		Use: "resourceimport",
		Aliases: []string{
			"resourceimports",
			"ri",
		},
		Short:   "Print Multi-Cluster ResourceImports",
		Args:    cobra.MaximumNArgs(1),
		Example: resourceImportExamples,
		RunE:    runE,
	}
	o := &resourceImportOptions{}
	options = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of ResourceImports")
	command.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
	command.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "If present, list ResourceImports across all Namespaces")

	return command
}

func runE(cmd *cobra.Command, args []string) error {
	options.validateAndComplete()
	argsNum := len(args)
	if options.allNamespaces && argsNum > 0 {
		return fmt.Errorf("a resource cannot be retrieved by name across all Namespaces")
	}

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	kubeconfig.GroupVersion = &schema.GroupVersion{Group: "", Version: ""}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)

	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		return err
	}

	singleResource := false
	if argsNum > 0 {
		singleResource = true
	}
	var res interface{}

	if singleResource {
		resourceImportName := args[0]
		resourceImport := multiclusterv1alpha1.ResourceImport{}
		err = k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: options.namespace,
			Name:      resourceImportName,
		}, &resourceImport)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("ResourceImport %s not found in Namespace %s", resourceImportName, options.namespace)
			}

			return err
		}

		gvks, unversioned, err := k8sClient.Scheme().ObjectKinds(&resourceImport)
		if err != nil {
			return err
		}
		if !unversioned && len(gvks) == 1 {
			resourceImport.SetGroupVersionKind(gvks[0])
		}
		res = resourceImport
	} else {
		resourceImportList := &multiclusterv1alpha1.ResourceImportList{}
		err = k8sClient.List(context.TODO(), resourceImportList, &client.ListOptions{Namespace: options.namespace})
		if err != nil {
			return err
		}

		if len(resourceImportList.Items) == 0 {
			if options.namespace != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "No resources found in Namespace %s\n", options.namespace)
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "No resources found in all Namespaces")
			}
			return nil
		}
		res = resourceImportList.Items
	}

	return output(res, singleResource, options.outputFormat, resourceimport.Transform)
}

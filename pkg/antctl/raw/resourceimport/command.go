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

package resourceimport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	mcsscheme "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/scheme"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw"
)

var Command *cobra.Command

type resourceImportOptions struct {
	namespace    string
	outputFormat string
}

var options *resourceImportOptions

var resourceImportExample = strings.Trim(`
	Get all Resource Imports of cluster set
	$ antctl get resourceimport
	Get all Resource Imports of specified namespace
	$ antctl get resourceimport -n <NAMESPACE>
	Get Resource Import using specified kubeConfig
	$ antctl get resourceimport --kubeconfig <KUBECONFIG>
	Get all Resource Imports and print json format
	$ antctl get resourceimport -o json
`, "\n")

func (o *resourceImportOptions) validateAndComplete() error {
	if o.namespace == "" {
		o.namespace = metav1.NamespaceAll
	}

	return nil
}

func init() {
	Command = &cobra.Command{
		Use:   "ResourceImport",
		Short: "Get multi-cluster ResourceImport",
		Aliases: []string{
			"ResourceImports",
		},
		Example: resourceImportExample,
		Args:    cobra.MaximumNArgs(1),
		RunE:    runE,
	}

	o := &resourceImportOptions{}
	options = o
	Command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "namespace of ResourceImport")
	Command.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
}

func runE(cmd *cobra.Command, _ []string) error {
	options.validateAndComplete()
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	var resourceImports []multiclusterv1alpha1.ResourceImport

	kubeconfig.GroupVersion = &schema.GroupVersion{Group: "", Version: ""}

	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)
	scheme := runtime.NewScheme()
	err = mcsscheme.AddToScheme(scheme)
	if err != nil {
		return err
	}

	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	res := &multiclusterv1alpha1.ResourceImportList{}
	err = k8sClient.List(context.TODO(), res, &client.ListOptions{Namespace: options.namespace})
	if err != nil {
		return err
	}

	resourceImports = append(resourceImports, res.Items...)

	switch options.outputFormat {
	case "json":
		bytesJson, err := json.Marshal(resourceImports)
		if err != nil {
			return err
		}
		var prettyJson bytes.Buffer
		err = json.Indent(&prettyJson, bytesJson, "", " ")
		if err != nil {
			return err
		}
		fmt.Println(prettyJson.String())
	case "yaml":
		yamlOutput, err := yaml.Marshal(resourceImports)
		if err != nil {
			return err
		}
		fmt.Println(string(yamlOutput))
	default:
		fmt.Println(output(resourceImports))
	}

	return nil
}

func output(resourceImport []multiclusterv1alpha1.ResourceImport) string {
	var output strings.Builder
	formatter := "%-50s%-50s%-50s\n"
	output.Write([]byte(fmt.Sprintf(formatter, "NAMESPACE", "NAME", "KIND")))
	for _, ri := range resourceImport {
		fmt.Fprintf(&output, formatter, ri.Namespace, ri.Name, ri.Spec.Kind)
	}
	return output.String()
}

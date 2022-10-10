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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/transform/membertoken"
)

type cmdOptions struct {
	namespace    string
	outputFile   string
	outputFormat string
	k8sClient    client.Client
}

var tokenOptions *cmdOptions

var cmdExamples = strings.Trim(`
Get all token Secrets in the antrea-multicluster Namespace
$ antctl mc get membertoken -n antrea-multicluster
Get the specified token Secret and print it in YAML format
$ antctl mc get membertoken -n antrea-multicluster -o yaml
Get the default token Secret in the antrea-multicluster Namespace
$ antctl mc get membertoken default-member-token -n antrea-multicluster
Get the specified token Secret and output the token Secret manifest to a file
$ antctl mc get membertoken cluster-east-token -n antrea-multicluster --output-file token-secret.yml
`, "\n")

func (o *cmdOptions) validateAndComplete(cmd *cobra.Command, tokenName string) error {
	if o.namespace == "" {
		return fmt.Errorf("Namespace is required")
	}
	if tokenName == "" && o.outputFile != "" {
		return fmt.Errorf("token name must be specified to save the token Secret manifest to an output-file")
	}

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	o.k8sClient, err = client.New(kubeconfig, client.Options{})
	return err
}

func NewMemberTokenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "membertoken",
		Aliases: []string{
			"membertokens",
		},
		Short:   "Print Multi-cluster member tokens in a leader cluster",
		Args:    cobra.MaximumNArgs(1),
		Example: cmdExamples,
		RunE:    runEMemberToken,
	}
	o := &cmdOptions{}
	tokenOptions = o
	cmd.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	cmd.Flags().StringVarP(&o.outputFile, "output-file", "", "", "Save the token Secret manifest to the specified file")
	cmd.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")

	return cmd
}

func runEMemberToken(cmd *cobra.Command, args []string) error {
	tokenName := ""
	if len(args) > 0 {
		tokenName = args[0]
	}

	err := tokenOptions.validateAndComplete(cmd, tokenName)
	if err != nil {
		return err
	}
	var results []corev1.Secret
	if tokenName != "" {
		var secret corev1.Secret
		err = tokenOptions.k8sClient.Get(context.TODO(),
			types.NamespacedName{Namespace: tokenOptions.namespace, Name: tokenName},
			&secret)
		if err != nil {
			return err
		}
		results = append(results, secret)
		// TODO: save the token Secret manifest to the output file if specified.
	} else {
		secretList := &corev1.SecretList{}
		// TODO: filter Secrets without the "created-by-antctl" annotation.
		err = tokenOptions.k8sClient.List(context.TODO(), secretList,
			&client.ListOptions{Namespace: tokenOptions.namespace})
		if err != nil {
			return err
		}
		results = secretList.Items
	}

	if len(results) == 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "No resource found in Namespace %s\n", tokenOptions.namespace)
		return nil
	}

	err = output(results, false, tokenOptions.outputFormat, cmd.OutOrStdout(), membertoken.Transform)
	if err != nil {
		return err
	}
	return nil
}

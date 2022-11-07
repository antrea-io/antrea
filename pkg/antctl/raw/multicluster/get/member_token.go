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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
	"antrea.io/antrea/pkg/antctl/transform/membertoken"
)

type tokenOptions struct {
	namespace     string
	outputFormat  string
	allNamespaces bool
	k8sClient     client.Client
}

var optionsToken *tokenOptions

var tokenExamples = strings.Trim(`
# Get all member tokens in the specified Namespace
  $ antctl mc get membertoken -n antrea-multicluster
# Get all member tokens in all Namespaces
  $ antctl mc get membertoken -A
# Get the specified member token
  $ antctl mc get membertoken cluster-east-token -n antrea-multicluster
# Get the default member token and print the token Secret in YAML format
  $ antctl mc get membertoken default-member-token -n antrea-multicluster -o yaml
# Save the token Secret manifest to a file (which can be used with "antctl mc join" command)
  $ antctl mc get membertoken cluster-east-token -n antrea-multicluster -o yaml > token.yml
`, "\n")

func (o *tokenOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.namespace == "" && !o.allNamespaces {
		return fmt.Errorf("Namespace must be specified")
	}
	if o.allNamespaces {
		o.namespace = metav1.NamespaceAll
	}

	var err error
	if o.k8sClient == nil {
		o.k8sClient, err = common.NewClient(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewMemberTokenCommand() *cobra.Command {
	cmdToken := &cobra.Command{
		Use: "membertoken",
		Aliases: []string{
			"membertokens",
		},
		Short:   "Print member tokens in a leader cluster",
		Args:    cobra.MaximumNArgs(1),
		Example: tokenExamples,
		RunE:    runEToken,
	}
	o := &tokenOptions{}
	optionsToken = o
	cmdToken.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the token")
	cmdToken.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
	cmdToken.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "Get tokens across all Namespaces")
	return cmdToken
}

func runEToken(cmd *cobra.Command, args []string) error {
	err := optionsToken.validateAndComplete(cmd)
	if err != nil {
		return err
	}

	if len(args) > 0 {
		memberTokenName := args[0]
		memberToken := corev1.Secret{}
		err = optionsToken.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: optionsToken.namespace,
			Name:      memberTokenName,
		}, &memberToken)
		if err != nil {
			return err
		}

		outToken := &memberToken
		if optionsToken.outputFormat != "" {
			outToken = common.ConvertMemberTokenSecret(outToken)
		}
		return output(*outToken, true, optionsToken.outputFormat, cmd.OutOrStdout(), membertoken.Transform)
	}

	memberTokenList := &corev1.SecretList{}
	err = optionsToken.k8sClient.List(context.TODO(), memberTokenList, &client.ListOptions{Namespace: optionsToken.namespace})
	if err != nil {
		return err
	}
	opaqueMemberTokens := []corev1.Secret{}
	for _, memberToken := range memberTokenList.Items {
		// Ignore tokens not created by antctl mc command.
		if memberToken.Annotations[common.CreateByAntctlAnnotation] == "true" {
			t := memberToken
			outToken := &t
			if optionsToken.outputFormat != "" {
				outToken = common.ConvertMemberTokenSecret(outToken)
				if optionsToken.namespace == "" {
					// ConvertMemberTokenSecret() does not set Namespace of the Secret.
					outToken.Namespace = memberToken.Namespace
				}
			}
			opaqueMemberTokens = append(opaqueMemberTokens, *outToken)
		}
	}

	if len(opaqueMemberTokens) == 0 {
		if optionsToken.namespace != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "No token found in Namespace %s\n", optionsToken.namespace)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No token found")
		}
		return nil
	}
	return output(opaqueMemberTokens, false, optionsToken.outputFormat, cmd.OutOrStdout(), membertoken.Transform)
}

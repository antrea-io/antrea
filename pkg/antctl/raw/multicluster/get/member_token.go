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
# Get the specified member token and print the token Secret in YAML format
  $ antctl mc get membertoken cluster-east-token -n antrea-multicluster -o yaml
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

	var memberTokens []corev1.Secret
	singleToken := false

	if len(args) > 0 {
		singleToken = true
		memberTokenName := args[0]
		memberToken := corev1.Secret{}
		err = optionsToken.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: optionsToken.namespace,
			Name:      memberTokenName,
		}, &memberToken)
		if err != nil {
			return err
		}

		memberTokens = append(memberTokens, memberToken)
	} else {
		memberTokenList := &corev1.SecretList{}
		err = optionsToken.k8sClient.List(context.TODO(), memberTokenList, &client.ListOptions{Namespace: optionsToken.namespace})
		if err != nil {
			return err
		}
		memberTokens = memberTokenList.Items
	}

	opaqueMemberTokens := []corev1.Secret{}
	for _, memberToken := range memberTokens {
		if memberToken.Annotations[common.CreateByAntctlAnnotation] == "true" {
			opaqueToken := common.ConvertMemberTokenSecret(memberToken)
			opaqueMemberTokens = append(opaqueMemberTokens, opaqueToken)
		}
	}

	if len(opaqueMemberTokens) == 0 {
		if singleToken {
			return fmt.Errorf("Member token %s created by antctl is not found", args[0])
		}
		if optionsToken.namespace != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "No token found in Namespace %s\n", optionsToken.namespace)
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "No token found")
		}
		return nil
	}

	if singleToken {
		opaqueMemberToken := opaqueMemberTokens[0]
		err = output(opaqueMemberToken, singleToken, optionsToken.outputFormat, cmd.OutOrStdout(), membertoken.Transform)
	} else {
		err = output(opaqueMemberTokens, singleToken, optionsToken.outputFormat, cmd.OutOrStdout(), membertoken.Transform)
	}
	return err
}

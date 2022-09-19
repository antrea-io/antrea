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

	corev1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
	"antrea.io/antrea/pkg/antctl/transform/token"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var cmdToken *cobra.Command

type tokenOptions struct {
	namespace     string
	outputFormat  string
	allNamespaces bool
	clusterID     string
}

var optionsToken *tokenOptions

var tokenExamples = strings.Trim(`
Get all Tokens of ClusterSet in default Namesapce
$ antctl mc get token
Get all Tokens of ClusterSet in all Namespaces
$ antctl mc get token -A
Get all Tokens in the specified Namespace
$ antctl mc get token -n <NAMESPACE>
Get all Tokens and print them in JSON format
$ antctl mc get token -o json
Get the specified Token
$ antctl mc get Token <TOKEN> -n <NAMESPACE>
`, "\n")

func (o *tokenOptions) validateAndComplete() {
	if o.allNamespaces {
		o.namespace = metav1.NamespaceAll
		return
	}
	if o.namespace == "" {
		o.namespace = metav1.NamespaceDefault
		return
	}
}

func NewTokenCommand() *cobra.Command {
	cmdToken = &cobra.Command{
		Use: "token",
		Aliases: []string{
			"tokens",
		},
		Short:   "Print Multi-cluster Tokens",
		Args:    cobra.MaximumNArgs(1),
		Example: tokenExamples,
		RunE:    runEToken,
	}
	o := &tokenOptions{}
	optionsToken = o
	cmdToken.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of Token")
	cmdToken.Flags().StringVarP(&o.outputFormat, "output", "o", "", "Output format. Supported formats: json|yaml")
	cmdToken.Flags().BoolVarP(&o.allNamespaces, "all-namespaces", "A", false, "If present, list Tokens across all namespaces")
	cmdToken.Flags().StringVarP(&o.clusterID, "cluster-id", "", "", "List of the Token of specific clusterID")

	return cmdToken
}

func runEToken(cmd *cobra.Command, args []string) error {
	optionsToken.validateAndComplete()

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}

	argsNum := len(args)
	singleToken := false
	if argsNum > 0 {
		singleToken = true
	}
	var tokens []corev1.Secret

	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: multiclusterscheme.Scheme})
	if err != nil {
		return err
	}

	if singleToken {
		tokenName := args[0]
		token := &corev1.Secret{}
		err = k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: optionsToken.namespace,
			Name:      tokenName,
		}, token)
		if err != nil {
			return err
		}
		gvks, unversioned, err := k8sClient.Scheme().ObjectKinds(token)
		if err != nil {
			return err
		}
		if !unversioned && len(gvks) == 1 {
			token.SetGroupVersionKind(gvks[0])
		}
		tokens = append(tokens, *token)

	} else {

		secretList := &corev1.SecretList{}
		err = k8sClient.List(context.TODO(), secretList, &client.ListOptions{
			Namespace: optionsToken.namespace,
		})
		if err != nil {
			return err
		}
		tokens = secretList.Items
	}

	if len(tokens) == 0 {
		if optionsToken.namespace != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "No tokens found in Namespace %s\n", optionsToken.namespace)
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "No rtokens found")
		}
		return nil
	}

	return output(tokens, false, optionsToken.outputFormat, token.Transform)

}

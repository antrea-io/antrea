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
	"os"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

type memberTokenOptions struct {
	namespace string
	output    string
	k8sClient client.Client
}

var memberTokenOpts *memberTokenOptions

var memberTokenExamples = strings.Trim(`
# Create a member token in the antrea-multicluster Namespace
  $ antctl mc create membertoken cluster-east-token -n antrea-multicluster
# Create a member token and save the Secret manifest to a file
  $ antctl mc create membertoken cluster-east-token -n antrea-multicluster -o token-secret.yml
`, "\n")

func (o *memberTokenOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.namespace == "" {
		return fmt.Errorf("Namespace must be specified")
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

func NewMemberTokenCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "membertoken",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Create a member token in a leader cluster",
		Long:    "Create a member token in a leader cluster, which will be saved in a Secret. A ServiceAccount and a RoleBinding will be created too.",
		Example: memberTokenExamples,
		RunE:    memberTokenRunE,
	}

	o := &memberTokenOptions{}
	memberTokenOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	command.Flags().StringVarP(&o.output, "output-file", "o", "", "Output file to save the token Secret manifest")

	return command
}

func memberTokenRunE(cmd *cobra.Command, args []string) error {
	if err := memberTokenOpts.validateAndComplete(cmd); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("token name must be specified")
	}

	var createErr error
	createdRes := []map[string]interface{}{}
	defer func() {
		if createErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create the member token. Deleting the created resources\n")
			common.Rollback(cmd, memberTokenOpts.k8sClient, createdRes)
		}
	}()

	if createErr = common.CreateMemberToken(cmd, memberTokenOpts.k8sClient, args[0], memberTokenOpts.namespace, &createdRes); createErr != nil {
		return createErr
	}

	fmt.Fprintf(cmd.OutOrStdout(), "You can now run \"antctl mc join\" command with the token in a member cluster to join the ClusterSet\n")
	if memberTokenOpts.output == "" {
		return nil
	}

	file, err := os.OpenFile(memberTokenOpts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	tokenSecret := &corev1.Secret{}
	if err = memberTokenOpts.k8sClient.Get(context.TODO(), types.NamespacedName{
		Namespace: memberTokenOpts.namespace,
		Name:      args[0],
	}, tokenSecret); err != nil {
		return err
	}
	return common.OutputMemberTokenSecret(tokenSecret, file)
}

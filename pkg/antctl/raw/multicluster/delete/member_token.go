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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

type deleteTokenOptions struct {
	namespace string
	k8sClient client.Client
}

var deleteTokenOpts *deleteTokenOptions

var deleteTokenExamples = strings.Trim(`
# Delete a member token in the antrea-multicluster Namespace
  $ antctl mc delete membertoken cluster-east-token -n antrea-multicluster
`, "\n")

func (o *deleteTokenOptions) validateAndComplete(cmd *cobra.Command) error {
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
		Short:   "Delete a member token in a leader cluster Namespace",
		Long:    "Delete a member token in a leader cluster Namespace. Corresponding Secret, ServiceAccount and RoleBinding will be deleted if they exist.",
		Example: deleteTokenExamples,
		RunE:    deleteTokenRunE,
	}

	o := &deleteTokenOptions{}
	deleteTokenOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the token")

	return command
}

func deleteTokenRunE(cmd *cobra.Command, args []string) error {
	if err := deleteTokenOpts.validateAndComplete(cmd); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("token name must be specified")
	}

	if err := common.DeleteMemberToken(cmd, deleteTokenOpts.k8sClient, args[0], deleteTokenOpts.namespace); err != nil {
		return err
	}

	return nil
}

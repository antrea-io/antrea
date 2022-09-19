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

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
	"github.com/spf13/cobra"
)

type deleteTokenOptions struct {
	namespace string
	file      string
}

var deleteTokenOpts *deleteTokenOptions

var deleteTokenExamples = strings.Trim(`
# Delete a member token.
  $ antctl mc delete membertoken cluster-east-token -n antrea-multicluster
`, "\n")

func (o *deleteTokenOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace is required")
	}
	return nil
}

func DeleteTokenCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "deletetoken",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Delete a member token in a leader cluster",
		Long:    "Delete a member token in a leader cluster",
		Example: deleteTokenExamples,
		RunE:    deleteTokenRunE,
	}

	o := &deleteTokenOptions{}
	deleteTokenOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the Token")
	command.Flags().StringVarP(&o.file, "configfile", "f", "", "File the token Secret saved in")
	return command
}

func deleteTokenRunE(cmd *cobra.Command, args []string) error {
	if err := deleteTokenOpts.validateAndComplete(); err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("exactly one NAME is required, got %d", len(args))
	}
	k8sClient, err := common.NewClient(cmd)
	if err != nil {
		return err
	}

	if deleteErr := common.DeleteMemberToken(cmd, k8sClient, args[0], deleteTokenOpts.namespace); deleteErr != nil {
		return deleteErr
	}

	return nil
}

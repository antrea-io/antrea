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

type memberTokenOptions struct {
	namespace string
	k8sClient client.Client
}

var memberTokenOpts *memberTokenOptions

var memberTokenExamples = strings.Trim(`
# Delete a member token in the antrea-multicluster Namespace
  $ antctl mc delete membertoken cluster-east-token -n antrea-multicluster
`, "\n")

func (o *memberTokenOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.namespace == "" {
		return fmt.Errorf("Namespace is required")
	}
	var err error
	o.k8sClient, err = common.NewClient(cmd)
	return err
}

func NewMemberTokenCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "membertoken",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Delete a member token in a leader cluster",
		Long:    "Delete a member token in a leader cluster. It deletes the Secret, ServiceAccount and RoleBinding for the token if they exist.",
		Example: memberTokenExamples,
		RunE:    memberTokenRunE,
	}

	o := &memberTokenOptions{}
	memberTokenOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")

	return command
}

func memberTokenRunE(cmd *cobra.Command, args []string) error {
	if err := memberTokenOpts.validateAndComplete(cmd); err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("token name must be specified")
	}
	if len(args) > 1 {
		return fmt.Errorf("only one argument is accepeted")
	}
	return common.DeleteMemberToken(cmd, memberTokenOpts.k8sClient, args[0], memberTokenOpts.namespace)
}

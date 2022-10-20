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

package multicluster

import (
	"strings"

	"github.com/spf13/cobra"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

var leaveOpts *common.CleanOptions

var leaveExamples = strings.Trim(`
# Leave the ClusterSet in the kube-system Namespace
  antctl mc leave --clusterset clusterset1 -n kube-system
`, "\n")

func NewLeaveCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "leave",
		Short:   "Leave the ClusterSet from a member cluster",
		Args:    cobra.MaximumNArgs(0),
		Example: leaveExamples,
		RunE:    leaveRunE,
	}

	o := common.CleanOptions{}
	leaveOpts = &o
	command.Flags().StringVarP(&o.Namespace, "namespace", "n", common.DefaultMemberNamespace, "Antrea Multi-cluster Namespace. Defaults to "+common.DefaultMemberNamespace)
	command.Flags().StringVarP(&o.ClusterSet, "clusterset", "", "", "ClusterSet ID")

	return command
}

func leaveRunE(cmd *cobra.Command, args []string) error {
	return common.Cleanup(cmd, leaveOpts)
}

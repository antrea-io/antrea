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

var destroyOpts *common.CleanOptions

var destroyExamples = strings.Trim(`
# Destroy the ClusterSet in the antrea-multicluster Namespace
  antctl mc destroy --clusterset clusterset1 -n antrea-multicluster
`, "\n")

func NewDestroyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "destroy",
		Short:   "Destroy the ClusterSet in the given Namespace of the leader cluster",
		Args:    cobra.MaximumNArgs(0),
		Example: destroyExamples,
		RunE:    destroyRunE,
	}

	o := common.CleanOptions{}
	destroyOpts = &o
	command.Flags().StringVarP(&o.Namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	command.Flags().StringVarP(&o.ClusterSet, "clusterset", "", "", "ClusterSet ID")

	return command
}

func destroyRunE(cmd *cobra.Command, args []string) error {
	return common.Cleanup(cmd, destroyOpts)
}

// Copyright 2023 Antrea Authors
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

package clean

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

type memberClusterOptions struct {
	namespace     string
	antreaVersion string
	filename      string
}

var memberClusterOpts *memberClusterOptions

var memberClusterExamples = strings.Trim(`
# Clean up Antrea Multi-cluster of the specified version in a given Namespace
  $ antctl mc clean membercluster --antrea-version <ANTREA_VERSION> -n <NAMESPACE>
# Clean Antrea Multi-cluster using a pre-downloaded manifest
  $ antctl mc clean membercluster -f <PATH_TO_MANIFEST>
`, "\n")

func (o *memberClusterOptions) validateAndComplete() error {
	if o.filename != "" {
		if _, err := os.Stat(o.filename); err != nil {
			return err
		}
	}
	if o.namespace == "" {
		return fmt.Errorf("Namespace must be specified")
	}
	if o.antreaVersion == "" {
		o.antreaVersion = "latest"
	}

	return nil
}

func NewMemberClusterCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "membercluster",
		Args:    cobra.MaximumNArgs(0),
		Short:   "Clean up Antrea Multi-cluster on a member cluster",
		Long:    "Clean up Antrea Multi-cluster on a member cluster in a Namespace",
		Example: memberClusterExamples,
		RunE:    memberClusterRunE,
	}
	o := &memberClusterOptions{}
	memberClusterOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace to deploy Antrea Multi-cluster")
	command.Flags().StringVarP(&o.antreaVersion, "antrea-version", "", "",
		"version of Antrea Multi-cluster to remove. If not specified, the latest version from Antrea main branch will be used. "+
			"When manifest-file is not provided, the Antrea Multi-cluster deployment manifest of the specified version will be downloaded and applied; "+
			"when manifest-file is provided, this option will be ignored")
	command.Flags().StringVarP(&o.filename, "manifest-file", "f", "", "path to the Antrea Multi-cluster deployment manifest file for member cluster")

	return command
}

func memberClusterRunE(cmd *cobra.Command, _ []string) error {
	if err := memberClusterOpts.validateAndComplete(); err != nil {
		return err
	}

	return common.DeployOrRemove(cmd, common.MemberRole, memberClusterOpts.antreaVersion, memberClusterOpts.namespace, memberClusterOpts.filename, "remove")
}

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
	"github.com/spf13/cobra"

	"antrea.io/antrea/pkg/antctl/raw/multicluster/add"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/create"
	deleteCmd "antrea.io/antrea/pkg/antctl/raw/multicluster/delete"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/deploy"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/get"
)

var GetCmd = &cobra.Command{
	Use:   "get",
	Short: "Display one or many resources in a ClusterSet",
}

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create multi-cluster resources",
}

var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new member cluster to a ClusterSet",
}

var DeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete multi-cluster resources",
}

var DeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy Antrea Multi-cluster Controller to a leader or member cluster",
}

func init() {
	GetCmd.AddCommand(get.NewClusterSetCommand())
	GetCmd.AddCommand(get.NewResourceImportCommand())
	GetCmd.AddCommand(get.NewResourceExportCommand())
	CreateCmd.AddCommand(create.NewClusterClaimCmd())
	CreateCmd.AddCommand(create.NewAccessTokenCmd())
	CreateCmd.AddCommand(create.NewClusterSetCmd())
	DeleteCmd.AddCommand(deleteCmd.NewMemberClusterCmd())
	DeleteCmd.AddCommand(deleteCmd.NewClusterSetCmd())
	DeleteCmd.AddCommand(deleteCmd.NewClusterClaimCmd())
	AddCmd.AddCommand(add.NewMemberClusterCmd())
	DeployCmd.AddCommand(deploy.NewLeaderClusterCmd())
	DeployCmd.AddCommand(deploy.NewMemberClusterCmd())
}

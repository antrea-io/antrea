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

// Common codes for both leader and member cluster to clean up the Antrea
// Multi-cluster resources in the given Namespace.

package common

import (
	"fmt"

	"github.com/spf13/cobra"
)

type CleanOptions struct {
	Namespace  string
	ClusterSet string
}

func (o *CleanOptions) validate() error {
	if o.ClusterSet == "" {
		return fmt.Errorf("ClusterSet is required")
	}

	return nil
}

func Cleanup(cmd *cobra.Command, cleanOpts *CleanOptions) error {
	if err := cleanOpts.validate(); err != nil {
		return err
	}
	k8sClient, err := NewClient(cmd)
	if err != nil {
		return err
	}
	deleteClusterSet(cmd, k8sClient, cleanOpts.Namespace, cleanOpts.ClusterSet)
	deleteClusterClaims(cmd, k8sClient, cleanOpts.Namespace)
	deleteSecrets(cmd, k8sClient, cleanOpts.Namespace)
	deleteServiceAccounts(cmd, k8sClient, cleanOpts.Namespace)
	deleteRoleBindings(cmd, k8sClient, cleanOpts.Namespace)

	return nil
}

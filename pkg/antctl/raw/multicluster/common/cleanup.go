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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CleanOptions struct {
	Namespace  string
	ClusterSet string
	K8sClient  client.Client
}

func (o *CleanOptions) validate(cmd *cobra.Command) error {
	if o.ClusterSet == "" {
		return fmt.Errorf("ClusterSet must be provided")
	}

	if o.Namespace == "" {
		return fmt.Errorf("Namespace must be specified")
	}

	var err error
	if o.K8sClient == nil {
		o.K8sClient, err = NewClient(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func Cleanup(cmd *cobra.Command, cleanOpts *CleanOptions) error {
	if err := cleanOpts.validate(cmd); err != nil {
		return err
	}

	deleteClusterSet(cmd, cleanOpts.K8sClient, cleanOpts.Namespace, cleanOpts.ClusterSet)
	deleteSecrets(cmd, cleanOpts.K8sClient, cleanOpts.Namespace)
	deleteServiceAccounts(cmd, cleanOpts.K8sClient, cleanOpts.Namespace)
	deleteRoleBindings(cmd, cleanOpts.K8sClient, cleanOpts.Namespace)

	return nil
}

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

const defaultToken = "default-member-token"

type initOptions struct {
	namespace   string
	clusterSet  string
	clusterID   string
	createToken bool
	output      string
	k8sClient   client.Client
}

var initOpts *initOptions

func (o *initOptions) validate(cmd *cobra.Command) error {
	if o.namespace == "" {
		return fmt.Errorf("Namespace must be specified")
	}
	if o.clusterSet == "" {
		return fmt.Errorf("ClusterSet must be provided")
	}
	if o.clusterID == "" {
		return fmt.Errorf("ClusterID must be provided")
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

var initExample = strings.Trim(`
# Initialize ClusterSet in the given Namespace of the leader cluster.
  $ antctl mc init --clusterset clusterset1 --clusterid cluster-north -n antrea-multicluster
# Initialize ClusterSet of the leader cluster and save the join config to a file.
  $ antctl mc init --clusterset clusterset1 --clusterid cluster-north -n antrea-multicluster -j join-config.yml
# Initialize ClusterSet with a default member token, and save the join config as well as the token Secret to a file.
  $ antctl mc init --clusterset clusterset1 --clusterid cluster-north --create-token -n antrea-multicluster -j join-config.yml
`, "\n")

func NewInitCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "init",
		Short:   "Initialize ClusterSet in the given Namespace of the leader cluster",
		Args:    cobra.MaximumNArgs(0),
		Example: initExample,
		RunE:    initRunE,
	}

	o := initOptions{}
	initOpts = &o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	command.Flags().StringVarP(&o.clusterSet, "clusterset", "", "", "ClusterSet ID of the leader cluster")
	command.Flags().StringVarP(&o.clusterID, "clusterid", "", "", "ClusterID of the leader cluster")
	command.Flags().BoolVarP(&o.createToken, "create-token", "", false, "If specified, a default member token will be created. "+
		"If the output file is also specified, the token Secret manifest will be saved to the file after the join config.")
	command.Flags().StringVarP(&o.output, "join-config-file", "j", "", "File to save the config parameters for member clusters to join the ClusterSet")

	return command
}

func initRunE(cmd *cobra.Command, args []string) error {
	if err := initOpts.validate(cmd); err != nil {
		return err
	}
	createdRes := []map[string]interface{}{}
	var createErr error
	defer func() {
		if createErr != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to initialize the ClusterSet. Deleting the created resources\n")
			common.Rollback(cmd, initOpts.k8sClient, createdRes)
		}
	}()
	createErr = common.CreateClusterSet(cmd, initOpts.k8sClient, initOpts.namespace, initOpts.clusterSet, "", "", "", initOpts.clusterID, initOpts.namespace, &createdRes)
	if createErr != nil {
		return createErr
	}

	// Declare ClusterSet init succeeded, even if there is a failure later when creating the
	// member token or writing the join config file.
	fmt.Fprintf(cmd.OutOrStdout(), "Successfully initialized ClusterSet %s\n", initOpts.clusterSet)
	fmt.Fprintf(cmd.OutOrStdout(), "You can run command \"antctl mc get joinconfig -n %s\" to print the parameters needed for a member cluster to join the ClusterSet.\n", initOpts.namespace)

	var tokenSecret *corev1.Secret
	if initOpts.createToken {
		if err := common.CreateMemberToken(cmd, initOpts.k8sClient, defaultToken, initOpts.namespace, &createdRes); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Failed to create member token. You may run command \"antctl mc create membertoken\" to create a token.\n")
			return err
		}

		tokenSecret = &corev1.Secret{}
		if err := initOpts.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: initOpts.namespace,
			Name:      defaultToken,
		}, tokenSecret); err != nil {
			return err
		}
	}

	var err error
	var file *os.File
	if initOpts.output != "" {
		if file, err = os.OpenFile(initOpts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error opening file %s: %v\n", initOpts.output, err)
			return err
		}
		defer file.Close()
		if err := common.OutputJoinConfig(cmd, file, initOpts.clusterSet, initOpts.clusterID, initOpts.namespace, tokenSecret); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Saved ClusterSet join parameters to file: %s\n", initOpts.output)
	}

	return nil
}

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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

const (
	defaultToken = "default-member-token"

	// We comment out these ClusterSetJoinConfig fields in the generated
	// join config file, so they can be populated by command line options of
	// the "antctl mc join" command.
	optionalFields = `#clusterID: ""
#namespace: ""
# Use the pre-created token Secret.
#tokenSecretName: ""
# Create a token Secret with the manifest file.
#tokenSecretFile: ""
`
)

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
		return fmt.Errorf("the Namespace is required")
	}
	if o.clusterSet == "" {
		return fmt.Errorf("the ClusterSet is required")
	}
	if o.clusterID == "" {
		return fmt.Errorf("the ClusterID is required")
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
  $ antctl mc init --namespace antrea-multicluster --clusterset clusterset1 --clusterid cluster-north
# Initialize ClusterSet of the leader cluster and save the member cluster join config to a file.
  $ antctl mc init --namespace antrea-multicluster --clusterset clusterset1 --clusterid cluster-north -o join-config.yml
# Initialize ClusterSet with a default member token, and save the join config as well as the token Secret to a file.
  $ antctl mc init --namespace antrea-multicluster --clusterset clusterset1 --clusterid cluster-north --create-token -o join-config.yml 
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
	command.Flags().StringVarP(&o.output, "output-file", "o", "", "Output file to save the member cluster join config")

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
			fmt.Fprintf(cmd.OutOrStderr(), "Failed to init the Antrea Multi-cluster. Deleting the created resources\n")
			if err := common.Rollback(cmd, initOpts.k8sClient, createdRes); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Failed to rollback: %v\n", err)
			}
		}
	}()
	createErr = common.CreateClusterClaim(cmd, initOpts.k8sClient, initOpts.namespace, initOpts.clusterSet, initOpts.clusterID, &createdRes)
	if createErr != nil {
		return createErr
	}
	createErr = common.CreateClusterSet(cmd, initOpts.k8sClient, initOpts.namespace, initOpts.clusterSet, "", "", "", initOpts.clusterID, initOpts.namespace, &createdRes)
	if createErr != nil {
		return createErr
	}

	var err error
	var file *os.File
	if initOpts.output != "" {
		if file, err = os.OpenFile(initOpts.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644); err != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Failed to open file %s: %v\n", initOpts.output, err)
		}
		defer file.Close()
	}

	if err := outputConfig(cmd, file); err != nil {
		return err
	}
	if initOpts.createToken {
		if createErr = common.CreateMemberToken(cmd, initOpts.k8sClient, defaultToken, initOpts.namespace, file, &createdRes); createErr != nil {
			fmt.Fprintf(cmd.OutOrStderr(), "Failed to create Secret: %v\n", createErr)
			return createErr
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully initialized ClusterSet %s\n", initOpts.clusterSet)

	return nil
}

func outputConfig(cmd *cobra.Command, file *os.File) error {
	if file == nil {
		return nil
	}
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}

	config := &ClusterSetJoinConfig{
		APIVersion:      common.ClusterSetJoinConfigAPIVersion,
		Kind:            common.ClusterSetJoinConfigKind,
		Namespace:       "",
		ClusterID:       "",
		LeaderClusterID: initOpts.clusterID,
		LeaderAPIServer: kubeconfig.Host,
		LeaderNamespace: initOpts.namespace,
		ClusterSetID:    initOpts.clusterSet,
	}

	b, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("---\n")); err != nil {
		return err
	}
	if _, err := file.Write(b); err != nil {
		return err
	}
	if _, err := file.Write([]byte(optionalFields)); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully output the join config to %s\n", initOpts.output)
	return nil
}

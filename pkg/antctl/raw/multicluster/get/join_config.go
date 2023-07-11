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

package get

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type joinConfigOptions struct {
	namespace   string
	memberToken string
	k8sClient   client.Client
}

var joinConfigOpts *joinConfigOptions

var joinConfigExamples = strings.Trim(`
Print member join parameters of the ClusterSet in the antrea-multicluster Namespace
$ antctl mc get joinconfig -n antrea-multicluster
Print member join parameters and the Secret manifest of the default member token
$ antctl mc get joinconfig --member-token default-member-token -n antrea-multicluster
Print member join parameters and the Secret manifest of the specified member token
$ antctl mc get joinconfig --member-token cluster-east-token -n antrea-multicluster
`, "\n")

func (o *joinConfigOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.namespace == "" {
		return fmt.Errorf("Namespace must be specified")
	}

	// For unit test.
	if o.k8sClient != nil {
		return nil
	}

	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err == nil {
		o.k8sClient, err = client.New(kubeconfig, client.Options{Scheme: multiclusterscheme.Scheme})
	}
	return err
}

func NewJoinConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "joinconfig",
		Short:   "Print ClusterSet join parameters in a leader cluster",
		Args:    cobra.MaximumNArgs(0),
		Example: joinConfigExamples,
		RunE:    runEJoinConfig,
	}
	o := &joinConfigOptions{}
	joinConfigOpts = o
	cmd.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterSet")
	cmd.Flags().StringVarP(&o.memberToken, "member-token", "", "", "Member token name. If provided, the Secret manifest of the token will also be printed.")

	return cmd
}

func runEJoinConfig(cmd *cobra.Command, args []string) error {
	err := joinConfigOpts.validateAndComplete(cmd)
	if err != nil {
		return err
	}

	clusterSetList := &mcv1alpha2.ClusterSetList{}
	err = joinConfigOpts.k8sClient.List(context.TODO(), clusterSetList, &client.ListOptions{Namespace: joinConfigOpts.namespace})
	if err != nil {
		return err
	}
	clusterSets := clusterSetList.Items

	if len(clusterSets) == 0 {
		return fmt.Errorf("No ClusterSet found in Namespace %s", joinConfigOpts.namespace)
	} else if len(clusterSets) > 1 {
		return fmt.Errorf("More than one ClusterSets in Namespace %s", joinConfigOpts.namespace)
	}

	cs := clusterSets[0]
	if len(cs.Spec.Leaders) == 0 {
		return fmt.Errorf("Invalid ClusterSet %s: no leader cluster", cs.Name)
	}

	var tokenSecret *corev1.Secret
	if joinConfigOpts.memberToken != "" {
		tokenSecret = &corev1.Secret{}
		err = joinConfigOpts.k8sClient.Get(context.TODO(), types.NamespacedName{
			Namespace: joinConfigOpts.namespace,
			Name:      joinConfigOpts.memberToken,
		}, tokenSecret)
		if err != nil {
			return err
		}
	}

	if err := common.OutputJoinConfig(cmd, cmd.OutOrStdout(), cs.Name, cs.Spec.Leaders[0].ClusterID, cs.Namespace, tokenSecret); err != nil {
		return err
	}
	return nil
}

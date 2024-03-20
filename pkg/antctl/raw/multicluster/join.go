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
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

var joinOpts *joinOptions

type joinOptions struct {
	common.ClusterSetJoinConfig
	ConfigFile string
	Secret     *v1.Secret
	k8sClient  client.Client
}

func (o *joinOptions) validateAndComplete(cmd *cobra.Command) error {
	if o.ConfigFile != "" {
		raw, err := os.ReadFile(o.ConfigFile)
		if err != nil {
			return err
		}
		if err := yamlUnmarshall(raw, &o.ClusterSetJoinConfig); err != nil {
			return err
		}
		if o.Kind != common.ClusterSetJoinConfigKind || o.APIVersion != common.ClusterSetJoinConfigAPIVersion {
			return fmt.Errorf("unknown apiVersion or kind in config: %s", o.ConfigFile)
		}

		if o.TokenSecretName == "" && o.TokenSecretFile == "" {
			// Try reading the Secret manifest from the config file.
			o.Secret, err = unmarshallSecret(raw)
			if err != nil {
				return fmt.Errorf("failed to unmarshall Secret from config file: %v", err)
			}
		}
	}

	// The precedence order is that TokenSecretName > TokenSecretFile > JoinConfigFile.
	if o.TokenSecretName == "" && o.TokenSecretFile != "" {
		raw, err := os.ReadFile(o.TokenSecretFile)
		if err != nil {
			return err
		}
		o.Secret, err = unmarshallSecret(raw)
		if err != nil {
			return fmt.Errorf("failed to unmarshall Secret from token Secret file: %s, error: %v", o.TokenSecretFile, err)
		}
	}

	if o.LeaderClusterID == "" {
		return fmt.Errorf("ClusterID of leader cluster must be provided")
	}
	if o.LeaderAPIServer == "" {
		return fmt.Errorf("API server of the leader cluster must be provided")
	}
	if o.TokenSecretName == "" && o.Secret == nil {
		return fmt.Errorf("a member token Secret must be provided through the Secret name, or Secret file, or Secret manifest in the config file")
	}
	if o.LeaderNamespace == "" {
		return fmt.Errorf("leader cluster Namespace must be provided")
	}
	if o.ClusterSetID == "" {
		return fmt.Errorf("ClusterSet ID must be provided")
	}
	if o.ClusterID == "" {
		return fmt.Errorf("ClusterID of member cluster must be provided")
	}
	if o.Namespace == "" {
		fmt.Printf("Antrea Multi-cluster Namespace is not specified. Use %s\n.", common.DefaultMemberNamespace)
		o.Namespace = common.DefaultMemberNamespace
	}

	// Always set the Secret Namespace with the member cluster Multi-cluster Namespace.
	if o.Secret != nil {
		o.Secret.Namespace = o.Namespace
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

func yamlUnmarshall(raw []byte, v interface{}) error {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(false)
	return d.Decode(v)
}

func unmarshallSecret(raw []byte) (*v1.Secret, error) {
	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 100)
	secret := &v1.Secret{}
	if err := decoder.Decode(secret); err != nil {
		return nil, err
	}
	if secret.Name != "" {
		return secret, nil
	}

	// We may need to skip the first object, which can be comments and the
	// starting "---" before the Secret.
	if err := decoder.Decode(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

var joinExamples = strings.Trim(`
# Join a ClusterSet with a pre-created token Secret
  $ antctl mc join --clusterset=clusterset1 \
                   --clusterid=cluster-east \
                   --leader-clusterid=cluster-north \
                   --leader-namespace=antrea-multicluster \
                   --leader-apiserver=https://172.18.0.3:6443 \
                   --token-secret-name=cluster-east-token \
                   --n kube-system

# Join a ClusterSet with a token Secret manifest
  $ antctl mc join --clusterset=clusterset1 \
                   --clusterid=cluster-east \
                   --leader-clusterid=cluster-north \
                   --leader-namespace=antrea-multicluster \
                   --leader-apiserver=https://172.18.0.3:6443 \
                   --token-secret-file=cluster-east-token.yml \
                   --n kube-system

# Join a ClusterSet with parameters defined in a config file
  $ antctl mc join --config-file join-config.yml

# Config file example:
---
apiVersion: multicluster.antrea.io/v1alpha1
kind: ClusterSetJoinConfig
clusterSetID: clusterset1
clusterID: cluster-east
namespace: kube-system
leaderClusterID: cluster-north
leaderNamespace: antrea-multicluster
leaderAPIServer: https://172.18.0.3:6443
# Use the pre-created token Secret.
#tokenSecretName: ""
# Create a token Secret with the manifest file.
#tokenSecretFile: ""
# Manifest to create a Secret for a member cluster token.
---
apiVersion: v1
kind: Secret
metadata:
  name: token-secret
data:
# Generated by "init" or "create membertoken" command
  ca.crt: ...
  namespace: ...
  token: ...
type: Opaque
`, "\n")

func NewJoinCommand() *cobra.Command {
	command := &cobra.Command{
		Use:     "join",
		Short:   "Join the ClusterSet from a member cluster",
		Args:    cobra.MaximumNArgs(0),
		Example: joinExamples,
		RunE:    joinRunE,
	}

	o := joinOptions{}
	joinOpts = &o
	command.Flags().StringVarP(&joinOpts.LeaderNamespace, "leader-namespace", "", "", "Namespace of the leader cluster")
	command.Flags().StringVarP(&joinOpts.LeaderClusterID, "leader-clusterid", "", "", "Cluster ID of the leader cluster")
	command.Flags().StringVarP(&joinOpts.TokenSecretName, "token-secret-name", "", "", "Name of the Secret resource that contains the member token. "+
		"Token Secret name takes precedence over token Secret file and the Secret manifest in the config file.")
	command.Flags().StringVarP(&joinOpts.LeaderAPIServer, "leader-apiserver", "", "", "API Server endpoint of the leader cluster")
	command.Flags().StringVarP(&joinOpts.Namespace, "namespace", "n", common.DefaultMemberNamespace, "Antrea Multi-cluster Namespace. Defaults to "+common.DefaultMemberNamespace+".")
	command.Flags().StringVarP(&joinOpts.ClusterID, "clusterid", "", "", "Cluster ID of the member cluster")
	command.Flags().StringVarP(&joinOpts.ClusterSetID, "clusterset", "", "", "ClusterSet ID")
	command.Flags().StringVarP(&joinOpts.TokenSecretFile, "token-secret-file", "", "", "Secret manifest for the member token. If specified, a Secret will be created with the manifest. "+
		"Token Secret file takes precedence over the Secret manifest in the config file, if both are specified.")
	command.Flags().StringVarP(&joinOpts.ConfigFile, "config-file", "f", "", "Config file that defines the join parameters. If both command line options and config file are specified, "+
		"the values in config file take precedence.")

	return command
}

func joinRunE(cmd *cobra.Command, args []string) error {
	var err error
	if err = joinOpts.validateAndComplete(cmd); err != nil {
		return err
	}

	memberClusterNamespace := joinOpts.Namespace
	memberClusterID := joinOpts.ClusterID
	memberClusterSet := joinOpts.ClusterSetID
	createdRes := []map[string]interface{}{}
	defer func() {
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to join the ClusterSet. Deleting the created resources\n")
			common.Rollback(cmd, joinOpts.k8sClient, createdRes)
		}
	}()

	if joinOpts.Secret != nil {
		joinOpts.Secret.Annotations = map[string]string{
			common.CreateByAntctlAnnotation: "true",
		}
		if err := joinOpts.k8sClient.Create(context.TODO(), joinOpts.Secret); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Failed to create member token Secret: %v\n", err)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created member token Secret %s\n", joinOpts.Secret.Name)
		unstructuredSecret, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(joinOpts.Secret)
		unstructuredSecret["apiVersion"] = "v1"
		unstructuredSecret["kind"] = "Secret"
		createdRes = append(createdRes, unstructuredSecret)
		joinOpts.TokenSecretName = joinOpts.Secret.Name
	}

	err = common.CreateClusterSet(cmd, joinOpts.k8sClient, memberClusterNamespace, memberClusterSet, joinOpts.LeaderAPIServer, joinOpts.TokenSecretName,
		memberClusterID, joinOpts.LeaderClusterID, joinOpts.LeaderNamespace, &createdRes)
	if err != nil {
		return err
	}
	if err = waitForMemberClusterReady(cmd, joinOpts.k8sClient); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Failed to wait for ClusterSet ready: %v\n", err)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Member cluster joined successfully\n")

	return nil
}

func waitForMemberClusterReady(cmd *cobra.Command, k8sClient client.Client) error {
	fmt.Fprintf(cmd.OutOrStdout(), "Waiting for ClusterSet ready\n")

	if err := waitForClusterSetReady(k8sClient, joinOpts.ClusterSetID, joinOpts.Namespace, joinOpts.LeaderClusterID); err != nil {
		return err
	}

	return nil
}

func waitForClusterSetReady(client client.Client, name string, namespace string, clusterID string) error {
	return wait.PollUntilContextTimeout(context.TODO(),
		1*time.Second,
		1*time.Minute,
		true,
		func(ctx context.Context) (bool, error) {
			clusterSet := &mcv1alpha2.ClusterSet{}
			if err := client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, clusterSet); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}

			for _, status := range clusterSet.Status.ClusterStatuses {
				if status.ClusterID == clusterID {
					for _, cond := range status.Conditions {
						if cond.Type == mcv1alpha2.ClusterReady {
							return cond.Status == "True", nil
						}
					}
					break
				}
			}

			return false, nil
		})
}

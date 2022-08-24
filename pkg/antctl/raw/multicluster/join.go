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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/pkg/antctl/raw/multicluster/common"
)

const (
	defaultMemberNamespace = "kube-system"
)

// "omitempty" fields (clusterID, namespace, tokenSecretName, tokenSecretFile)
// can be populated by the corresponding command line options if not set in the
// config file.
type ClusterSetJoinConfig struct {
	Kind            string `yaml:"kind"`
	APIVersion      string `yaml:"apiVersion"`
	ClusterSetID    string `yaml:"clusterSetID"`
	ClusterID       string `yaml:"clusterID,omitempty"`
	Namespace       string `yaml:"namespace,omitempty"`
	LeaderClusterID string `yaml:"leaderClusterID"`
	LeaderNamespace string `yaml:"leaderNamespace"`
	LeaderAPIServer string `yaml:"leaderAPIServer"`
	TokenSecretName string `yaml:"tokenSecretName,omitempty"`
	TokenSecretFile string `yaml:"tokenSecretFile,omitempty"`
	// The following fields are not included in the config file.
	ConfigFile string     `yaml:"-"`
	Secret     *v1.Secret `yaml:"-"`
}

var joinOpts *ClusterSetJoinConfig

func (o *ClusterSetJoinConfig) validateAndComplete() error {
	if o.ConfigFile != "" {
		raw, err := os.ReadFile(o.ConfigFile)
		if err != nil {
			return err
		}
		if err := yamlUnmarshall(raw, o); err != nil {
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
			return fmt.Errorf("failed to unmarshall Secret from token Secret file: %v", err)
		}
	}

	if o.LeaderClusterID == "" {
		return fmt.Errorf("the ClusterID of leader cluster is required")
	}
	if o.LeaderAPIServer == "" {
		return fmt.Errorf("the API server of the leader cluster is required")
	}
	if o.TokenSecretName == "" && o.Secret == nil {
		return fmt.Errorf("a member token Secret must be provided through the Secret name, or Secret file, or Secret manifest in the config file")
	}
	if o.LeaderNamespace == "" {
		return fmt.Errorf("the leader cluster Namespace is required")
	}
	if o.ClusterSetID == "" {
		return fmt.Errorf("the ClusterSet ID is required")
	}
	if o.ClusterID == "" {
		return fmt.Errorf("the member ClusterID is required")
	}
	if o.Namespace == "" {
		fmt.Printf("Antrea Multi-cluster Namespace is not specified. Use %s\n.", defaultMemberNamespace)
		o.Namespace = defaultMemberNamespace
	}

	// Always set the Secret Namespace with the member cluster Multi-cluster Namespace.
	if o.Secret != nil {
		o.Secret.Namespace = o.Namespace
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
	// We need to skip the first object. The Secret object is the second
	// object in the config file, and we also need to skip starting "---"
	// when decoding the token Secret file.
	u := unstructured.Unstructured{}
	if err := decoder.Decode(&u); err != nil {
		return nil, err
	}
	if err := decoder.Decode(secret); err != nil {
		return nil, err
	}

	return secret, nil
}

var joinExamples = strings.Trim(`
# Join the ClusterSet with a pre-created token Secret.
  $ antctl mc join --clusterset=clusterset1 \
                   --clusterid=cluster-east \
                   --namespace=kube-system \
                   --leader-clusterid=cluster-north \
                   --leader-namespace=antrea-multicluster \
                   --leader-apiserver=https://172.18.0.3:6443 \
                   --token-secret-name=cluster-east-token

# Join the ClusterSet with a token Secret manifest.
  $ antctl mc join --clusterset=clusterset1 \
                   --clusterid=cluster-east \
                   --namespace=kube-system \
                   --leader-clusterid=cluster-north \
                   --leader-namespace=antrea-multicluster \
                   --leader-apiserver=https://172.18.0.3:6443 \
                   --token-secret-file=cluster-east-token.yml

# Join the ClusterSet with a config manifest. 
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

	o := ClusterSetJoinConfig{}
	joinOpts = &o
	command.Flags().StringVarP(&joinOpts.LeaderNamespace, "leader-namespace", "", "", "Namespace of the leader cluster")
	command.Flags().StringVarP(&joinOpts.LeaderClusterID, "leader-clusterid", "", "", "Cluster ID of the leader cluster")
	command.Flags().StringVarP(&joinOpts.TokenSecretName, "token-secret-name", "", "", "Name of the Secret resource that contains the member token. "+
		"Token Secret name takes precedence over token Secret file and the Secret manifest in the join config file")
	command.Flags().StringVarP(&joinOpts.LeaderAPIServer, "leader-apiserver", "", "", "API Server endpoint of the leader cluster")
	command.Flags().StringVarP(&joinOpts.Namespace, "namespace", "n", defaultMemberNamespace, "Antrea Multi-cluster Namespace. Defaults to "+defaultMemberNamespace)
	command.Flags().StringVarP(&joinOpts.ClusterID, "clusterid", "", "", "Cluster ID of the member cluster")
	command.Flags().StringVarP(&joinOpts.ClusterSetID, "clusterset", "", "", "ClusterSet ID")
	command.Flags().StringVarP(&joinOpts.TokenSecretFile, "token-secret-file", "", "", "Secret manifest for the member token. If specified, a Secret will be created with the manifest. "+
		"Token Secret file takes precedence over the Secret manifest in the join config file, if both are specified.")
	command.Flags().StringVarP(&joinOpts.ConfigFile, "config-file", "f", "", "Config file that defines all config options. If both command line options and config file are specified, "+
		"the arguments in config file will be used.")

	return command
}

func joinRunE(cmd *cobra.Command, args []string) error {
	var err error
	if err = joinOpts.validateAndComplete(); err != nil {
		return err
	}
	k8sClient, err := common.NewClient(cmd)

	memberClusterNamespace := joinOpts.Namespace
	memberClusterID := joinOpts.ClusterID
	memberClusterSet := joinOpts.ClusterSetID
	createdRes := []map[string]interface{}{}
	defer func() {
		if err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to join the ClusterSet. Deleting the created resources\n")
			if err := common.Rollback(cmd, k8sClient, createdRes); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Failed to rollback: %v\n", err)
			}
		}
	}()

	if joinOpts.Secret != nil {
		joinOpts.Secret.Annotations = map[string]string{
			common.CreateByAntctlAnnotation: "true",
		}
		if err := k8sClient.Create(context.TODO(), joinOpts.Secret); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create the Secret from the config file: %v\n", err)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created the Secret from the config file\n")
		unstructuredSecret, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(joinOpts.Secret)
		unstructuredSecret["apiVersion"] = "v1"
		unstructuredSecret["kind"] = "Secret"
		createdRes = append(createdRes, unstructuredSecret)
		joinOpts.TokenSecretName = joinOpts.Secret.Name
	}

	err = common.CreateClusterClaim(cmd, k8sClient, memberClusterNamespace, memberClusterSet, memberClusterID, &createdRes)
	if err != nil {
		return err
	}
	err = common.CreateClusterSet(cmd, k8sClient, memberClusterNamespace, memberClusterSet, joinOpts.LeaderAPIServer, joinOpts.TokenSecretName,
		joinOpts.ClusterID, joinOpts.LeaderClusterID, joinOpts.LeaderNamespace, &createdRes)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Waiting for member cluster ready\n")
	if err = waitForMemberClusterReady(cmd, k8sClient); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to wait for member cluster ready: %v\n", err)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Member cluster joined successfully\n")

	return nil
}

func waitForMemberClusterReady(cmd *cobra.Command, k8sClient client.Client) error {
	fmt.Fprintf(cmd.OutOrStdout(), "Waiting for ClusterSet ready\n")

	if err := waitForClusterSetReady(k8sClient, joinOpts.ClusterSetID, joinOpts.Namespace, joinOpts.LeaderClusterID); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to wait for ClusterSet \"%s\" in Namespace %s in member cluster: %v\n", joinOpts.ClusterSetID, joinOpts.Namespace, err)
		return err
	}

	return nil
}

func waitForClusterSetReady(client client.Client, name string, namespace string, clusterID string) error {
	return wait.PollImmediate(
		1*time.Second,
		3*time.Minute,
		func() (bool, error) {
			clusterSet := &multiclusterv1alpha1.ClusterSet{}
			if err := client.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, clusterSet); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}

			for _, status := range clusterSet.Status.ClusterStatuses {
				if status.ClusterID == clusterID {
					for _, cond := range status.Conditions {
						if cond.Type == multiclusterv1alpha1.ClusterReady {
							return cond.Status == "True", nil
						}
					}
					break
				}
			}

			return false, nil
		})
}

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

package create

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

type accessTokenOptions struct {
	namespace      string
	serviceAccount string
	roleBinding    string
}

var accessTokenOpts *accessTokenOptions

var accessTokenExamples = strings.Trim(`
# Create an access token in a leader cluster for one or more member clusters. If the ServiceAccount or RoleBinding does not exist, the command will create them too
  $ antctl mc create accesstoken <NAME> -n <NAMESPACE> --service-account <SERVICE_ACCOUNT> --role-binding <ROLE_BINDING>
`, "\n")

func (o *accessTokenOptions) validateAndComplete() error {
	if o.namespace == "" {
		return fmt.Errorf("the Namespace cannot be empty")
	}
	if o.serviceAccount == "" {
		return fmt.Errorf("the ServiceAccount cannot be empty")
	}
	if o.roleBinding == "" {
		return fmt.Errorf("the RoleBinding cannot be empty")
	}
	return nil
}

func NewAccessTokenCmd() *cobra.Command {
	command := &cobra.Command{
		Use:     "accesstoken",
		Args:    cobra.MaximumNArgs(1),
		Short:   "Create an accesstoken in a leader cluster",
		Long:    "Create an accesstoken in a leader cluster",
		Example: accessTokenExamples,
		RunE:    accessTokenRunE,
	}

	o := &accessTokenOptions{}
	accessTokenOpts = o
	command.Flags().StringVarP(&o.namespace, "namespace", "n", "", "Namespace of the ClusterClaim")
	command.Flags().StringVarP(&o.serviceAccount, "service-account", "", "", "ServiceAccount of the access token")
	command.Flags().StringVarP(&o.roleBinding, "role-binding", "", "", "RoleBinding of the ServiceAccount")

	return command
}

func accessTokenRunE(cmd *cobra.Command, args []string) error {
	if err := accessTokenOpts.validateAndComplete(); err != nil {
		return err
	}
	if len(args) != 1 {
		return fmt.Errorf("exactly one NAME is required, got %d", len(args))
	}
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)
	k8sClient, err := client.New(kubeconfig, client.Options{Scheme: multiclusterscheme.Scheme})
	if err != nil {
		return err
	}

	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      accessTokenOpts.serviceAccount,
			Namespace: accessTokenOpts.namespace,
		},
	}

	var createErr error
	fmt.Fprintf(cmd.OutOrStdout(), "Creating ServiceAccount \"%s\"\n", accessTokenOpts.serviceAccount)
	createErr = k8sClient.Create(context.TODO(), &serviceAccount)
	if createErr != nil {
		if errors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStderr(), "ServiceAccount \"%s\" already exists\n", accessTokenOpts.serviceAccount)
			createErr = nil
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ServiceAccount \"%s\", error: %s\n", accessTokenOpts.serviceAccount, createErr.Error())
			return createErr
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount \"%s\" created\n", serviceAccount.Name)
		defer func() {
			if createErr != nil {
				err := k8sClient.Delete(context.TODO(), &serviceAccount)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ServiceAccount \"%s\", error: %s\n", serviceAccount.Name, err.Error())
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount \"%s\" deleted\n", serviceAccount.Name)
				}
			}
		}()
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Creating RoleBinding \"%s\"\n", accessTokenOpts.roleBinding)
	roleBinding := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      accessTokenOpts.roleBinding,
			Namespace: accessTokenOpts.namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "antrea-mc-member-cluster-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      accessTokenOpts.serviceAccount,
				Namespace: accessTokenOpts.namespace,
			},
		},
	}

	createErr = k8sClient.Create(context.TODO(), &roleBinding)
	if createErr != nil {
		if errors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStderr(), "RoleBinding \"%s\" already exists\n", accessTokenOpts.roleBinding)
			createErr = nil
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create RoleBingding \"%s\", error: %s\n", accessTokenOpts.roleBinding, createErr.Error())
			return createErr
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "RoleBinding \"%s\" created\n", roleBinding.Name)
		defer func() {
			if createErr != nil {
				err := k8sClient.Delete(context.TODO(), &roleBinding)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete RoleBinding \"%s\", error: %s\n", roleBinding.Name, err.Error())
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "RoleBinding \"%s\" deleted\n", roleBinding.Name)
				}
			}
		}()
	}

	secretName := args[0]

	fmt.Fprintf(cmd.OutOrStdout(), "Creating Secret \"%s\"\n", secretName)
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName + "A",
			Namespace: accessTokenOpts.namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": accessTokenOpts.serviceAccount,
			},
		},
		Type: "kubernetes.io/service-account-token",
	}

	createErr = k8sClient.Create(context.TODO(), &secret)
	if createErr != nil {
		if errors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStderr(), "Secret \"%s\" already exists\n", secretName)
			createErr = nil
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create Secret \"%s\", start rollback\n", secretName)
			return createErr
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Secret \"%s\" with access token created\n", secretName)
	}

	return nil
}

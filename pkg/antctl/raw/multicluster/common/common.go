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

package common

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8syaml "sigs.k8s.io/yaml"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	multiclusterv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/raw"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

const (
	ClusterSetJoinConfigAPIVersion = "multicluster.antrea.io/v1alpha1"
	ClusterSetJoinConfigKind       = "ClusterSetJoinConfig"

	CreateByAntctlAnnotation = "multicluster.antrea.io/created-by-antctl"

	DefaultMemberNamespace = "kube-system"
	DefaultLeaderNamespace = "antrea-multicluster"
)

// "omitempty" fields (clusterID, namespace, tokenSecretName, tokenSecretFile)
// can be populated by the corresponding command line options if not set in the
// config file.
type ClusterSetJoinConfig struct {
	APIVersion      string `yaml:"apiVersion"`
	Kind            string `yaml:"kind"`
	ClusterSetID    string `yaml:"clusterSetID"`
	ClusterID       string `yaml:"clusterID,omitempty"`
	Namespace       string `yaml:"namespace,omitempty"`
	LeaderClusterID string `yaml:"leaderClusterID"`
	LeaderNamespace string `yaml:"leaderNamespace"`
	LeaderAPIServer string `yaml:"leaderAPIServer"`
	TokenSecretName string `yaml:"tokenSecretName,omitempty"`
	TokenSecretFile string `yaml:"tokenSecretFile,omitempty"`
}

func NewClient(cmd *cobra.Command) (client.Client, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, err
	}
	restConfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restConfigTmpl)

	k8sClient, err := client.New(restConfigTmpl, client.Options{Scheme: multiclusterscheme.Scheme})
	if err != nil {
		return nil, err
	}

	return k8sClient, nil
}

func CreateClusterClaim(cmd *cobra.Command, k8sClient client.Client, namespace string, clusterset string, clusterID string, createdRes *[]map[string]interface{}) error {
	var createErr error
	var unstructuredClusterClaim map[string]interface{}
	clusterClaim := newClusterClaim(clusterID, namespace, false)

	if createErr = k8sClient.Create(context.TODO(), clusterClaim); createErr != nil {
		if !apierrors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ClusterClaim \"%s\": %v\n", multiclusterv1alpha2.WellKnownClusterClaimID, createErr)
			return createErr
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" already exists in Namespace %s\n", multiclusterv1alpha2.WellKnownClusterClaimID, namespace)
		createErr = nil
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" created in Namespace %s\n", multiclusterv1alpha2.WellKnownClusterClaimID, namespace)
		unstructuredClusterClaim, _ = runtime.DefaultUnstructuredConverter.ToUnstructured(clusterClaim)
		*createdRes = append(*createdRes, unstructuredClusterClaim)
	}

	clusterClaim = newClusterClaim(clusterset, namespace, true)
	if createErr = k8sClient.Create(context.TODO(), clusterClaim); createErr != nil {
		if !apierrors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ClusterClaim \"%s\": %v\n", multiclusterv1alpha2.WellKnownClusterClaimClusterSet, createErr)
			return createErr
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" already exists in Namespace %s\n", multiclusterv1alpha2.WellKnownClusterClaimClusterSet, namespace)
		createErr = nil
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" created in Namespace %s\n", multiclusterv1alpha2.WellKnownClusterClaimClusterSet, namespace)
		unstructuredClusterClaim, _ = runtime.DefaultUnstructuredConverter.ToUnstructured(clusterClaim)
		*createdRes = append(*createdRes, unstructuredClusterClaim)
	}

	return nil
}

func CreateClusterSet(cmd *cobra.Command, k8sClient client.Client, namespace string, clusterset string,
	leaderServer string, secret string, memberClusterID string, leaderClusterID string, leaderClusterNamespace string, createdRes *[]map[string]interface{}) error {
	clusterSet := newClusterSet(clusterset, namespace, leaderServer, secret, memberClusterID, leaderClusterID, leaderClusterNamespace)

	if err := k8sClient.Create(context.TODO(), clusterSet); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ClusterSet \"%s\": %v\n", clusterSet.Name, err)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" already exists in Namespace %s\n", clusterSet.Name, clusterSet.Namespace)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" created in Namespace %s\n", clusterSet.Name, clusterSet.Namespace)
		unstructuredClusterSet, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(clusterSet)
		*createdRes = append(*createdRes, unstructuredClusterSet)
	}

	return nil
}

func deleteClusterClaims(cmd *cobra.Command, k8sClient client.Client, namespace string) {
	clusterClaimNames := []string{
		multiclusterv1alpha2.WellKnownClusterClaimID,
		multiclusterv1alpha2.WellKnownClusterClaimClusterSet,
	}
	for _, name := range clusterClaimNames {
		if err := k8sClient.Delete(context.TODO(), newClusterClaim(name, namespace, name == multiclusterv1alpha2.WellKnownClusterClaimClusterSet)); err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" deleted in Namespace %s\n", name, namespace)
		} else {
			if apierrors.IsNotFound(err) {
				fmt.Fprintf(cmd.OutOrStdout(), "ClusterClaim \"%s\" not found in Namespace %s\n", name, namespace)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ClusterClaim \"%s\": %v\n", name, err)
			}
		}
	}
}

func deleteClusterSet(cmd *cobra.Command, k8sClient client.Client, namespace string, clusterSet string) {
	var err error
	if err = k8sClient.Delete(context.TODO(), newClusterSet(clusterSet, namespace, "", "", "", "", "")); err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" deleted in Namespace %s\n", clusterSet, namespace)
		return
	}
	if apierrors.IsNotFound(err) {
		fmt.Fprintf(cmd.OutOrStdout(), "ClusterSet \"%s\" not found in Namespace %s\n", clusterSet, namespace)
		return
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ClusterSet \"%s\": %v\n", clusterSet, err)
}

func deleteSecrets(cmd *cobra.Command, k8sClient client.Client, namespace string) {
	secretList := &corev1.SecretList{}
	if err := k8sClient.List(context.TODO(), secretList, client.InNamespace(namespace)); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to list Secrets in Namespace %s: %v\n", namespace, err)
		return
	}

	for _, s := range secretList.Items {
		secret := s
		if secret.Annotations[CreateByAntctlAnnotation] != "true" {
			continue
		}

		if err := k8sClient.Delete(context.TODO(), &secret); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete Secret \"%s\": %v\n", secret.Name, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Secret \"%s\" deleted in Namespace %s\n", secret.Name, namespace)
	}
}

func deleteRoleBindings(cmd *cobra.Command, k8sClient client.Client, namespace string) {
	roleBindingList := &rbacv1.RoleBindingList{}
	if err := k8sClient.List(context.TODO(), roleBindingList, client.InNamespace(namespace)); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to list RoleBindings in Namespace %s: %v\n", namespace, err)
		return
	}

	for _, r := range roleBindingList.Items {
		roleBinding := r
		if roleBinding.Annotations[CreateByAntctlAnnotation] != "true" {
			continue
		}

		if err := k8sClient.Delete(context.TODO(), &roleBinding); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete RoleBinding \"%s\": %v\n", roleBinding.Name, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "RoleBinding \"%s\" deleted in Namespace %s\n", roleBinding.Name, namespace)
	}
}

func deleteServiceAccounts(cmd *cobra.Command, k8sClient client.Client, namespace string) {
	serviceAccountList := &corev1.ServiceAccountList{}
	if err := k8sClient.List(context.TODO(), serviceAccountList, client.InNamespace(namespace)); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to list ServiceAccounts in Namespace %s: %v\n", namespace, err)
		return
	}

	for _, sa := range serviceAccountList.Items {
		serviceAccount := sa
		if serviceAccount.Annotations[CreateByAntctlAnnotation] != "true" {
			continue
		}

		if err := k8sClient.Delete(context.TODO(), &serviceAccount); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete ServiceAccount \"%s\": %v\n", serviceAccount.Name, err)
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount \"%s\" deleted in Namespace %s\n", serviceAccount.Name, namespace)
	}
}

// ConvertMemberTokenSecret generates a token Secret manifest for creating the input Secret in a member cluster.
func ConvertMemberTokenSecret(secret corev1.Secret) corev1.Secret {
	s := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
		Data: secret.Data,
		Type: corev1.SecretTypeOpaque,
	}
	return s
}

func CreateMemberToken(cmd *cobra.Command, k8sClient client.Client, name string, namespace string, file *os.File, createdRes *[]map[string]interface{}) error {
	var createErr error
	serviceAccount := newServiceAccount(name, namespace)
	createErr = k8sClient.Create(context.TODO(), serviceAccount)
	if createErr != nil {
		if !apierrors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create ServiceAccount \"%s\", error: %s\n", name, createErr.Error())
			return createErr
		}
		fmt.Fprintf(cmd.OutOrStderr(), "ServiceAccount \"%s\" already exists\n", name)
		createErr = nil
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount \"%s\" created\n", serviceAccount.Name)
		unstructuredSA, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(serviceAccount)
		*createdRes = append(*createdRes, unstructuredSA)
	}

	roleBinding := newRoleBinding(name, name, namespace)
	createErr = k8sClient.Create(context.TODO(), roleBinding)
	if createErr != nil {
		if !apierrors.IsAlreadyExists(createErr) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create RoleBinding \"%s\", error: %s\n", name, createErr.Error())
			return createErr
		}
		fmt.Fprintf(cmd.OutOrStderr(), "RoleBinding \"%s\" already exists\n", name)
		createErr = nil
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "RoleBinding \"%s\" created\n", roleBinding.Name)
		unstructuredRoleBinding, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(roleBinding)
		*createdRes = append(*createdRes, unstructuredRoleBinding)
	}
	var secretAlreadyExists bool
	secret := newSecret(name, name, namespace)
	createErr = k8sClient.Create(context.TODO(), secret)
	if createErr != nil {
		secretAlreadyExists = apierrors.IsAlreadyExists(createErr)
		if !secretAlreadyExists {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to create Secret \"%s\", start rollback\n", name)
			return createErr
		}
		fmt.Fprintf(cmd.OutOrStderr(), "Secret \"%s\" already exists\n", name)
	}
	// It will take one or two seconds to wait for the Data.token to be created.
	if err := waitForSecretReady(k8sClient, name, namespace); err != nil {
		return err
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Secret \"%s\" created\n", secret.Name)
		if !secretAlreadyExists {
			unstructuredSecret, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
			*createdRes = append(*createdRes, unstructuredSecret)
		}
	}

	if file == nil {
		return nil
	}

	if err := k8sClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, secret); err != nil {
		return err
	}

	s := ConvertMemberTokenSecret(*secret)

	b, err := k8syaml.Marshal(s)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte("# Manifest to create a Secret for an Antrea Multi-cluster  member cluster token.\n")); err != nil {
		return err
	}
	if _, err := file.Write([]byte("---\n")); err != nil {
		return err
	}
	if _, err := file.Write(b); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Member token saved to %s\n", file.Name())

	return nil
}

func DeleteMemberToken(cmd *cobra.Command, k8sClient client.Client, name string, namespace string) error {
	errFunc := func(kind string, act string, err error) error {
		if apierrors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s not found in Namespace %s\n", kind, name, namespace)
			return nil
		}
		if err != nil {
			return err
		}
		if act == "delete" {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s deleted\n", kind, name)
		}
		return nil
	}

	secret := &corev1.Secret{}
	getErr := k8sClient.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, secret)
	err := errFunc("Secret", "get", getErr)
	if err != nil {
		return err
	}
	if secret.Annotations[CreateByAntctlAnnotation] == "true" {
		deleteErr := k8sClient.Delete(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
			}}, &client.DeleteOptions{})
		err = errFunc("Secret", "delete", deleteErr)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Secret %s is not created by antctl,  ignoring it", name)
	}

	roleBinding := &rbacv1.RoleBinding{}
	getErr = k8sClient.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, roleBinding)
	err = errFunc("RoleBinding", "get", getErr)
	if err != nil {
		return err
	}
	if roleBinding.Annotations[CreateByAntctlAnnotation] == "true" {
		deleteErr := k8sClient.Delete(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
			}}, &client.DeleteOptions{})
		err = errFunc("RoleBinding", "delete", deleteErr)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "RoleBinding %s is not created by antctl , ignoring it", name)
	}

	serviceAccount := &corev1.ServiceAccount{}
	getErr = k8sClient.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, serviceAccount)
	err = errFunc("ServiceAccount", "get", getErr)
	if err != nil {
		return err
	}
	if serviceAccount.Annotations[CreateByAntctlAnnotation] == "true" {
		deleteErr := k8sClient.Delete(context.TODO(), &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
			}}, &client.DeleteOptions{})
		err = errFunc("ServiceAccount", "delete", deleteErr)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount %s is not created by antctl, ignoring it", name)
	}
	return nil
}

func waitForSecretReady(client client.Client, secretName string, namespace string) error {
	return wait.PollImmediate(
		1*time.Second,
		5*time.Second,
		func() (bool, error) {
			secret := &corev1.Secret{}
			if err := client.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				return false, err
			}
			return string(secret.Data["token"]) != "", nil
		})
}

func newClusterClaim(name string, namespace string, clusterSet bool) *multiclusterv1alpha2.ClusterClaim {
	clusterClaim := &multiclusterv1alpha2.ClusterClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "multicluster.crd.antrea.io/v1alpha2",
			Kind:       "ClusterClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      multiclusterv1alpha2.WellKnownClusterClaimID,
		},
		Value: name,
	}

	if clusterSet {
		clusterClaim.Name = multiclusterv1alpha2.WellKnownClusterClaimClusterSet
	}

	return clusterClaim
}

func newClusterSet(name, namespace, leaderServer, secret, memberClusterID, leaderClusterID, leaderNamespace string) *multiclusterv1alpha1.ClusterSet {
	clusterSet := &multiclusterv1alpha1.ClusterSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "multicluster.crd.antrea.io/v1alpha1",
			Kind:       "ClusterSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: multiclusterv1alpha1.ClusterSetSpec{
			Leaders: []multiclusterv1alpha1.MemberCluster{
				{
					ClusterID: leaderClusterID,
				},
			},
			Namespace: namespace,
		},
	}
	if leaderServer != "" {
		clusterSet.Spec.Namespace = leaderNamespace
		clusterSet.Spec.Leaders[0].Secret = secret
		clusterSet.Spec.Leaders[0].Server = leaderServer
		clusterSet.Spec.Members = append(clusterSet.Spec.Members, multiclusterv1alpha1.MemberCluster{
			ClusterID: memberClusterID,
		})
	}

	return clusterSet
}

func newRoleBinding(name string, saName string, namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "antrea-mc-member-cluster-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: namespace,
			},
		},
	}
}

func newSecret(name string, saName string, namespace string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": saName,
				CreateByAntctlAnnotation:             "true",
			},
		},
		Type: "kubernetes.io/service-account-token",
	}
}

func newServiceAccount(name string, namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}
}

func OutputJoinConfig(cmd *cobra.Command, writer io.Writer, clusterSetID, leaderClusterID, leaderNamespace string) error {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}

	config := &ClusterSetJoinConfig{
		APIVersion:      ClusterSetJoinConfigAPIVersion,
		Kind:            ClusterSetJoinConfigKind,
		Namespace:       "",
		ClusterID:       "",
		LeaderClusterID: leaderClusterID,
		LeaderAPIServer: kubeconfig.Host,
		LeaderNamespace: leaderNamespace,
		ClusterSetID:    clusterSetID,
	}

	var writeErr error
	b, _ := yaml.Marshal(config)
	if _, writeErr = writer.Write([]byte("---\n")); writeErr != nil {
		return writeErr
	}
	if _, writeErr = writer.Write(b); writeErr != nil {
		return writeErr
	}

	// We comment out these ClusterSetJoinConfig fields in the generated
	// join config file, so they can be populated by command line options of
	// the "antctl mc join" command.
	optionalFields := `#clusterID: ""
#namespace: ""
# Use the pre-created token Secret.
#tokenSecretName: ""
# Create a token Secret with the manifest file.
#tokenSecretFile: ""
`
	if _, writeErr = writer.Write([]byte(optionalFields)); writeErr != nil {
		return writeErr
	}
	return nil
}

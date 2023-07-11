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
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	multiclusterscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestCreateClusterSet(t *testing.T) {
	tests := []struct {
		name               string
		expectedResLen     int
		existingClusterSet *mcv1alpha2.ClusterSet
	}{
		{
			name:           "create successfully",
			expectedResLen: 1,
		},
		{
			name:           "falied to create ClusterSet",
			expectedResLen: 0,
			existingClusterSet: &mcv1alpha2.ClusterSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "clusterset",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			createdRes := []map[string]interface{}{}
			fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).Build()
			if tt.existingClusterSet != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(tt.existingClusterSet).Build()
			}

			_ = CreateClusterSet(cmd, fakeClient, "default", "clusterset", "http://localhost", "token",
				"member-id", "leader-id", "leader-ns", &createdRes)

			assert.Equal(t, len(createdRes), tt.expectedResLen)
		})
	}
}

func TestDeleteClusterSet(t *testing.T) {
	existingClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset",
		},
	}
	tests := []struct {
		name               string
		expectedOutput     string
		existingClusterSet *mcv1alpha2.ClusterSet
	}{
		{
			name:               "delete successfully",
			expectedOutput:     "ClusterSet \"clusterset\" deleted in Namespace default\n",
			existingClusterSet: existingClusterSet,
		},
		{
			name:           "delete with not found error",
			expectedOutput: "ClusterSet \"clusterset\" not found in Namespace default\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).Build()
			if tt.existingClusterSet != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(tt.existingClusterSet).Build()
			}
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			deleteClusterSet(cmd, fakeClient, "default", "clusterset")

			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func TestDeleteSecrets(t *testing.T) {
	secret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "membertoken",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}
	secret2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "othertoken2",
		},
	}

	cmd := &cobra.Command{}
	fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(secret1, secret2).Build()
	buf := new(bytes.Buffer)
	cmd.SetOutput(buf)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	deleteSecrets(cmd, fakeClient, "default")

	assert.Equal(t, "Secret \"membertoken\" deleted in Namespace default\n", buf.String())
	remainSecrets := &corev1.SecretList{}
	fakeClient.List(context.Background(), remainSecrets, &client.ListOptions{})
	assert.Equal(t, 1, len(remainSecrets.Items))
}

func TestDeleteRoleBindings(t *testing.T) {
	rb1 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rb1",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}
	rb2 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "rb2",
		},
	}
	cmd := &cobra.Command{}
	fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(rb1, rb2).Build()
	buf := new(bytes.Buffer)
	cmd.SetOutput(buf)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	deleteRoleBindings(cmd, fakeClient, "default")

	assert.Equal(t, "RoleBinding \"rb1\" deleted in Namespace default\n", buf.String())
	remainRBs := &rbacv1.RoleBindingList{}
	fakeClient.List(context.Background(), remainRBs, &client.ListOptions{})
	assert.Equal(t, 1, len(remainRBs.Items))
}

func TestDeleteServiceAccounts(t *testing.T) {
	sa1 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "sa1",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}
	sa2 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "sa2",
		},
	}
	cmd := &cobra.Command{}
	fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(sa1, sa2).Build()
	buf := new(bytes.Buffer)
	cmd.SetOutput(buf)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	deleteServiceAccounts(cmd, fakeClient, "default")

	assert.Equal(t, "ServiceAccount \"sa1\" deleted in Namespace default\n", buf.String())
	remainSAs := &corev1.ServiceAccountList{}
	fakeClient.List(context.Background(), remainSAs, &client.ListOptions{})
	assert.Equal(t, 1, len(remainSAs.Items))
}

func TestCreateMemberToken(t *testing.T) {
	tests := []struct {
		name           string
		expectedResLen int
		expectedErr    string
		existingSecret *corev1.Secret
		existingSA     *corev1.ServiceAccount
		existingRB     *rbacv1.RoleBinding
	}{
		{
			name:           "create ServiceAccount and RoleBinding successfully",
			expectedResLen: 2,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
				Data: map[string][]byte{"token": []byte("12345")},
			},
		},
		{
			name:           "create RoleBinding successfully",
			expectedResLen: 1,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
				Data: map[string][]byte{"token": []byte("12345")},
			},
			existingSA: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
			},
		},
		{
			name:           "create successfully with all existing resources",
			expectedResLen: 0,
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
				Data: map[string][]byte{"token": []byte("12345")},
			},
			existingSA: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
			},
			existingRB: &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "membertoken",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			createdRes := []map[string]interface{}{}
			var obj []client.Object
			if tt.existingSA != nil {
				obj = append(obj, tt.existingSA)
			}
			if tt.existingRB != nil {
				obj = append(obj, tt.existingRB)
			}
			if tt.existingSecret != nil {
				obj = append(obj, tt.existingSecret)
			}
			fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(obj...).Build()
			_ = CreateMemberToken(cmd, fakeClient, "membertoken", "default", &createdRes)
			assert.Equal(t, tt.expectedResLen, len(createdRes))
		})
	}
}

func TestDeleteMemberToken(t *testing.T) {
	secretContent := []byte(`apiVersion: v1
kind: Secret
metadata:
  name: default-member-token
data:
  ca.crt: YWJjZAo=
  namespace: ZGVmYXVsdAo=
  token: YWJjZAo=
type: Opaque`)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
		Data: map[string][]byte{"token": secretContent},
	}

	existingSecretNoAnnotation := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
		},
		Data: map[string][]byte{"token": secretContent},
	}

	existingSecret1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token-1",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
		Data: map[string][]byte{"token": secretContent},
	}

	existingRolebinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}

	existingRolebinding1 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token-notexist",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}

	existingServiceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}

	existingServiceAccount1 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-member-token-notexist",
			Annotations: map[string]string{
				CreateByAntctlAnnotation: "true",
			},
		},
	}

	tests := []struct {
		name                 string
		namespace            string
		tokenName            string
		serviceAccount       *corev1.ServiceAccount
		rolebinding          *rbacv1.RoleBinding
		secret               *corev1.Secret
		numsOfServiceAccount int
		numsOfRolebinding    int
		numsOfSecret         int
		expectedOutput       string
	}{
		{
			name:                 "delete successfully",
			tokenName:            "default-member-token",
			namespace:            "default",
			secret:               existingSecret,
			rolebinding:          existingRolebinding,
			serviceAccount:       existingServiceAccount,
			numsOfServiceAccount: 0,
			numsOfRolebinding:    0,
			numsOfSecret:         0,
			expectedOutput:       "",
		},
		{
			name:                 "failed to delete because of wrong secret name",
			tokenName:            "default-member-token",
			namespace:            "default",
			secret:               existingSecret1,
			rolebinding:          existingRolebinding,
			serviceAccount:       existingServiceAccount,
			numsOfSecret:         1,
			numsOfRolebinding:    0,
			numsOfServiceAccount: 0,
			expectedOutput:       "Secret default-member-token not found in Namespace default",
		},
		{
			name:                 "failed to delete because of wrong rolebinding name",
			tokenName:            "default-member-token",
			namespace:            "default",
			secret:               existingSecret,
			rolebinding:          existingRolebinding1,
			serviceAccount:       existingServiceAccount,
			numsOfSecret:         0,
			numsOfRolebinding:    1,
			numsOfServiceAccount: 0,
			expectedOutput:       "RoleBinding default-member-token not found in Namespace default",
		},
		{
			name:                 "failed to delete because of wrong serviceaccount name",
			tokenName:            "default-member-token",
			namespace:            "default",
			secret:               existingSecret,
			rolebinding:          existingRolebinding,
			serviceAccount:       existingServiceAccount1,
			numsOfSecret:         0,
			numsOfRolebinding:    0,
			numsOfServiceAccount: 1,
			expectedOutput:       "ServiceAccount default-member-token not found in Namespace default",
		},
		{
			name:                 "the secret does not have the require annotation",
			tokenName:            "default-member-token",
			namespace:            "default",
			secret:               existingSecretNoAnnotation,
			rolebinding:          existingRolebinding,
			serviceAccount:       existingServiceAccount,
			numsOfServiceAccount: 0,
			numsOfRolebinding:    0,
			numsOfSecret:         1,
			expectedOutput:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			fakeClient := fake.NewClientBuilder().WithScheme(multiclusterscheme.Scheme).WithObjects(tt.secret, tt.rolebinding, tt.serviceAccount).Build()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			DeleteMemberToken(cmd, fakeClient, tt.tokenName, tt.namespace)

			assert.Contains(t, buf.String(), tt.expectedOutput)

			remainSecrets := &corev1.SecretList{}
			fakeClient.List(context.Background(), remainSecrets, &client.ListOptions{})
			assert.Equal(t, tt.numsOfSecret, len(remainSecrets.Items))
			remainRoleBinding := &rbacv1.RoleBindingList{}
			fakeClient.List(context.Background(), remainRoleBinding, &client.ListOptions{})
			assert.Equal(t, tt.numsOfRolebinding, len(remainRoleBinding.Items))
			remainServiceAccount := &corev1.ServiceAccountList{}
			fakeClient.List(context.Background(), remainServiceAccount, &client.ListOptions{})
			assert.Equal(t, tt.numsOfServiceAccount, len(remainServiceAccount.Items))
		})
	}
}

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

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// rollbackActionRestoreAnnotation marks a createdRes entry that records a
// mutation of a pre-existing object: Rollback restores it instead of deleting
// the object, which outlives the command that mutated it.
const rollbackActionRestoreAnnotation = "restoreAnnotation"

func Rollback(cmd *cobra.Command, k8sClient client.Client, res []map[string]interface{}) error {
	for _, obj := range res {
		u := &unstructured.Unstructured{Object: obj}
		if action, _, _ := unstructured.NestedString(obj, "rollbackAction"); action == rollbackActionRestoreAnnotation {
			if err := restoreAnnotation(cmd, k8sClient, obj, u); err != nil {
				return err
			}
			continue
		}
		if err := k8sClient.Delete(context.TODO(), u); err != nil && !apierrors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete %s %s/%s: %v\n", u.GetKind(), u.GetNamespace(), u.GetName(), err)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s \"%s/%s\" deleted\n", u.GetKind(), u.GetNamespace(), u.GetName())
	}
	return nil
}

func restoreAnnotation(cmd *cobra.Command, k8sClient client.Client, obj map[string]interface{}, u *unstructured.Unstructured) error {
	key, _, _ := unstructured.NestedString(obj, "annotationKey")
	value, _, _ := unstructured.NestedString(obj, "annotationValue")
	sa := &corev1.ServiceAccount{}
	if err := k8sClient.Get(context.TODO(), types.NamespacedName{Namespace: u.GetNamespace(), Name: u.GetName()}, sa); err != nil {
		if apierrors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "ServiceAccount \"%s/%s\" no longer exists; nothing to restore\n", u.GetNamespace(), u.GetName())
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to get ServiceAccount \"%s/%s\": %v\n", u.GetNamespace(), u.GetName(), err)
		return err
	}
	if sa.Annotations == nil {
		sa.Annotations = map[string]string{}
	}
	sa.Annotations[key] = value
	if err := k8sClient.Update(context.TODO(), sa); err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Failed to restore ClusterID binding on ServiceAccount \"%s/%s\": %v\n", u.GetNamespace(), u.GetName(), err)
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Restored ClusterID binding %q on ServiceAccount \"%s/%s\"\n", value, u.GetNamespace(), u.GetName())
	return nil
}

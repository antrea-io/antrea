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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Rollback(cmd *cobra.Command, k8sClient client.Client, res []map[string]interface{}) error {
	for _, obj := range res {
		u := &unstructured.Unstructured{Object: obj}
		if err := k8sClient.Delete(context.TODO(), u); err != nil && !apierrors.IsNotFound(err) {
			fmt.Fprintf(cmd.OutOrStdout(), "Failed to delete %s %s/%s: %v\n", u.GetKind(), u.GetNamespace(), u.GetName(), err)
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s \"%s/%s\" deleted\n", u.GetKind(), u.GetNamespace(), u.GetName())
	}
	return nil
}

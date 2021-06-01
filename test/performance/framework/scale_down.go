// Copyright 2021 Antrea Authors
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

package framework

import (
	"context"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

// ScaleDown delete pods/ns and verify if it gets deleted
func (data *ScaleData) ScaleDown(ctx context.Context) error {
	allNS, err := data.kubernetesClientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var nssToDelete []string
	for i := range allNS.Items {
		toDeleteNs := allNS.Items[i]
		if !strings.HasPrefix(toDeleteNs.Name, ScaleTestNamespacePrefix) {
			continue
		}
		nssToDelete = append(nssToDelete, toDeleteNs.Name)
		if err := data.kubernetesClientSet.CoreV1().Namespaces().Delete(ctx, toDeleteNs.Name, metav1.DeleteOptions{}); err != nil {
			klog.InfoS("Delete namespace", "Name", toDeleteNs.Name)
			return err
		}
	}
	return wait.PollImmediate(10*time.Second, 1*time.Minute, func() (done bool, err error) {
		count := 0
		for _, ns := range nssToDelete {
			if err := data.kubernetesClientSet.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{}); errors.IsNotFound(err) {
				count++
			}
		}
		klog.InfoS("Waiting for clean up namespaces", "all", len(nssToDelete), "count", count)
		return count == len(nssToDelete), nil
	})
}

// ScaleDownOnlyPods delete pods only so it will get recreated inside same ns
func (data *ScaleData) ScaleDownOnlyPods(ctx context.Context) error {
	return nil
}

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

package namespace

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func ScaleUp(ctx context.Context, cs kubernetes.Interface, nsPrefix string, nsNum int) (nss []string, err error) {
	klog.Infof("Creating scale test namespaces")
	for i := 0; i < nsNum; i++ {
		nsToCreate := fmt.Sprintf("%s-%d", nsPrefix, i)
		if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsToCreate}}, metav1.CreateOptions{}); err != nil {
			return nss, err
		}
		nss = append(nss, nsToCreate)
		klog.InfoS("Create Namespace", "name", nsToCreate)
	}
	return nss, nil
}

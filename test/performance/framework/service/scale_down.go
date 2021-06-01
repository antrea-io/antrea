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

package service

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func ScaleDown(ctx context.Context, svcs []ServiceInfo, cs kubernetes.Interface) error {
	for _, svc := range svcs {
		if err := cs.CoreV1().Services(svc.NameSpace).Delete(ctx, svc.Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
		klog.V(2).InfoS("Deleted service", "serviceName", svc)
	}
	return wait.PollImmediate(10*time.Second, 1*time.Minute, func() (done bool, err error) {
		count := 0
		for _, svc := range svcs {
			if err := cs.CoreV1().Services(svc.NameSpace).Delete(ctx, svc.Name, metav1.DeleteOptions{}); errors.IsNotFound(err) {
				count++
			}
		}
		klog.InfoS("Scale down Services", "Services", len(svcs), "cleanedUpCount", count)
		return count == len(svcs), nil
	})
}

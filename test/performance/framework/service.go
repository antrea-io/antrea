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

//goland:noinspection ALL
import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/framework/service"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleService", ScaleService)
	RegisterFunc("ScaleServiceDemo", ScaleServiceDemo)
}

func ScaleService(ctx context.Context, data *ScaleData) error {
	svcs, err := service.ScaleUp(ctx, data.kubernetesClientSet, data.namespaces, data.Specification.SvcNumPerNs, data.Specification.IPv6)
	if err != nil {
		return fmt.Errorf("scale up services error: %v", err)
	}

	maxSvcCheckedCount := data.nodesNum

	start := time.Now()
	for i := range svcs {
		if utils.CheckTimeout(start, data.checkTimeout) || i > maxSvcCheckedCount {
			klog.InfoS("Services check deadline exceeded", "count", i)
			break
		}
		k := int(utils.GenRandInt()) % len(data.clientPods)
		clientPod := data.clientPods[k]
		svc := svcs[i]
		if err := PingIP(ctx, data.kubeconfig, data.kubernetesClientSet, &clientPod, svc.IP); err != nil {
			klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name, "svc", svc)
			return err
		}
		klog.V(2).InfoS("Check service", "svc", svc, "Pod", clientPod.Name)
	}

	if err := service.ScaleDown(ctx, svcs, data.kubernetesClientSet); err != nil {
		return fmt.Errorf("scale down svcs error %v", err)
	}
	return nil
}

func ScaleServiceDemo(ctx context.Context, data *ScaleData) error {
	list, err := data.kubernetesClientSet.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	klog.InfoS("List all test namespace", "namespacesNum", len(list.Items))
	klog.V(2).InfoS("level 2 log")
	klog.V(1).InfoS("level 1 log")
	return nil
}

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework/service"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleService", ScaleService)
	RegisterFunc("ScaleServiceDemo", ScaleServiceDemo)
}

func ScaleService(ctx context.Context, data *ScaleData) error {
	// Service numbers based on the Node number.
	svcNum := data.Specification.SvcNumPerNode * data.nodesNum
	svcs, err := service.ScaleUp(ctx, svcNum, data.kubernetesClientSet, ScaleTestNamespacePrefix, data.Specification.IPv6)
	if err != nil {
		return fmt.Errorf("scale up services error: %v", err)
	}

	// Check services is ready
	for i := range data.clientPods {
		clientPod := data.clientPods[i]
		readySvcs := sets.String{}
		err := utils.DefaultRetry(func() error {
			return wait.PollImmediateUntil(config.WaitInterval, func() (bool, error) {
				if readySvcs.Len() == len(svcs) {
					return true, nil
				}
				for _, svc := range svcs {
					svcKey := fmt.Sprintf("%s_%s", svc.NameSpace, svc.Name)
					if _, ok := readySvcs[svcKey]; ok { // Skip the service if it is verified.
						continue
					}
					if err := PingIP(data.kubeconfig, data.kubernetesClientSet, &clientPod, svc.IP); err != nil {
						return false, err
					}
					klog.V(2).InfoS("Check service", "svc", svc, "Pod", clientPod.Name)
					readySvcs.Insert(svcKey)
				}
				return readySvcs.Len() == len(svcs), nil
			}, ctx.Done())
		})
		if err != nil {
			klog.ErrorS(err, "Check readiness of service error", "ClientPodName", clientPod.Name)
			return err
		}
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

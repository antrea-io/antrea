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
	"time"

	appv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleRestartAgent", ScaleRestartAgent)
	RegisterFunc("RestartController", RestartController)
	RegisterFunc("RestartOVSContainer", RestartOVSContainer)
}

func ScaleRestartAgent(ctx context.Context, data *ScaleData) error {
	err := data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).
		DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-agent"})
	if err != nil {
		return err
	}
	time.Sleep(3 * time.Second)
	return wait.PollImmediateUntil(time.Second, func() (bool, error) {
		var ds *appv1.DaemonSet
		if err := utils.DefaultRetry(func() error {
			var err error
			ds, err = data.kubernetesClientSet.
				AppsV1().DaemonSets(metav1.NamespaceSystem).
				Get(ctx, "antrea-agent", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		return ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable, nil
	}, ctx.Done())
}

func RestartController(ctx context.Context, data *ScaleData) error {
	err := data.kubernetesClientSet.CoreV1().Pods(metav1.NamespaceSystem).
		DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app=antrea,component=antrea-controller"})
	if err != nil {
		return err
	}
	time.Sleep(3 * time.Second)
	return wait.PollImmediateUntil(time.Second, func() (bool, error) {
		var dp *appv1.Deployment
		if err := utils.DefaultRetry(func() error {
			var err error
			dp, err = data.kubernetesClientSet.AppsV1().Deployments(metav1.NamespaceSystem).Get(ctx, "antrea-controller", metav1.GetOptions{})
			return err
		}); err != nil {
			return false, err
		}
		return dp.Status.UnavailableReplicas == 0, nil
	}, ctx.Done())
}

func RestartOVSContainer(ctx context.Context, data *ScaleData) error {
	return ScaleRestartAgent(ctx, data)
}

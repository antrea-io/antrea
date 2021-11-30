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
	"fmt"
	"time"

	"golang.org/x/time/rate"

	"antrea.io/antrea/test/performance/framework/networkpolicy"
	"antrea.io/antrea/test/performance/utils"
)

func init() {
	RegisterFunc("ScaleNetworkPolicy", ScaleNetworkPolicy)
}

func ScaleNetworkPolicy(ctx context.Context, data *ScaleData) error {
	npNum := data.Specification.NpNumPerNode * data.nodesNum

	// ScaleUp networkPolicies
	nps, err := networkpolicy.ScaleUp(ctx, npNum, data.kubernetesClientSet, data.namespaces, data.Specification.IPv6)
	if err != nil {
		return fmt.Errorf("scale up NetworkPolicies error: %v", err)
	}

	retryWithRateLimiter := func(ctx context.Context, rateLimiter *rate.Limiter, f func() error) error {
		rateLimiter.Wait(ctx)
		return utils.DefaultRetry(f)
	}

	baseIndex := 1
	if len(nps) > 600 {
		baseIndex = len(nps) / 600
	}
	start := time.Now()
	for _, ns := range data.namespaces {
		// Check connection of Pods in NetworkPolicies, workload Pods
		rateLimiter := rate.NewLimiter(rate.Limit(10*len(data.clientPods)), len(data.clientPods)*20)
		for i, np := range nps {
			if utils.CheckTimeout(start, data.checkTimeout) {
				break
			}
			if i%baseIndex != 0 {
				continue
			}
			fromPod, ip, err := networkpolicy.SelectConnectPod(ctx, data.kubernetesClientSet, ns, np)
			if err != nil || fromPod == nil || ip == "" {
				continue
			}
			if err := retryWithRateLimiter(ctx, rateLimiter, func() error {
				if err := PingIP(data.kubeconfig, data.kubernetesClientSet, fromPod, ip); err != nil {
					return fmt.Errorf("the connection should be success, NetworkPolicyName: %s, FromPod: %s, ToPod: %s",
						np.Name, fromPod.Name, ip)
				}
				return nil
			}); err != nil {
				return err
			}
		}

		// Check isolation of Pods in NetworkPolicies, client Pods to workload Pods
		for i, np := range nps {
			if utils.CheckTimeout(start, data.checkTimeout) {
				break
			}
			if i%baseIndex != 0 {
				continue
			}
			fromPod, ip, err := networkpolicy.SelectIsoPod(ctx, data.kubernetesClientSet, ns, np, data.clientPods)
			if err != nil || fromPod == nil || ip == "" {
				continue
			}
			if err := retryWithRateLimiter(ctx, rateLimiter, func() error {
				if err := PingIP(data.kubeconfig, data.kubernetesClientSet, fromPod, ip); err == nil {
					return fmt.Errorf("the connection should not be success, NetworkPolicyName: %s, FromPod: %s, ToPodIP: %s", np.Name, fromPod.Name, ip)
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}

	if err := networkpolicy.ScaleDown(ctx, data.namespaces, data.kubernetesClientSet); err != nil {
		return err
	}
	return nil
}

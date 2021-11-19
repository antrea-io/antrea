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

package networkpolicy

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
)

// ScaleDown clean up NetworkPolicies in the namespaces list nss
func ScaleDown(ctx context.Context, nss []string, cs kubernetes.Interface) error {
	for _, ns := range nss {
		if err := cs.NetworkingV1().NetworkPolicies(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
			klog.ErrorS(err, "Deleted NetworkPolicies error", "namespace", ns)
			return err
		}
		klog.V(2).InfoS("Deleted NetworkPolicies", "namespace", ns)
	}

	return wait.PollImmediateUntil(config.WaitInterval, func() (done bool, err error) {
		cleanCount := 0
		staleNpNum := 0
		for _, ns := range nss {
			staleNpNum = 0
			nps, err := cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}
			if len(nps.Items) == 0 {
				cleanCount++
				continue
			}
			staleNpNum += len(nps.Items)
			if err := cs.NetworkingV1().NetworkPolicies(ns).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{}); err != nil {
				return false, err
			}
		}
		klog.InfoS("Scale down NetworkPolicies", "allNamespaces", nss, "cleanedCount", cleanCount, "staleNpNum", staleNpNum)
		return cleanCount == len(nss), nil
	}, ctx.Done())
}

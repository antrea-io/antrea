// Copyright 2020 Antrea Authors
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

// Package networkpolicy provides NetworkPolicyController implementation to manage
// and synchronize the Pods and Namespaces affected by Network Policies and enforce
// their rules.
package networkpolicy

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var (
	// maxSupportedTiers is the soft limit on the maximum number of supported
	// Tiers.
	maxSupportedTiers = 20

	// defaultTierName maintains the name of the default Tier in Antrea.
	defaultTierName = "application"
	// emergencyTierName maintains the name of the Emergency Tier in Antrea.
	emergencyTierName   = "emergency"
	securityOpsTierName = "securityops"
	networkOpsTierName  = "networkops"
	platformTierName    = "platform"
	baselineTierName    = "baseline"
	// priorityMap maintains the Tier priority associated with system generated
	// Tier names.
	priorityMap = map[string]int32{
		baselineTierName:    secv1beta1.BaselineTierPriority,
		defaultTierName:     secv1beta1.DefaultTierPriority,
		platformTierName:    int32(200),
		networkOpsTierName:  int32(150),
		securityOpsTierName: int32(100),
		emergencyTierName:   int32(50),
	}
	// staticTierSet maintains the names of the static tiers such that they can
	// be converted to corresponding Tier CRD names.
	staticTierSet = sets.New[string]("Emergency", "SecurityOps", "NetworkOps", "Platform", "Application", "Baseline")
	// systemGeneratedTiers are the Tier CRs to be created at init.
	systemGeneratedTiers = []*secv1beta1.Tier{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: baselineTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[baselineTierName],
				Description: "[READ-ONLY]: System generated Baseline Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[defaultTierName],
				Description: "[READ-ONLY]: System generated default Application Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: platformTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[platformTierName],
				Description: "[READ-ONLY]: System generated Platform Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: networkOpsTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[networkOpsTierName],
				Description: "[READ-ONLY]: System generated NetworkOps Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: securityOpsTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[securityOpsTierName],
				Description: "[READ-ONLY]: System generated SecurityOps Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: emergencyTierName,
			},
			Spec: secv1beta1.TierSpec{
				Priority:    priorityMap[emergencyTierName],
				Description: "[READ-ONLY]: System generated Emergency Tier",
			},
		},
	}
)

// InitializeTiers initializes the default Tiers created by Antrea on init. It
// will first attempt to retrieve the Tier by it's name from K8s and if missing,
// create the CR. InitializeTiers will be called as part of a Post-Start hook
// of antrea-controller's APIServer.
func (n *NetworkPolicyController) InitializeTiers(ctx context.Context) error {
	if !cache.WaitForCacheSync(ctx.Done(), n.tierListerSynced) {
		// This happens when Done is closed because we are shutting down.
		return fmt.Errorf("caches not synced for system Tier initialization")
	}
	for _, t := range systemGeneratedTiers {
		if err := n.initializeTier(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

func (n *NetworkPolicyController) initializeTier(ctx context.Context, t *secv1beta1.Tier) error {
	// Tier creation or update may fail because antrea APIService is not yet ready to accept
	// requests for validation. We will keep retrying until it succeeds, using an exponential
	// backoff (not exceeding 8s), unless the context is cancelled.
	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2.0,
		Jitter:   0.0,
		Steps:    3, // max duration of 8s
	}
	retryAttempt := 1
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if success := func() bool {
			// Check if Tier is already present.
			if oldTier, err := n.tierLister.Get(t.Name); err == nil {
				// Tier is already present.
				klog.V(2).InfoS("Tier already exists", "tier", klog.KObj(t))
				// Update Tier Priority if it is not set to desired Priority.
				expPrio := t.Spec.Priority
				if oldTier.Spec.Priority == expPrio {
					return true
				}
				tToUpdate := oldTier.DeepCopy()
				tToUpdate.Spec.Priority = expPrio
				if err := n.updateTier(ctx, tToUpdate); err != nil {
					klog.InfoS("Failed to update system Tier on init, will retry", "tier", klog.KObj(t), "attempts", retryAttempt, "err", err)
					return false
				}
				return true
			}
			if err := n.createTier(ctx, t); err != nil {
				// Error may be that the Tier already exists, in this case, we will
				// call tierLister.Get again and compare priorities.
				klog.InfoS("Failed to create system Tier on init, will retry", "tier", klog.KObj(t), "attempts", retryAttempt, "err", err)
				return false
			}
			return true
		}(); success {
			break
		}
		retryAttempt += 1
		waitBeforeRetry := backoff.Step()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitBeforeRetry):
		}
	}
	return nil
}

func (n *NetworkPolicyController) createTier(ctx context.Context, t *secv1beta1.Tier) error {
	klog.V(2).InfoS("Creating system Tier", "tier", klog.KObj(t))
	if _, err := n.crdClient.CrdV1beta1().Tiers().Create(ctx, t, metav1.CreateOptions{}); err != nil {
		return err
	}
	klog.InfoS("Created system Tier", "tier", klog.KObj(t))
	return nil
}

func (n *NetworkPolicyController) updateTier(ctx context.Context, t *secv1beta1.Tier) error {
	klog.V(2).InfoS("Updating system Tier", "tier", klog.KObj(t))
	if _, err := n.crdClient.CrdV1beta1().Tiers().Update(ctx, t, metav1.UpdateOptions{}); err != nil {
		return err
	}
	klog.InfoS("Updated system Tier", "tier", klog.KObj(t))
	return nil
}

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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
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
func (n *NetworkPolicyController) InitializeTiers() {
	for _, t := range systemGeneratedTiers {
		// Check if Tier is already present.
		oldTier, err := n.tierLister.Get(t.Name)
		if err == nil {
			// Tier is already present.
			klog.V(2).Infof("%s Tier already created", t.Name)
			// Update Tier Priority if it is not set to desired Priority.
			expPrio := priorityMap[t.Name]
			if oldTier.Spec.Priority != expPrio {
				tToUpdate := oldTier.DeepCopy()
				tToUpdate.Spec.Priority = expPrio
				n.updateTier(tToUpdate)
			}
			continue
		}
		n.initTier(t)
	}
}

// initTier attempts to create system Tiers until they are created using an
// exponential backoff period from 1 to max of 8secs.
func (n *NetworkPolicyController) initTier(t *secv1beta1.Tier) {
	var err error
	const maxBackoffTime = 8 * time.Second
	backoff := 1 * time.Second
	retryAttempt := 1
	for {
		klog.V(2).InfoS("Creating system Tier", "tier", t.Name)
		_, err = n.crdClient.CrdV1beta1().Tiers().Create(context.TODO(), t, metav1.CreateOptions{})
		// Attempt to recreate Tier after a backoff only if it does not exist.
		if err != nil {
			if errors.IsAlreadyExists(err) {
				klog.InfoS("System Tier already exists", "tier", t.Name)
				return
			}
			klog.InfoS("Failed to create system Tier on init, will retry", "tier", t.Name, "attempts", retryAttempt, "err", err)
			// Tier creation may fail because antrea APIService is not yet ready
			// to accept requests for validation. Retry fixed number of times
			// not exceeding 8s.
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoffTime {
				backoff = maxBackoffTime
			}
			retryAttempt += 1
			continue
		}
		klog.InfoS("Created system Tier", "tier", t.Name)
		return
	}
}

// updateTier attempts to update Tiers using an
// exponential backoff period from 1 to max of 8secs.
func (n *NetworkPolicyController) updateTier(t *secv1beta1.Tier) {
	var err error
	const maxBackoffTime = 8 * time.Second
	backoff := 1 * time.Second
	retryAttempt := 1
	for {
		klog.V(2).Infof("Updating %s Tier", t.Name)
		_, err = n.crdClient.CrdV1beta1().Tiers().Update(context.TODO(), t, metav1.UpdateOptions{})
		// Attempt to update Tier after a backoff.
		if err != nil {
			klog.Warningf("Failed to update %s Tier on init: %v. Retry attempt: %d", t.Name, err, retryAttempt)
			// Tier update may fail because antrea APIService is not yet ready
			// to accept requests for validation. Retry fixed number of times
			// not exceeding 8s.
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoffTime {
				backoff = maxBackoffTime
			}
			retryAttempt += 1
			continue
		}
		return
	}
}

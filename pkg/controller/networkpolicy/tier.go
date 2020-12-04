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
	"k8s.io/klog"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

var (
	// maxSupportedTiers is the soft limit on the maximum number of supported
	// Tiers.
	maxSupportedTiers = 20
	// DefaultTierPriority maintains the priority for the system generated default Tier.
	// This is the lowest priority for tiers that will be enforced before K8s NetworkPolicies.
	DefaultTierPriority = int32(250)
	// BaselineTierPriority maintains the priority for the system generated baseline Tier.
	// This is the tier that will be enforced after K8s NetworkPolicies.
	BaselineTierPriority = int32(253)
	// defaultTierName maintains the name of the default Tier in Antrea.
	defaultTierName = "application"
	// priorityMap maintains the Tier priority associated with system generated
	// Tier names.
	priorityMap = map[string]int32{
		"baseline":      BaselineTierPriority,
		defaultTierName: DefaultTierPriority,
		"platform":      int32(150),
		"networkops":    int32(100),
		"securityops":   int32(50),
		"emergency":     int32(5),
	}
	// staticTierSet maintains the names of the static tiers such that they can
	// be converted to corresponding Tier CRD names.
	staticTierSet = sets.NewString("Emergency", "SecurityOps", "NetworkOps", "Platform", "Application", "Baseline")
	// systemGeneratedTiers are the Tier CRs to be created at init.
	systemGeneratedTiers = []*secv1alpha1.Tier{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "baseline",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["baseline"],
				Description: "[READ-ONLY]: System generated Baseline Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultTierName,
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap[defaultTierName],
				Description: "[READ-ONLY]: System generated default Application Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "platform",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["platform"],
				Description: "[READ-ONLY]: System generated Platform Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "networkops",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["networkops"],
				Description: "[READ-ONLY]: System generated NetworkOps Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "securityops",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["securityops"],
				Description: "[READ-ONLY]: System generated SecurityOps Tier",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "emergency",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["emergency"],
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
		_, err := n.tierLister.Get(t.Name)
		if err == nil {
			// Tier is already present.
			klog.V(2).Infof("%s Tier already created", t.Name)
			continue
		}
		n.initTier(t)
	}
}

// initTier attempts to create system Tiers until they are created using an
// exponential backoff period from 1 to max of 8secs.
func (n *NetworkPolicyController) initTier(t *secv1alpha1.Tier) {
	var err error
	const maxBackoffTime = 8 * time.Second
	backoff := 1 * time.Second
	retryAttempt := 1
	for {
		klog.V(2).Infof("Creating %s Tier", t.Name)
		_, err = n.crdClient.SecurityV1alpha1().Tiers().Create(context.TODO(), t, metav1.CreateOptions{})
		// Attempt to recreate Tier after a backoff only if it does not exist.
		if err != nil && !errors.IsAlreadyExists(err) {
			klog.Warningf("Failed to create %s Tier on init: %v. Retry attempt: %d", t.Name, err, retryAttempt)
			// Tier creation may fail because antrea APIService is not yet ready
			// to accept requests for validation. Retry fixed number of times
			// not exceeding 2 * 5 = 10s.
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

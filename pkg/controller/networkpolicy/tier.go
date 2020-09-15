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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

var (
	// maxSupportedTiers is the soft limit on the maximum number of supported
	// Tiers.
	maxSupportedTiers = 50
	// retryInitTier maintains the number of times Tier creation will be attempted
	// for default Tiers during initialization.
	retryInitTier     = 5
	retryInitInterval = 2 * time.Second
	// defaultTierPriority maintains the lowest priority for the system generated
	// default Tier.
	defaultTierPriority = int32(250)
	// priorityMap maintains the Tier priority associated with system generated
	// Tier names.
	priorityMap = map[string]int32{
		"application": defaultTierPriority,
		"platform":    int32(150),
		"networkops":  int32(100),
		"securityops": int32(50),
		"emergency":   int32(5),
	}
	// staticTierSet maintains the names of the static tiers such that they can
	// be converted to corresponding Tier CRD names.
	staticTierSet = sets.NewString("Emergency", "SecurityOps", "NetworkOps", "Platform", "Application")
	// systemGeneratedTiers are the Tier CRs to be created at init.
	systemGeneratedTiers = []*secv1alpha1.Tier{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "application",
			},
			Spec: secv1alpha1.TierSpec{
				Priority:    priorityMap["application"],
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
		err = n.initTier(t)
		if err != nil {
			// System generated Tiers were not initialized within an acceptable delay.
			klog.Errorf("Failed to create system Tier %s on init", t.Name)
		}
	}
}

func (n *NetworkPolicyController) initTier(t *secv1alpha1.Tier) error {
	var err error
	for i := 1; i <= retryInitTier; i++ {
		// Allow APIServer to start and accept requests for Tier CREATE validation.
		time.Sleep(retryInitInterval)
		klog.V(2).Infof("Creating %s Tier", t.Name)
		_, err = n.crdClient.SecurityV1alpha1().Tiers().Create(context.TODO(), t, metav1.CreateOptions{})
		if err != nil {
			klog.Warningf("Failed to create %s Tier on init: %v. Retry attempt: %d", t.Name, err, i)
			// Tier creation may fail because antrea APIService is not yet ready
			// to accept requests for validation. Retry fixed number of times
			// not exceeding 2 * 5 = 10s.
			continue
		}
		return nil
	}
	return err
}

// addTier receives Tier ADD events and updates the TierPrioritySet.
func (n *NetworkPolicyController) addTier(obj interface{}) {
	t := obj.(*secv1alpha1.Tier)
	klog.V(2).Infof("Processing Tier %s ADD event", t.Name)
	// Insert Tier's Priority in the unique set.
	n.tierPrioritySet.Insert(t.Spec.Priority)
}

// updateTier receives Tier UPDATE events and updates the TierPrioritySet.
func (n *NetworkPolicyController) updateTier(oldObj, curObj interface{}) {
	curT := curObj.(*secv1alpha1.Tier)
	klog.V(2).Infof("Processing Tier %s UPDATE event", curT.Name)
	// Insert Tier's Priority in the unique set.
	n.tierPrioritySet.Insert(curT.Spec.Priority)
}

// deleteTier receives Tier DELETE events and updates the TierPrioritySet.
func (n *NetworkPolicyController) deleteTier(old interface{}) {
	t := old.(*secv1alpha1.Tier)
	klog.V(2).Infof("Processing Tier %s DELETE event", t.Name)
	// Remove Tier's Priority from the unique set.
	n.tierPrioritySet.Delete(t.Spec.Priority)
}

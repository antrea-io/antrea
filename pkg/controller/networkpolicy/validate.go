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

package networkpolicy

import (
	"encoding/json"
	"fmt"
	"strconv"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

var (
	// reservedTierPriorities stores the reserved priority range from 251, 252, 254 and 255.
	// The priority 250 is reserved for default Tier but not part of this set in order to be
	// able to create the Tier by Antrea. Same for priority 253 which is reserved for the
	// baseline tier.
	reservedTierPriorities = sets.NewInt32(int32(251), int32(252), int32(254), int32(255))
	// reservedTierNames stores the set of Tier names which cannot be deleted
	// since they are created by Antrea.
	reservedTierNames = sets.NewString("baseline", "application", "platform", "networkops", "securityops", "emergency")
)

type NetworkPolicyValidator struct {
	networkPolicyController *NetworkPolicyController
}

// NewNetworkPolicyValidator returns a new *NetworkPolicyValidator.
func NewNetworkPolicyValidator(networkPolicyController *NetworkPolicyController) *NetworkPolicyValidator {
	return &NetworkPolicyValidator{
		networkPolicyController: networkPolicyController,
	}
}

// Validate function validates a Tier or Antrea Policy object
func (v *NetworkPolicyValidator) Validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := false
	op := ar.Request.Operation
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw
	switch ar.Request.Kind.Kind {
	case "Tier":
		klog.V(2).Info("Validating Tier CRD")
		var curTier, oldTier secv1alpha1.Tier
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curTier); err != nil {
				klog.Errorf("Error de-serializing current Tier")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldTier); err != nil {
				klog.Errorf("Error de-serializing old Tier")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateTier(&curTier, &oldTier, op)
	case "ClusterNetworkPolicy":
		klog.V(2).Info("Validating Antrea ClusterNetworkPolicy CRD")
		var curCNP, oldCNP secv1alpha1.ClusterNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curCNP); err != nil {
				klog.Errorf("Error de-serializing current Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldCNP); err != nil {
				klog.Errorf("Error de-serializing old Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaPolicy(op, curCNP.Spec.Tier, curCNP.Spec.Ingress, curCNP.Spec.Egress)
	case "NetworkPolicy":
		klog.V(2).Info("Validating Antrea NetworkPolicy CRD")
		var curANP, oldANP secv1alpha1.NetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curANP); err != nil {
				klog.Errorf("Error de-serializing current Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldANP); err != nil {
				klog.Errorf("Error de-serializing old Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaPolicy(op, curANP.Spec.Tier, curANP.Spec.Ingress, curANP.Spec.Egress)
	}
	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}

// validateAntreaPolicy validates the admission of a Antrea NetworkPolicy CRDs
func (v *NetworkPolicyValidator) validateAntreaPolicy(op admv1.Operation, tier string, ingress, egress []secv1alpha1.Rule) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create, admv1.Update:
		if isUnique := v.validateRuleName(ingress, egress); !isUnique {
			allowed = false
			reason = "rules names are not unique, or policy has duplicate rules, or collision occurred in generated rule names"
			break
		}
		// "tier" must exist before referencing.
		if tier == "" || staticTierSet.Has(tier) {
			// Empty Tier name corresponds to default Tier
			break
		}
		if ok := v.tierExists(tier); !ok {
			allowed = false
			reason = fmt.Sprintf("tier %s does not exist", tier)
		}
	case admv1.Delete:
		// Delete of Antrea Policies have no validation
		allowed = true
	}
	return reason, allowed
}

// validateRuleName validates if the name of each rule is unique within a policy
func (v *NetworkPolicyValidator) validateRuleName(ingress, egress []secv1alpha1.Rule) bool {
	uniqueRuleName := sets.NewString()
	isUnique := func(rules []secv1alpha1.Rule) bool {
		for _, rule := range rules {
			if uniqueRuleName.Has(rule.Name) {
				return false
			}
			uniqueRuleName.Insert(rule.Name)
		}
		return true
	}
	return isUnique(ingress) && isUnique(egress)
}

// validateTier validates the admission of a Tier resource
func (v *NetworkPolicyValidator) validateTier(curTier, oldTier *secv1alpha1.Tier, op admv1.Operation) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for Tier")
		if len(v.networkPolicyController.tierInformer.Informer().GetIndexer().ListIndexFuncValues(PriorityIndex)) >= maxSupportedTiers {
			return fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers), false
		}
		// Tier priority must not overlap reserved tier's priority
		if reservedTierPriorities.Has(curTier.Spec.Priority) {
			return fmt.Sprintf("tier %s priority %d is reserved", curTier.Name, curTier.Spec.Priority), false
		}
		// Tier priority must not overlap existing tier's priority
		trs, err := v.networkPolicyController.tierInformer.Informer().GetIndexer().ByIndex(PriorityIndex, strconv.FormatInt(int64(curTier.Spec.Priority), 10))
		if err != nil || len(trs) > 0 {
			return fmt.Sprintf("tier %s priority %d overlaps with existing Tier", curTier.Name, curTier.Spec.Priority), false
		}
	case admv1.Update:
		// Tier priority updates are not allowed
		klog.V(2).Info("Validating UPDATE request for Tier")
		if curTier.Spec.Priority != oldTier.Spec.Priority {
			allowed = false
			reason = "update to Tier priority is not allowed"
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for Tier")
		if reservedTierNames.Has(oldTier.Name) {
			reason = fmt.Sprintf("cannot delete reserved tier %s", oldTier.Name)
			return reason, false
		}
		// Tier with existing ACNPs/ANPs cannot be deleted
		cnps, err := v.networkPolicyController.cnpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
		if err != nil || len(cnps) > 0 {
			reason = fmt.Sprintf("tier %s is referenced by %d Antrea ClusterNetworkPolicies", oldTier.Name, len(cnps))
			return reason, false
		}
		anps, err := v.networkPolicyController.anpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
		if err != nil || len(anps) > 0 {
			reason = fmt.Sprintf("tier %s is referenced by %d Antrea NetworkPolicies", oldTier.Name, len(anps))
			return reason, false
		}
	}
	return reason, allowed
}

func (v *NetworkPolicyValidator) tierExists(name string) bool {
	_, err := v.networkPolicyController.tierLister.Get(name)
	if err != nil {
		return false
	}
	return true
}

// GetAdmissionResponseForErr returns an object of type AdmissionResponse with
// the submitted error message.
func GetAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	if err == nil {
		return nil
	}
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

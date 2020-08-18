// Copyright 2019 Antrea Authors
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
	"io/ioutil"
	"net/http"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

var (
	// reservedTierPriorities stores the reserved priority range from 251-255.
	// The priority 250 is reserved for default Tier but not part of this set in
	// order to be able to create the Tier by Antrea.
	reservedTierPriorities = controlplane.NewUInt32(uint32(251), uint32(252), uint32(253), uint32(254), uint32(255))
	// reservedTierNames stores the set of Tier names which cannot be deleted
	// since they are created by Antrea.
	reservedTierNames = sets.NewString("application", "platform", "networkops", "securityops", "emergency")
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

func HandleValidationNetworkPolicy(v *NetworkPolicyValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.Info("Received request to validate Tier/CNP CRD")
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = ioutil.ReadAll(r.Body)
		}
		if len(reqBody) == 0 {
			klog.Errorf("Tier validation received empty request body")
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}
		// verify the content type is accurate
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			klog.Errorf("Invalid content-Type=%s, expected application/json", contentType)
			http.Error(w, "invalid Content-Type, expected `application/json`", http.StatusUnsupportedMediaType)
			return
		}
		if r.URL.Path != "/validate/tier" && r.URL.Path != "/validate/cnp" {
			klog.Errorf("Invalid path received for Tier/CNP validation")
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		var admissionResponse *admv1.AdmissionResponse
		ar := admv1.AdmissionReview{}
		ar.TypeMeta.Kind = "AdmissionReview"
		ar.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if err := json.Unmarshal(reqBody, &ar); err != nil {
			klog.Errorf("CRD validation received incorrect body")
			admissionResponse = getAdmissionResponseForErr(err)
		} else {
			admissionResponse = v.validate(&ar)
		}
		aReview := admv1.AdmissionReview{}
		aReview.TypeMeta.Kind = "AdmissionReview"
		aReview.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if admissionResponse != nil {
			aReview.Response = admissionResponse
			if ar.Request != nil {
				aReview.Response.UID = ar.Request.UID
			}
		}
		resp, err := json.Marshal(aReview)
		if err != nil {
			klog.Errorf("Unable to encode response during validation: %v", err)
			http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		}
		klog.Infof("Writing validation response to ValidationAdmissionHook")
		if _, err := w.Write(resp); err != nil {
			klog.Errorf("Unable to write response during validation: %v", err)
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		}
	}
}

// validate function validates a Tier or CNP object
func (v *NetworkPolicyValidator) validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := false
	op := ar.Request.Operation
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw
	switch ar.Request.Kind.Kind {
	case "Tier":
		klog.Info("Validating Tier CRD")
		var curTier, oldTier secv1alpha1.Tier
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curTier); err != nil {
				klog.Errorf("Error de-serializing current Tier")
				return getAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldTier); err != nil {
				klog.Errorf("Error de-serializing old Tier")
				return getAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateTier(&curTier, &oldTier, op)
	case "ClusterNetworkPolicy":
		klog.Info("Validating ClusterNetworkPolicy CRD")
		var curCNP, oldCNP secv1alpha1.ClusterNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curCNP); err != nil {
				klog.Errorf("Error de-serializing current ClusterNetworkPolicy")
				return getAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldCNP); err != nil {
				klog.Errorf("Error de-serializing old ClusterNetworkPolicy")
				return getAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateCNP(&curCNP, &oldCNP, op)
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

// validateCNP validates the admission of a ClusterNetworkPolicy resource
func (v *NetworkPolicyValidator) validateCNP(curCNP, oldCNP *secv1alpha1.ClusterNetworkPolicy, op admv1.Operation) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case "CREATE":
		// CNP "tier" must exist before referencing
		klog.Info("Validating CREATE request for ClusterNetworkPolicy")
		if curCNP.Spec.Tier == "" || staticTierSet.Has(curCNP.Spec.Tier) {
			// Empty Tier name corresponds to default Tier
			break
		}
		if ok := v.tierExists(curCNP.Spec.Tier); !ok {
			allowed = false
			reason = fmt.Sprintf("tier %s does not exist", curCNP.Spec.Tier)
		}
	case "UPDATE":
		// CNP "tier" must exist before referencing
		klog.Info("Validating UPDATE request for CNP")
		if curCNP.Spec.Tier == "" || staticTierSet.Has(curCNP.Spec.Tier) {
			// Empty Tier name corresponds to default Tier
			break
		}
		if ok := v.tierExists(curCNP.Spec.Tier); !ok {
			allowed = false
			reason = fmt.Sprintf("tier %s does not exist", curCNP.Spec.Tier)
		}
	case "DELETE":
		// Delete of CNP have no validation
		allowed = true
	}
	return reason, allowed
}

// validateTier validates the admission of a Tier resource
func (v *NetworkPolicyValidator) validateTier(curTier, oldTier *secv1alpha1.Tier, op admv1.Operation) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case "CREATE":
		// Tier priority must not overlap existing tier's priority
		klog.Info("Validating CREATE request for Tier")
		if len(v.networkPolicyController.tierPrioritySet) >= maxSupportedTiers {
			allowed = false
			reason = fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers)
		} else if reservedTierPriorities.Has(curTier.Spec.Priority) {
			allowed = false
			reason = fmt.Sprintf("tier %s priority %d is reserved", curTier.Name, curTier.Spec.Priority)
		} else if v.networkPolicyController.tierPrioritySet.Has(curTier.Spec.Priority) {
			allowed = false
			reason = fmt.Sprintf("tier %s priority %d overlaps with existing Tier", curTier.Name, curTier.Spec.Priority)
		}
	case "UPDATE":
		// Tier priority updates are not allowed
		klog.Info("Validating UPDATE request for Tier")
		if curTier.Spec.Priority != oldTier.Spec.Priority {
			allowed = false
			reason = "update to Tier priority is not allowed"
		}
	case "DELETE":
		klog.Info("Validating DELETE request for Tier")
		if reservedTierNames.Has(oldTier.Name) {
			reason = fmt.Sprintf("cannot delete reserved tier %s", oldTier.Name)
			return reason, false
		}
		// Tier with existing CNPs cannot be deleted
		cnps, err := v.networkPolicyController.cnpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
		if err != nil || len(cnps) > 0 {
			allowed = false
			reason = fmt.Sprintf("tier %s is referenced by %d NetworkPolic(y)ies", oldTier.Name, len(cnps))
		}
	}
	return reason, allowed
}

func (v *NetworkPolicyValidator) tierExists(name string) bool {
	tier, err := v.networkPolicyController.tierLister.Get(name)
	if tier == nil || err != nil {
		return false
	}
	return true
}

// getAdmissionResponseForErr returns an object of type AdmissionResponse with
// the submitted error message.
func getAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	if err == nil {
		return nil
	}
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

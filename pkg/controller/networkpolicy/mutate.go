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
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

type NetworkPolicyMutator struct {
	networkPolicyController *NetworkPolicyController
}

// NewNetworkPolicyMutator returns a new *NetworkPolicyMutator.
func NewNetworkPolicyMutator(networkPolicyController *NetworkPolicyController) *NetworkPolicyMutator {
	return &NetworkPolicyMutator{
		networkPolicyController: networkPolicyController,
	}
}

// Mutate function mutate a Antrea Policy object
func (m *NetworkPolicyMutator) Mutate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	var patch []byte
	allowed := false
	patchType := admv1.PatchTypeJSONPatch

	op := ar.Request.Operation
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw

	switch ar.Request.Kind.Kind {
	case "ClusterNetworkPolicy":
		klog.V(2).Info("Mutating Antrea ClusterNetworkPolicy CRD")
		var curACNP, oldACNP secv1alpha1.ClusterNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curACNP); err != nil {
				klog.Errorf("Error de-serializing current Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldACNP); err != nil {
				klog.Errorf("Error de-serializing old Antrea ClusterNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed, patch = m.mutateAntreaPolicyRuleName(op, curACNP.Spec.Ingress, curACNP.Spec.Egress)
	case "NetworkPolicy":
		klog.V(2).Info("Mutating Antrea NetworkPolicy CRD")
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
		msg, allowed, patch = m.mutateAntreaPolicyRuleName(op, curANP.Spec.Ingress, curANP.Spec.Egress)
	}

	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed:   allowed,
		Result:    result,
		PatchType: &patchType,
		Patch:     patch,
	}
}

// mutateAntreaPolicyRuleName mutates names of rules of an Antrea NetworkPolicy CRD.
// If users didn't specify the name of an ingress or egress rule,
// mutateAntreaPolicyRuleName will auto-generate a name for this rule.
func (m *NetworkPolicyMutator) mutateAntreaPolicyRuleName(op admv1.Operation, ingress, egress []secv1alpha1.Rule) (string, bool, []byte) {
	allowed := true
	reason := ""
	var patch []byte
	switch op {
	case admv1.Create, admv1.Update:
		ingressRulePaths, ingressRuleNames := generateRuleNames("ingress", ingress)
		egressRulePaths, egressRuleNames := generateRuleNames("egress", egress)

		genPatch, err := createReplacePatch(append(ingressRulePaths, egressRulePaths...), append(ingressRuleNames, egressRuleNames...))
		if err != nil {
			allowed = false
			reason = "unable to generate mutating patch"
			break
		}
		patch = genPatch

	case admv1.Delete:
		// Delete of Antrea Policies have no mutation
		allowed = true
	}
	return reason, allowed, patch
}

// generateRuleNames generates unique rule names and returns a list of json paths and the corresponding list of generated names
func generateRuleNames(prefix string, rules []secv1alpha1.Rule) ([]string, []string) {
	var paths []string
	var values []string
	for idx, rule := range rules {
		if rule.Name == "" {
			genName := fmt.Sprintf("%s-%s-%s", prefix, strings.ToLower(string(*rule.Action)), hashRule(rule))
			paths = append(paths, fmt.Sprintf("/spec/%s/%d/name", prefix, idx))
			values = append(values, genName)
		}
	}
	return paths, values
}

type jsonPatchOperation string

const (
	jsonPatchReplaceOp jsonPatchOperation = "replace"
)

// jsonPatch contains necessary info that MutatingWebhook required
type jsonPatch struct {
	// Op represent the operation of this mutation
	Op jsonPatchOperation `json:"op"`
	// Path is a jsonPath to locate the value that need to be mutated
	Path string `json:"path"`
	// Value represent the value which is used in mutation
	Value interface{} `json:"value,omitempty"`
}

// createReplacePatch use paths and values that need to be replace to generate a serialized patch
func createReplacePatch(paths []string, values []string) ([]byte, error) {
	var patch []jsonPatch

	if len(paths) != len(values) {
		return nil, fmt.Errorf("the number of paths is not equal to the number of values that need to be added")
	}

	for i := range paths {
		patch = append(patch, jsonPatch{
			Op:    jsonPatchReplaceOp,
			Path:  paths[i],
			Value: values[i],
		})
	}

	return json.Marshal(patch)
}

const ruleNameSuffixLen = 7

// hashRule calculates a string based on the rule's content.
func hashRule(r secv1alpha1.Rule) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	b, _ := json.Marshal(r)
	hash.Write(b)
	hashValue := hex.EncodeToString(hash.Sum(nil))
	return hashValue[:ruleNameSuffixLen]
}

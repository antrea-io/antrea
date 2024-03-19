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
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
)

// validator interface introduces the set of functions that must be implemented
// by any resource validator.
type validator interface {
	// createValidate is the interface which must be satisfied for resource
	// CREATE events.
	createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
	// updateValidate is the interface which must be satisfied for resource
	// UPDATE events.
	updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
	// deleteValidate is the interface which must be satisfied for resource
	// DELETE events.
	deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool)
}

// resourceValidator maintains a reference of the NetworkPolicyController and
// provides a base struct for validating objects which implement the validator
// interface.
type resourceValidator struct {
	networkPolicyController *NetworkPolicyController
}

// antreaPolicyValidator implements the validator interface for Antrea-native
// policies.
type antreaPolicyValidator resourceValidator

// tierValidator implements the validator interface for Tier resources.
type tierValidator resourceValidator

// groupValidator implements the validator interface for the ClusterGroup resource.
type groupValidator resourceValidator

// adminPolicyValidator implements the validator interface for the AdminNetworkPolicy resource.
type adminPolicyValidator resourceValidator

var (
	// reservedTierPriorities stores the reserved priority range from 251, 252, 254 and 255.
	// The priority 250 is reserved for default Tier but not part of this set in order to be
	// able to create the Tier by Antrea. Same for priority 253 which is reserved for the
	// baseline tier.
	reservedTierPriorities = sets.New[int32](int32(251), int32(252), int32(254), int32(255))
	// reservedTierNames stores the set of Tier names which cannot be deleted
	// since they are created by Antrea.
	reservedTierNames = sets.New[string]("baseline", "application", "platform", "networkops", "securityops", "emergency")
	// allowedFQDNChars validates that the matchPattern field contains only valid DNS characters
	// and the wildcard '*' character.
	allowedFQDNChars = regexp.MustCompile("^[-0-9a-zA-Z.*]+$")
)

// RegisterAntreaPolicyValidator registers an Antrea-native policy validator
// to the resource registry. A new validator must be registered by calling
// this function before the Run phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterAntreaPolicyValidator(a validator) {
	v.antreaPolicyValidators = append(v.antreaPolicyValidators, a)
}

// RegisterTierValidator registers a Tier validator to the resource registry.
// A new validator must be registered by calling this function before the Run
// phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterTierValidator(t validator) {
	v.tierValidators = append(v.tierValidators, t)
}

// RegisterGroupValidator registers a Group validator to the resource registry.
// A new validator must be registered by calling this function before the Run
// phase of the APIServer.
func (v *NetworkPolicyValidator) RegisterGroupValidator(g validator) {
	v.groupValidators = append(v.groupValidators, g)
}

func (v *NetworkPolicyValidator) RegisterAdminNetworkPolicyValidator(a validator) {
	v.adminNPValidators = append(v.adminNPValidators, a)
}

// NetworkPolicyValidator maintains list of validator objects which validate
// the Antrea-native policy related resources.
type NetworkPolicyValidator struct {
	// antreaPolicyValidators maintains a list of validator objects which
	// implement the validator interface for Antrea-native policies.
	antreaPolicyValidators []validator
	// tierValidators maintains a list of validator objects which
	// implement the validator interface for Tier resources.
	tierValidators []validator
	// groupValidators maintains a list of validator objects which
	// implement the validator interface for ClusterGroup resources.
	groupValidators []validator
	// adminNPValidators maintains a list of validator objects which
	// implement the validator interface for ANP and BANP resources.
	adminNPValidators []validator
}

// NewNetworkPolicyValidator returns a new *NetworkPolicyValidator.
func NewNetworkPolicyValidator(networkPolicyController *NetworkPolicyController) *NetworkPolicyValidator {
	// initialize the validator registry with the default validators that need to
	// be called.
	vr := NetworkPolicyValidator{}
	// apv is an instance of antreaPolicyValidator to validate Antrea-native
	// policy events.
	apv := antreaPolicyValidator{
		networkPolicyController: networkPolicyController,
	}
	// tv is an instance of tierValidator to validate Tier resource events.
	tv := tierValidator{
		networkPolicyController: networkPolicyController,
	}
	// gv is an instance of groupValidator to validate ClusterGroup
	// resource events.
	gv := groupValidator{
		networkPolicyController: networkPolicyController,
	}
	av := adminPolicyValidator{
		networkPolicyController: networkPolicyController,
	}
	vr.RegisterAntreaPolicyValidator(&apv)
	vr.RegisterTierValidator(&tv)
	vr.RegisterGroupValidator(&gv)
	vr.RegisterAdminNetworkPolicyValidator(&av)
	return &vr
}

// Validate function validates a Group, ClusterGroup, Tier or Antrea Policy object
func (v *NetworkPolicyValidator) Validate(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := false
	op := ar.Request.Operation
	ui := ar.Request.UserInfo
	curRaw := ar.Request.Object.Raw
	oldRaw := ar.Request.OldObject.Raw
	switch ar.Request.Kind.Kind {
	case "Tier":
		klog.V(2).Info("Validating Tier CRD")
		// Current serving versions of Tier are v1alpha1 and v1beta1. They have the same
		// schema and the same validating logic, and we only store v1beta1 in the etcd. So
		// we unmarshal both of them into a v1beta1 object to do validation.
		var curTier, oldTier crdv1beta1.Tier
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
		msg, allowed = v.validateTier(&curTier, &oldTier, op, ui)
	case "ClusterGroup":
		klog.V(2).Info("Validating ClusterGroup CRD")
		// Current serving versions of ClusterGroup are v1alpha3 and v1beta1. They have
		// the same schema and the same validating logic, and we only store v1beta1 in
		// the etcd. So we unmarshal both of them into a v1beta1 object to do validation.
		var curCG, oldCG crdv1beta1.ClusterGroup
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curCG); err != nil {
				klog.Errorf("Error de-serializing current ClusterGroup")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldCG); err != nil {
				klog.Errorf("Error de-serializing old ClusterGroup")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaGroup(&curCG, &oldCG, op, ui)
	case "Group":
		klog.V(2).Info("Validating Group CRD")
		// Current serving versions of Group are v1alpha3 and v1beta1. They have the same
		// schema and the same validating logic, and we only store v1beta1 in the etcd. So
		// we unmarshal both of them into a v1beta1 object to do validation.
		var curG, oldG crdv1beta1.Group
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curG); err != nil {
				klog.Errorf("Error de-serializing current Group")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldG); err != nil {
				klog.Errorf("Error de-serializing old Group")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaGroup(&curG, &oldG, op, ui)
	case "ClusterNetworkPolicy":
		klog.V(2).Info("Validating Antrea ClusterNetworkPolicy CRD")
		var curACNP, oldACNP crdv1beta1.ClusterNetworkPolicy
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
		msg, allowed = v.validateAntreaPolicy(&curACNP, &oldACNP, op, ui)
	case "NetworkPolicy":
		klog.V(2).Info("Validating Antrea NetworkPolicy CRD")
		var curANNP, oldANNP crdv1beta1.NetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curANNP); err != nil {
				klog.Errorf("Error de-serializing current Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldANNP); err != nil {
				klog.Errorf("Error de-serializing old Antrea NetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAntreaPolicy(&curANNP, &oldANNP, op, ui)
	case "AdminNetworkPolicy":
		klog.V(2).Info("Validating AdminNetworkPolicy CRD")
		var curANP, oldANP v1alpha1.AdminNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curANP); err != nil {
				klog.Errorf("Error de-serializing current AdminNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldANP); err != nil {
				klog.Errorf("Error de-serializing old AdminNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAdminNetworkPolicy(&curANP, &oldANP, op, ui)
	case "BaselineAdminNetworkPolicy":
		klog.V(2).Info("Validating BaselineAdminNetworkPolicy CRD")
		var curBANP, oldBANP v1alpha1.BaselineAdminNetworkPolicy
		if curRaw != nil {
			if err := json.Unmarshal(curRaw, &curBANP); err != nil {
				klog.Errorf("Error de-serializing current BaselineAdminNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		if oldRaw != nil {
			if err := json.Unmarshal(oldRaw, &oldBANP); err != nil {
				klog.Errorf("Error de-serializing old BaselineAdminNetworkPolicy")
				return GetAdmissionResponseForErr(err)
			}
		}
		msg, allowed = v.validateAdminNetworkPolicy(&curBANP, &oldBANP, op, ui)
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
func (v *NetworkPolicyValidator) validateAntreaPolicy(curObj, oldObj interface{}, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.createValidate(curObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.updateValidate(curObj, oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		// Delete of Antrea Policies have no validation. This will be an
		// empty for loop.
		for _, val := range v.antreaPolicyValidators {
			reason, allowed = val.deleteValidate(oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

func (v *NetworkPolicyValidator) validateAdminNetworkPolicy(curObj, oldObj interface{}, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		for _, val := range v.adminNPValidators {
			reason, allowed = val.createValidate(curObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		for _, val := range v.adminNPValidators {
			reason, allowed = val.updateValidate(curObj, oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		for _, val := range v.adminNPValidators {
			reason, allowed = val.deleteValidate(oldObj, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

// validatePort validates if ports is valid
func (v *antreaPolicyValidator) validatePort(ingress, egress []crdv1beta1.Rule) error {
	isValid := func(rules []crdv1beta1.Rule) error {
		for _, rule := range rules {
			for _, port := range rule.Ports {
				if port.EndPort != nil {
					if port.Port == nil {
						return fmt.Errorf("if `endPort` is specified `port` must be specified")
					}
					if port.Port.Type == intstr.String {
						return fmt.Errorf("if `port` is a string `endPort` cannot be specified")
					}
					if *port.EndPort < port.Port.IntVal {
						return fmt.Errorf("`endPort` should be greater than or equal to `port`")
					}
				}
				if port.SourceEndPort != nil {
					if port.SourcePort == nil {
						return fmt.Errorf("if `sourceEndPort` is specified `sourcePort` must be specified")
					}
					if *port.SourceEndPort < *port.SourcePort {
						return fmt.Errorf("`sourceEndPort` should be greater than or equal to `sourcePort`")
					}
				}
			}
		}
		return nil
	}
	if err := isValid(ingress); err != nil {
		return err
	}
	if err := isValid(egress); err != nil {
		return err
	}
	return nil
}

// validateAntreaGroup validates the admission of a Group, ClusterGroup resource
func (v *NetworkPolicyValidator) validateAntreaGroup(curAG, oldAG interface{}, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for ClusterGroup/Group")
		for _, val := range v.groupValidators {
			reason, allowed = val.createValidate(curAG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ClusterGroup/Group")
		for _, val := range v.groupValidators {
			reason, allowed = val.updateValidate(curAG, oldAG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for ClusterGroup/Group")
		for _, val := range v.groupValidators {
			reason, allowed = val.deleteValidate(oldAG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

// validateTier validates the admission of a Tier resource
func (v *NetworkPolicyValidator) validateTier(curTier, oldTier *crdv1beta1.Tier, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.createValidate(curTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		// Tier priority updates are not allowed
		klog.V(2).Info("Validating UPDATE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.updateValidate(curTier, oldTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for Tier")
		for _, val := range v.tierValidators {
			reason, allowed = val.deleteValidate(oldTier, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

func (v *antreaPolicyValidator) tierExists(name string) bool {
	_, err := v.networkPolicyController.tierLister.Get(name)
	return err == nil
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

// createValidate validates the CREATE events of Antrea-native policies,
func (v *antreaPolicyValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return v.validatePolicy(curObj)
}

// validatePolicy validates the CREATE and UPDATE events of Antrea-native policies,
func (v *antreaPolicyValidator) validatePolicy(curObj interface{}) (string, bool) {
	var tier string
	var ingress, egress []crdv1beta1.Rule
	var specAppliedTo []crdv1beta1.AppliedTo
	switch curObj.(type) {
	case *crdv1beta1.ClusterNetworkPolicy:
		curACNP := curObj.(*crdv1beta1.ClusterNetworkPolicy)
		tier = curACNP.Spec.Tier
		ingress = curACNP.Spec.Ingress
		egress = curACNP.Spec.Egress
		specAppliedTo = curACNP.Spec.AppliedTo
	case *crdv1beta1.NetworkPolicy:
		curANNP := curObj.(*crdv1beta1.NetworkPolicy)
		tier = curANNP.Spec.Tier
		ingress = curANNP.Spec.Ingress
		egress = curANNP.Spec.Egress
		specAppliedTo = curANNP.Spec.AppliedTo
	}
	reason, allowed := v.validateTierForPolicy(tier)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateTierForPassAction(tier, ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if ruleNameUnique := v.validateRuleName(ingress, egress); !ruleNameUnique {
		return "rules names must be unique within the policy", false
	}
	reason, allowed = v.validateAppliedTo(ingress, egress, specAppliedTo)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validatePeers(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateAppliedToServiceIngressPeer(specAppliedTo, ingress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateFQDNSelectors(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateEgressMulticastAddress(egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateMulticastIGMP(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = v.validateL7Protocols(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if err := v.validatePort(ingress, egress); err != nil {
		return err.Error(), false
	}
	return "", true
}

// validateRuleName validates if the name of each rule is unique within a policy
func (v *antreaPolicyValidator) validateRuleName(ingress, egress []crdv1beta1.Rule) bool {
	uniqueRuleName := sets.New[string]()
	isUnique := func(rules []crdv1beta1.Rule) bool {
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

func (v *antreaPolicyValidator) validateAppliedTo(ingress, egress []crdv1beta1.Rule, specAppliedTo []crdv1beta1.AppliedTo) (string, bool) {
	appliedToInSpec := len(specAppliedTo) != 0
	countAppliedToInRules := func(rules []crdv1beta1.Rule) int {
		num := 0
		for _, rule := range rules {
			if len(rule.AppliedTo) != 0 {
				num++
			}
		}
		return num
	}
	numAppliedToInRules := countAppliedToInRules(ingress) + countAppliedToInRules(egress)
	// Ensure that AppliedTo is not set in both spec and rules.
	if appliedToInSpec && (numAppliedToInRules > 0) {
		return "appliedTo should not be set in both spec and rules", false
	}
	if !appliedToInSpec && (numAppliedToInRules == 0) {
		return "appliedTo needs to be set in either spec or rules", false
	}
	// Ensure that all rules have AppliedTo set.
	if numAppliedToInRules > 0 && (numAppliedToInRules != len(ingress)+len(egress)) {
		return "appliedTo field should either be set in all rules or in none of them", false
	}

	var (
		appliedToPolicy      = 0
		appliedToIngressRule = 1
		appliedToEgressRule  = 2
	)

	checkAppliedTo := func(appliedTo []crdv1beta1.AppliedTo, appliedToScope int) (string, bool) {
		appliedToSvcNum := 0
		for _, eachAppliedTo := range appliedTo {
			appliedToFieldsNum := numFieldsSetInStruct(eachAppliedTo)
			if eachAppliedTo.Group != "" && appliedToFieldsNum > 1 {
				return "group cannot be set with other peers in appliedTo", false
			}
			if eachAppliedTo.ServiceAccount != nil && appliedToFieldsNum > 1 {
				return "serviceAccount cannot be set with other peers in appliedTo", false
			}
			if eachAppliedTo.Service != nil {
				if appliedToFieldsNum > 1 {
					return "service cannot be set with other peers in appliedTo", false
				}
				if appliedToScope == appliedToEgressRule || appliedToScope == appliedToPolicy && len(egress) > 0 {
					return "egress rule cannot be applied to Services", false
				}
				appliedToSvcNum++
			}
			if reason, allowed := checkSelectorsLabels(eachAppliedTo.PodSelector, eachAppliedTo.NamespaceSelector, eachAppliedTo.ExternalEntitySelector); !allowed {
				return reason, allowed
			}
		}
		if appliedToSvcNum > 0 && appliedToSvcNum < len(appliedTo) {
			return "a rule/policy cannot be applied to Services and other peers at the same time", false
		}
		return "", true
	}

	reason, allowed := checkAppliedTo(specAppliedTo, appliedToPolicy)
	if !allowed {
		return reason, allowed
	}

	for _, eachIngress := range ingress {
		reason, allowed = checkAppliedTo(eachIngress.AppliedTo, appliedToIngressRule)
		if !allowed {
			return reason, allowed
		}
	}
	for _, eachEgress := range egress {
		reason, allowed = checkAppliedTo(eachEgress.AppliedTo, appliedToEgressRule)
		if !allowed {
			return reason, allowed
		}
	}
	return "", true
}

// validatePeers ensures that the NetworkPolicyPeer object set in rules are valid, i.e.
// currently it ensures that a Group cannot be set with other stand-alone selectors or IPBlock.
func (v *antreaPolicyValidator) validatePeers(ingress, egress []crdv1beta1.Rule) (string, bool) {
	checkPeers := func(peers []crdv1beta1.NetworkPolicyPeer) (string, bool) {
		for _, peer := range peers {
			if peer.NamespaceSelector != nil && peer.Namespaces != nil {
				return "namespaces and namespaceSelector cannot be set at the same time for a single NetworkPolicyPeer", false
			}
			if peer.Namespaces != nil {
				if numFieldsSetInStruct(*peer.Namespaces) > 1 {
					return "only one matching criteria can be specified in a single peer namespaces field", false
				}
				for _, k := range peer.Namespaces.SameLabels {
					if err := validation.IsQualifiedName(k); err != nil {
						return fmt.Sprintf("Invalid label key in sameLabels rule: %s", k), false
					}
				}
			}
			peerFieldsNum := numFieldsSetInStruct(peer)
			if peer.Group != "" && peerFieldsNum > 1 {
				return "group cannot be set with other peers in rules", false
			}
			if peer.ServiceAccount != nil && peerFieldsNum > 1 {
				return "serviceAccount cannot be set with other peers in rules", false
			}
			if peer.NodeSelector != nil && peerFieldsNum > 1 {
				return "nodeSelector cannot be set with other peers in rules", false
			}
			if reason, allowed := checkSelectorsLabels(peer.PodSelector, peer.NamespaceSelector, peer.ExternalEntitySelector, peer.NodeSelector); !allowed {
				return reason, allowed
			}
		}
		return "", true
	}
	for _, rule := range ingress {
		msg, isValid := checkPeers(rule.From)
		if !isValid {
			return msg, false
		}
	}
	for _, rule := range egress {
		if rule.ToServices != nil {
			if (rule.To != nil && len(rule.To) > 0) || rule.Ports != nil || rule.Protocols != nil {
				return "`toServices` cannot be used with `to`, `ports` or `protocols`", false
			}
		}
		msg, isValid := checkPeers(rule.To)
		if !isValid {
			return msg, false
		}
	}
	return "", true
}

// validateAppliedToServiceIngressPeer ensures that if a policy or an ingress rule
// is applied to Services, the ingress rule can only use ipBlock to select workloads.
func (v *antreaPolicyValidator) validateAppliedToServiceIngressPeer(specAppliedTo []crdv1beta1.AppliedTo, ingress []crdv1beta1.Rule) (string, bool) {
	isAppliedToService := func(peers []crdv1beta1.AppliedTo) bool {
		if len(peers) > 0 {
			return peers[0].Service != nil
		}
		return false
	}
	policyAppliedToService := isAppliedToService(specAppliedTo)
	for _, rule := range ingress {
		if policyAppliedToService || isAppliedToService(rule.AppliedTo) {
			for _, peer := range rule.From {
				if peer.IPBlock == nil || numFieldsSetInStruct(peer) > 1 {
					return "a rule/policy that is applied to Services can only use ipBlock to select workloads", false
				}
			}
		}
	}
	return "", true
}

// numFieldsSetInStruct returns the number of fields in use of the object.
func numFieldsSetInStruct(obj interface{}) int {
	num := 0
	v := reflect.ValueOf(obj)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			num++
		}
	}
	return num
}

// checkSelectorsLabels validates labels used in all selectors passed in.
func checkSelectorsLabels(selectors ...*metav1.LabelSelector) (string, bool) {
	validateLabels := func(labels map[string]string) (string, bool) {
		for k, v := range labels {
			err := validation.IsQualifiedName(k)
			if err != nil {
				return fmt.Sprintf("Invalid label key: %s: %s", k, strings.Join(err, "; ")), false
			}
			err = validation.IsValidLabelValue(v)
			if err != nil {
				return fmt.Sprintf("Invalid label value: %s: %s", v, strings.Join(err, "; ")), false
			}
		}
		return "", true
	}
	for _, selector := range selectors {
		if selector != nil {
			if reason, allowed := validateLabels(selector.MatchLabels); !allowed {
				return reason, allowed
			}
		}
	}
	return "", true
}

// validateTierForPolicy validates whether a referenced Tier exists.
func (v *antreaPolicyValidator) validateTierForPolicy(tier string) (string, bool) {
	// "tier" must exist before referencing
	if tier == "" || staticTierSet.Has(tier) {
		// Empty Tier name corresponds to default Tier.
		return "", true
	}
	if ok := v.tierExists(tier); !ok {
		reason := fmt.Sprintf("tier %s does not exist", tier)
		return reason, false
	}
	return "", true
}

// validateTierForPassAction validates that rules with pass action are not created in the Baseline Tier.
func (v *antreaPolicyValidator) validateTierForPassAction(tier string, ingress, egress []crdv1beta1.Rule) (string, bool) {
	if strings.ToLower(tier) != baselineTierName {
		return "", true
	}
	for _, rule := range ingress {
		if *rule.Action == crdv1beta1.RuleActionPass {
			return "`Pass` action should not be set for Baseline Tier policy rules", false
		}
	}
	for _, rule := range egress {
		if *rule.Action == crdv1beta1.RuleActionPass {
			return "`Pass` action should not be set for Baseline Tier policy rules", false
		}
	}
	return "", true
}

func (v *antreaPolicyValidator) validateEgressMulticastAddress(egressRule []crdv1beta1.Rule) (string, bool) {
	for _, r := range egressRule {
		multicast := false
		unicast := false
		otherSelectors := false
		for _, to := range r.To {
			if to.IPBlock == nil {
				continue
			}
			toIPAddr, _, err := net.ParseCIDR(to.IPBlock.CIDR)
			if err != nil {
				return fmt.Sprintf("invalid multicast groupAddress address (to.IPBlock.CIDR): %v", err.Error()), false
			}
			if toIPAddr.IsMulticast() {
				multicast = true
			} else {
				unicast = true
			}
			if to.PodSelector != nil || to.NamespaceSelector != nil || to.Namespaces != nil ||
				to.ExternalEntitySelector != nil || to.ServiceAccount != nil || to.NodeSelector != nil {
				otherSelectors = true
			}
			if multicast && (*r.Action == crdv1beta1.RuleActionPass || *r.Action == crdv1beta1.RuleActionReject) {
				return "multicast does not support action Pass or Reject", false
			}
		}
		if multicast && unicast {
			return "can not set multicast groupAddress and unicast ip address at the same time", false
		}
		if multicast && otherSelectors {
			return "can not set multicast groupAddress and selectors at the same time", false
		}
	}
	return "", true
}

func validateIGMPProtocol(protocol crdv1beta1.NetworkPolicyProtocol) (string, bool) {
	if protocol.IGMP.GroupAddress == "" {
		return "", true
	}
	groupIP := net.ParseIP(protocol.IGMP.GroupAddress)
	if !groupIP.IsMulticast() {
		return fmt.Sprintf("groupAddress %+v is not multicast address", groupIP), false
	}

	return "", true
}

func (v *antreaPolicyValidator) validateMulticastIGMP(ingressRules, egressRules []crdv1beta1.Rule) (string, bool) {
	haveIGMP := false
	haveICMP := false
	for _, r := range append(ingressRules, egressRules...) {
		for _, protocol := range r.Protocols {
			if protocol.IGMP != nil {
				haveIGMP = true
				reason, allowed := validateIGMPProtocol(protocol)
				if !allowed {
					return reason, allowed
				}
				if *r.Action == crdv1beta1.RuleActionPass || *r.Action == crdv1beta1.RuleActionReject {
					return "protocol IGMP does not support Pass or Reject", false
				}
			}
			if protocol.ICMP != nil {
				haveICMP = true
			}
		}
		if haveIGMP && (len(r.Ports) != 0 || len(r.ToServices) != 0 || len(r.From) != 0 || len(r.To) != 0 || haveICMP) {
			return "protocol IGMP can not be used with other protocols or other properties like from, to", false
		}
	}
	return "", true
}

// validateL7Protocols validates the L7Protocols field set in Antrea-native policy
// rules are valid, and compatible with the ports or protocols fields.
func (v *antreaPolicyValidator) validateL7Protocols(ingressRules, egressRules []crdv1beta1.Rule) (string, bool) {
	for _, r := range append(ingressRules, egressRules...) {
		if len(r.L7Protocols) == 0 {
			continue
		}
		if !features.DefaultFeatureGate.Enabled(features.L7NetworkPolicy) {
			return "layer 7 protocols can only be used when L7NetworkPolicy is enabled", false
		}
		if *r.Action != crdv1beta1.RuleActionAllow {
			return "layer 7 protocols only support Allow", false
		}
		if len(r.ToServices) != 0 {
			return "layer 7 protocols can not be used with toServices", false
		}
		haveHTTP := false
		for _, p := range r.L7Protocols {
			if p.HTTP != nil {
				haveHTTP = true
			}
		}
		for _, port := range r.Ports {
			if haveHTTP && (port.Protocol != nil && *port.Protocol != v1.ProtocolTCP) {
				return "HTTP protocol can only be used when layer 4 protocol is TCP or unset", false
			}
		}
		for _, protocol := range r.Protocols {
			if haveHTTP && (protocol.IGMP != nil || protocol.ICMP != nil) {
				return "HTTP protocol can not be used with protocol IGMP or ICMP", false
			}
		}
	}
	return "", true
}

// validateFQDNSelectors validates the toFQDN field set in Antrea-native policy egress rules are valid.
func (v *antreaPolicyValidator) validateFQDNSelectors(egressRules []crdv1beta1.Rule) (string, bool) {
	for _, r := range egressRules {
		for _, peer := range r.To {
			if len(peer.FQDN) > 0 && !allowedFQDNChars.MatchString(peer.FQDN) {
				return fmt.Sprintf("invalid characters in egress rule fqdn field: %s", peer.FQDN), false
			}
		}
	}
	return "", true
}

// updateValidate validates the UPDATE events of Antrea-native policies.
func (v *antreaPolicyValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return v.validatePolicy(curObj)
}

// deleteValidate validates the DELETE events of Antrea-native policies.
func (v *antreaPolicyValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}

// createValidate validates the CREATE events of Tier resources.
func (t *tierValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	if len(t.networkPolicyController.tierInformer.Informer().GetIndexer().ListIndexFuncValues(PriorityIndex)) >= maxSupportedTiers {
		return fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers), false
	}
	curTier := curObj.(*crdv1beta1.Tier)
	// Tier priority must not overlap reserved tier's priority.
	if reservedTierPriorities.Has(curTier.Spec.Priority) {
		return fmt.Sprintf("tier %s priority %d is reserved", curTier.Name, curTier.Spec.Priority), false
	}
	// Tier priority must not overlap existing tier's priority
	trs, err := t.networkPolicyController.tierInformer.Informer().GetIndexer().ByIndex(PriorityIndex, strconv.FormatInt(int64(curTier.Spec.Priority), 10))
	if err != nil || len(trs) > 0 {
		return fmt.Sprintf("tier %s priority %d overlaps with existing Tier", curTier.Name, curTier.Spec.Priority), false
	}
	return "", true
}

// updateValidate validates the UPDATE events of Tier resources.
func (t *tierValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	curTier := curObj.(*crdv1beta1.Tier)
	oldTier := oldObj.(*crdv1beta1.Tier)
	// Retrieve antrea-controller's Namespace
	namespace := env.GetAntreaNamespace()
	// Allow exception of Tier Priority updates performed by the antrea-controller
	if serviceaccount.MatchesUsername(namespace, env.GetAntreaControllerServiceAccount(), userInfo.Username) {
		return "", true
	}
	if curTier.Spec.Priority != oldTier.Spec.Priority {
		allowed = false
		reason = "update to Tier priority is not allowed"
	}
	return reason, allowed
}

// deleteValidate validates the DELETE events of Tier resources.
func (t *tierValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	oldTier := oldObj.(*crdv1beta1.Tier)
	if reservedTierNames.Has(oldTier.Name) {
		return fmt.Sprintf("cannot delete reserved tier %s", oldTier.Name), false
	}
	// Tier with existing ACNPs/ANNPs cannot be deleted.
	acnps, err := t.networkPolicyController.acnpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(acnps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea ClusterNetworkPolicies", oldTier.Name, len(acnps)), false
	}
	annps, err := t.networkPolicyController.annpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(annps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea NetworkPolicies", oldTier.Name, len(annps)), false
	}
	return "", true
}

// validateAntreaClusterGroupSpec ensures that an IPBlock is not set along with namespaceSelector and/or a
// podSelector. Similarly, ExternalEntitySelector cannot be set with PodSelector.
func validateAntreaClusterGroupSpec(s crdv1beta1.GroupSpec) (string, bool) {
	errMsg := "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup"
	setFieldNum := numFieldsSetInStruct(s)
	if setFieldNum > 2 {
		return errMsg, false
	} else if setFieldNum == 2 {
		// If two fields are set, only nsSel+pSel and nsSel+eeSel are valid.
		if !(s.NamespaceSelector != nil && (s.PodSelector != nil || s.ExternalEntitySelector != nil)) {
			return errMsg, false
		}
	}
	if s.NamespaceSelector != nil || s.ExternalEntitySelector != nil || s.PodSelector != nil {
		if reason, allowed := checkSelectorsLabels(s.PodSelector, s.NamespaceSelector, s.ExternalEntitySelector); !allowed {
			return reason, allowed
		}
	}
	multicast := false
	unicast := false
	for _, ipb := range s.IPBlocks {
		ipaddr, _, err := net.ParseCIDR(ipb.CIDR)
		if err != nil {
			return fmt.Sprintf("invalid ip address: %v", err), false
		}
		if ipaddr.IsMulticast() {
			multicast = true
		} else {
			unicast = true
		}
	}
	if multicast && unicast {
		return "can not set multicast groupAddress together with unicast ip address", false
	}
	return "", true
}

func validateAntreaGroupSpec(s crdv1beta1.GroupSpec) (string, bool) {
	errMsg := "At most one of podSelector, externalEntitySelector, serviceReference, ipBlocks or childGroups can be set for a Group"
	setFieldNum := numFieldsSetInStruct(s)
	if setFieldNum > 2 {
		return errMsg, false
	} else if setFieldNum == 2 {
		// If two fields are set, only nsSel+pSel and nsSel+eeSel are valid.
		if !(s.NamespaceSelector != nil && (s.PodSelector != nil || s.ExternalEntitySelector != nil)) {
			return errMsg, false
		}
	}
	if s.NamespaceSelector != nil || s.ExternalEntitySelector != nil || s.PodSelector != nil {
		if reason, allowed := checkSelectorsLabels(s.PodSelector, s.NamespaceSelector, s.ExternalEntitySelector); !allowed {
			return reason, allowed
		}
	}
	return "", true
}

func (g *groupValidator) validateChildClusterGroup(s *crdv1beta1.ClusterGroup) (string, bool) {
	if len(s.Spec.ChildGroups) > 0 {
		parentGrps, err := g.networkPolicyController.internalGroupStore.GetByIndex(store.ChildGroupIndex, s.Name)
		if err != nil {
			return fmt.Sprintf("error retrieving parents of ClusterGroup %s: %v", s.Name, err), false
		}
		// TODO: relax this constraint when max group nesting level increases.
		if len(parentGrps) > 0 {
			return fmt.Sprintf("cannot set childGroups for ClusterGroup %s, who has %d parents", s.Name, len(parentGrps)), false
		}
		for _, groupname := range s.Spec.ChildGroups {
			cg, err := g.networkPolicyController.cgLister.Get(string(groupname))
			if err != nil {
				// the childGroup has not been created yet.
				continue
			}
			// TODO: relax this constraint when max group nesting level increases.
			if len(cg.Spec.ChildGroups) > 0 {
				return fmt.Sprintf("cannot set ClusterGroup %s as childGroup, who has %d childGroups itself", string(groupname), len(cg.Spec.ChildGroups)), false
			}
		}
	}
	return "", true
}

func (g *groupValidator) validateChildGroup(s *crdv1beta1.Group) (string, bool) {
	if len(s.Spec.ChildGroups) > 0 {
		parentGrps, err := g.networkPolicyController.internalGroupStore.GetByIndex(store.ChildGroupIndex, s.Namespace+"/"+s.Name)
		if err != nil {
			return fmt.Sprintf("error retrieving parents of Group %s/%s: %v", s.Namespace, s.Name, err), false
		}
		// TODO: relax this constraint when max group nesting level increases.
		if len(parentGrps) > 0 {
			return fmt.Sprintf("cannot set childGroups for Group %s/%s, who has %d parents", s.Namespace, s.Name, len(parentGrps)), false
		}
		for _, groupname := range s.Spec.ChildGroups {
			childGrp, err := g.networkPolicyController.grpLister.Groups(s.Namespace).Get(string(groupname))
			if err != nil {
				// the childGroup has not been created yet.
				continue
			}
			// TODO: relax this constraint when max group nesting level increases.
			if len(childGrp.Spec.ChildGroups) > 0 {
				return fmt.Sprintf("cannot set Group %s/%s as childGroup, who has %d childGroups itself", s.Namespace, string(groupname), len(childGrp.Spec.ChildGroups)), false
			}
		}
	}
	return "", true
}

func (g *groupValidator) validateCG(cg *crdv1beta1.ClusterGroup) (string, bool) {
	reason, allowed := validateAntreaClusterGroupSpec(cg.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildClusterGroup(cg)
}

func (g *groupValidator) validateG(grp *crdv1beta1.Group) (string, bool) {
	reason, allowed := validateAntreaGroupSpec(grp.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildGroup(grp)
}

// createValidate validates the CREATE events of Group, ClusterGroup resources.
func (g *groupValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return g.validateGroup(curObj)
}

// updateValidate validates the UPDATE events of Group, ClusterGroup resources.
func (g *groupValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return g.validateGroup(curObj)
}

// validateGroup validates the CREATE and UPDATE events of Group, ClusterGroup resources.
func (g *groupValidator) validateGroup(curObj interface{}) (string, bool) {
	var curCG *crdv1beta1.ClusterGroup
	var curG *crdv1beta1.Group
	var reason string
	var allowed bool
	switch curObj.(type) {
	case *crdv1beta1.ClusterGroup:
		curCG = curObj.(*crdv1beta1.ClusterGroup)
		reason, allowed = g.validateCG(curCG)
	case *crdv1beta1.Group:
		curG = curObj.(*crdv1beta1.Group)
		reason, allowed = g.validateG(curG)
	}
	return reason, allowed
}

// deleteValidate validates the DELETE events of Group, ClusterGroup resources.
func (g *groupValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}

func (a *adminPolicyValidator) validateAdminNP(anp *v1alpha1.AdminNetworkPolicy) (string, bool) {
	if anpHasNamespaceLabelRule(anp) {
		return "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea", false
	}
	return "", true
}

func (a *adminPolicyValidator) validateBANP(banp *v1alpha1.BaselineAdminNetworkPolicy) (string, bool) {
	if banpHasNamespaceLabelRule(banp) {
		return "SameLabels and NotSameLabels namespace selection are not yet supported by Antrea", false
	}
	return "", true
}

func (a *adminPolicyValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	var reason string
	var allowed bool
	switch curObj.(type) {
	case *v1alpha1.AdminNetworkPolicy:
		curANP := curObj.(*v1alpha1.AdminNetworkPolicy)
		reason, allowed = a.validateAdminNP(curANP)
	case *v1alpha1.BaselineAdminNetworkPolicy:
		curBANP := curObj.(*v1alpha1.BaselineAdminNetworkPolicy)
		reason, allowed = a.validateBANP(curBANP)
	}
	return reason, allowed
}

func (a *adminPolicyValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return a.createValidate(curObj, userInfo)
}

func (a *adminPolicyValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}

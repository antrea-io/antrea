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
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
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
	vr.RegisterAntreaPolicyValidator(&apv)
	vr.RegisterTierValidator(&tv)
	vr.RegisterGroupValidator(&gv)
	return &vr
}

// Validate function validates a ClusterGroup, Tier or Antrea Policy object
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
		var curTier, oldTier crdv1alpha1.Tier
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
		var curCG, oldCG crdv1alpha2.ClusterGroup
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
	case "ClusterNetworkPolicy":
		klog.V(2).Info("Validating Antrea ClusterNetworkPolicy CRD")
		var curCNP, oldCNP crdv1alpha1.ClusterNetworkPolicy
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
		msg, allowed = v.validateAntreaPolicy(&curCNP, &oldCNP, op, ui)
	case "NetworkPolicy":
		klog.V(2).Info("Validating Antrea NetworkPolicy CRD")
		var curANP, oldANP crdv1alpha1.NetworkPolicy
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
		msg, allowed = v.validateAntreaPolicy(&curANP, &oldANP, op, ui)
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

// validatePort validates if ports is valid
func (a *antreaPolicyValidator) validatePort(ingress, egress []crdv1alpha1.Rule) error {
	isValid := func(rules []crdv1alpha1.Rule) error {
		for _, rule := range rules {
			for _, port := range rule.Ports {
				if port.EndPort == nil {
					continue
				}
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

// validateAntreaGroup validates the admission of a ClusterGroup resource
func (v *NetworkPolicyValidator) validateAntreaGroup(curCG, oldCG *crdv1alpha2.ClusterGroup, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
	allowed := true
	reason := ""
	switch op {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.createValidate(curCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.updateValidate(curCG, oldCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for ClusterGroup")
		for _, val := range v.groupValidators {
			reason, allowed = val.deleteValidate(oldCG, userInfo)
			if !allowed {
				return reason, allowed
			}
		}
	}
	return reason, allowed
}

// validateTier validates the admission of a Tier resource
func (v *NetworkPolicyValidator) validateTier(curTier, oldTier *crdv1alpha1.Tier, op admv1.Operation, userInfo authenticationv1.UserInfo) (string, bool) {
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
	if err != nil {
		return false
	}
	return true
}

func (v *antreaPolicyValidator) clusterGroupExists(name string) bool {
	_, err := v.networkPolicyController.cgLister.Get(name)
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

// createValidate validates the CREATE events of Antrea-native policies,
func (a *antreaPolicyValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	var tier string
	var ingress, egress []crdv1alpha1.Rule
	var specAppliedTo []crdv1alpha1.NetworkPolicyPeer
	switch curObj.(type) {
	case *crdv1alpha1.ClusterNetworkPolicy:
		curCNP := curObj.(*crdv1alpha1.ClusterNetworkPolicy)
		tier = curCNP.Spec.Tier
		ingress = curCNP.Spec.Ingress
		egress = curCNP.Spec.Egress
		specAppliedTo = curCNP.Spec.AppliedTo
	case *crdv1alpha1.NetworkPolicy:
		curANP := curObj.(*crdv1alpha1.NetworkPolicy)
		tier = curANP.Spec.Tier
		ingress = curANP.Spec.Ingress
		egress = curANP.Spec.Egress
		specAppliedTo = curANP.Spec.AppliedTo
	}
	reason, allowed := a.validateTierForPolicy(tier)
	if !allowed {
		return reason, allowed
	}
	if ruleNameUnique := a.validateRuleName(ingress, egress); !ruleNameUnique {
		return fmt.Sprint("rules names must be unique within the policy"), false
	}
	reason, allowed = a.validateAppliedTo(ingress, egress, specAppliedTo)
	if !allowed {
		return reason, allowed
	}
	reason, allowed = a.validatePeers(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if err := a.validatePort(ingress, egress); err != nil {
		return err.Error(), false
	}
	return "", true
}

// validateRuleName validates if the name of each rule is unique within a policy
func (v *antreaPolicyValidator) validateRuleName(ingress, egress []crdv1alpha1.Rule) bool {
	uniqueRuleName := sets.NewString()
	isUnique := func(rules []crdv1alpha1.Rule) bool {
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

func (a *antreaPolicyValidator) validateAppliedTo(ingress, egress []crdv1alpha1.Rule, specAppliedTo []crdv1alpha1.NetworkPolicyPeer) (string, bool) {
	appliedToInSpec := len(specAppliedTo) != 0
	countAppliedToInRules := func(rules []crdv1alpha1.Rule) int {
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
	// Ensure CG exists
	checkAppTo := func(appTos []crdv1alpha1.NetworkPolicyPeer) bool {
		for _, appTo := range specAppliedTo {
			if appTo.Group != "" {
				// Ensure that group exists
				if !a.clusterGroupExists(appTo.Group) {
					return false
				}
			}
		}
		return true
	}
	if appliedToInSpec {
		if !checkAppTo(specAppliedTo) {
			return fmt.Sprintf("cluster group referenced in appliedTo does not exist"), false
		}
	} else {
		for _, rule := range ingress {
			if !checkAppTo(rule.AppliedTo) {
				return fmt.Sprintf("cluster group referenced in appliedTo does not exist"), false
			}
		}
		for _, rule := range egress {
			if !checkAppTo(rule.AppliedTo) {
				return fmt.Sprintf("cluster group referenced in appliedTo does not exist"), false
			}
		}
	}
	return "", true
}

// validatePeers ensures that the NetworkPolicyPeer object set in rules are valid, i.e.
// currently it ensures that a Group cannot be set with other stand-alone selectors or IPBlock.
func (a *antreaPolicyValidator) validatePeers(ingress, egress []crdv1alpha1.Rule) (string, bool) {
	checkPeers := func(peers []crdv1alpha1.NetworkPolicyPeer) (string, bool) {
		for _, peer := range peers {
			if peer.NamespaceSelector != nil && peer.Namespaces != nil {
				return "namespaces and namespaceSelector cannot be set at the same time for a single NetworkPolicyPeer", false
			}
			if peer.Group == "" {
				continue
			}
			if peer.PodSelector != nil || peer.IPBlock != nil || peer.NamespaceSelector != nil {
				return "group cannot be set with other peers in rules", false
			}
			// Ensure that group exists
			if !a.clusterGroupExists(peer.Group) {
				return fmt.Sprintf("cluster group %s referenced in rules does not exist", peer.Group), false
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
		msg, isValid := checkPeers(rule.To)
		if !isValid {
			return msg, false
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

// updateValidate validates the UPDATE events of Antrea-native policies.
func (a *antreaPolicyValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	var tier string
	var ingress, egress []crdv1alpha1.Rule
	var specAppliedTo []crdv1alpha1.NetworkPolicyPeer
	switch curObj.(type) {
	case *crdv1alpha1.ClusterNetworkPolicy:
		curCNP := curObj.(*crdv1alpha1.ClusterNetworkPolicy)
		tier = curCNP.Spec.Tier
		ingress = curCNP.Spec.Ingress
		egress = curCNP.Spec.Egress
		specAppliedTo = curCNP.Spec.AppliedTo
	case *crdv1alpha1.NetworkPolicy:
		curANP := curObj.(*crdv1alpha1.NetworkPolicy)
		tier = curANP.Spec.Tier
		ingress = curANP.Spec.Ingress
		egress = curANP.Spec.Egress
		specAppliedTo = curANP.Spec.AppliedTo
	}
	reason, allowed := a.validateAppliedTo(ingress, egress, specAppliedTo)
	if !allowed {
		return reason, allowed
	}
	if ruleNameUnique := a.validateRuleName(ingress, egress); !ruleNameUnique {
		return fmt.Sprint("rules names must be unique within the policy"), false
	}
	reason, allowed = a.validatePeers(ingress, egress)
	if !allowed {
		return reason, allowed
	}
	if err := a.validatePort(ingress, egress); err != nil {
		return err.Error(), false
	}
	return a.validateTierForPolicy(tier)
}

// deleteValidate validates the DELETE events of Antrea-native policies.
func (a *antreaPolicyValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	return "", true
}

// createValidate validates the CREATE events of Tier resources.
func (t *tierValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	if len(t.networkPolicyController.tierInformer.Informer().GetIndexer().ListIndexFuncValues(PriorityIndex)) >= maxSupportedTiers {
		return fmt.Sprintf("maximum number of Tiers supported: %d", maxSupportedTiers), false
	}
	curTier := curObj.(*crdv1alpha1.Tier)
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
	curTier := curObj.(*crdv1alpha1.Tier)
	oldTier := oldObj.(*crdv1alpha1.Tier)
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
	oldTier := oldObj.(*crdv1alpha1.Tier)
	if reservedTierNames.Has(oldTier.Name) {
		return fmt.Sprintf("cannot delete reserved tier %s", oldTier.Name), false
	}
	// Tier with existing ACNPs/ANPs cannot be deleted.
	cnps, err := t.networkPolicyController.cnpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(cnps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea ClusterNetworkPolicies", oldTier.Name, len(cnps)), false
	}
	anps, err := t.networkPolicyController.anpInformer.Informer().GetIndexer().ByIndex(TierIndex, oldTier.Name)
	if err != nil || len(anps) > 0 {
		return fmt.Sprintf("tier %s is referenced by %d Antrea NetworkPolicies", oldTier.Name, len(anps)), false
	}
	return "", true
}

// validateAntreaGroupSpec ensures that an IPBlock is not set along with namespaceSelector and/or a
// podSelector. Similarly, ExternalEntitySelector cannot be set with PodSelector.
func validateAntreaGroupSpec(s crdv1alpha2.GroupSpec) (string, bool) {
	errMsg := "At most one of podSelector, externalEntitySelector, serviceReference, ipBlock, ipBlocks or childGroups can be set for a ClusterGroup"
	if s.PodSelector != nil && s.ExternalEntitySelector != nil {
		return errMsg, false
	}
	selector, serviceRef, ipBlock, ipBlocks, childGroups := 0, 0, 0, 0, 0
	if s.NamespaceSelector != nil || s.ExternalEntitySelector != nil || s.PodSelector != nil {
		selector = 1
	}
	if s.IPBlock != nil {
		ipBlock = 1
	}
	if len(s.IPBlocks) > 0 {
		ipBlocks = 1
	}
	if s.ServiceReference != nil {
		serviceRef = 1
	}
	if len(s.ChildGroups) > 0 {
		childGroups = 1
	}
	if selector+serviceRef+ipBlock+ipBlocks+childGroups > 1 {
		return errMsg, false
	}
	return "", true
}

func (g *groupValidator) validateChildGroup(s *crdv1alpha2.ClusterGroup) (string, bool) {
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

// createValidate validates the CREATE events of ClusterGroup resources.
func (g *groupValidator) createValidate(curObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	curCG := curObj.(*crdv1alpha2.ClusterGroup)
	reason, allowed := validateAntreaGroupSpec(curCG.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildGroup(curCG)
}

// updateValidate validates the UPDATE events of ClusterGroup resources.
func (g *groupValidator) updateValidate(curObj, oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	curCG := curObj.(*crdv1alpha2.ClusterGroup)
	reason, allowed := validateAntreaGroupSpec(curCG.Spec)
	if !allowed {
		return reason, allowed
	}
	return g.validateChildGroup(curCG)
}

// deleteValidate validates the DELETE events of ClusterGroup resources.
func (g *groupValidator) deleteValidate(oldObj interface{}, userInfo authenticationv1.UserInfo) (string, bool) {
	oldCG := oldObj.(*crdv1alpha2.ClusterGroup)
	// ClusterGroup with existing ACNP references cannot be deleted.
	cnps, err := g.networkPolicyController.cnpInformer.Informer().GetIndexer().ByIndex(ClusterGroupIndex, oldCG.Name)
	if err != nil {
		return fmt.Sprintf("error occurred when retrieving Antrea ClusterNetworkPolicies that refer to ClusterGroup %s: %v", oldCG.Name, err), false
	}
	if len(cnps) > 0 {
		cnpNameList := make([]string, len(cnps))
		for i := range cnps {
			cnpObj := cnps[i].(*crdv1alpha1.ClusterNetworkPolicy)
			cnpNameList[i] = cnpObj.Name
		}
		return fmt.Sprintf("ClusterGroup %s is referenced by %d Antrea ClusterNetworkPolicies: %v", oldCG.Name, len(cnps), cnpNameList), false
	}
	return "", true
}

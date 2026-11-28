/*
Copyright 2022 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

const (
	antreaAgentSAName  = "antrea-agent"
	mcControllerSAName = "antrea-mc-controller"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-gateway,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=gateways,verbs=create;update,versions=v1alpha1,name=vgateway.kb.io,admissionReviewVersions={v1,v1beta1}
//+kubebuilder:rbac:groups=crd.antrea.io,resources=antreaagentinfos,verbs=get

// Gateway validator
type gatewayValidator struct {
	Client client.Client
	// agentInfoReader reads AntreaAgentInfos directly from the API server, so that
	// the Multi-cluster Controller does not need to cache all of them.
	agentInfoReader client.Reader
	decoder         admission.Decoder
	// namespace is the Namespace of antrea-mc-controller.
	namespace string
}

// Handle handles admission requests.
func (v *gatewayValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	gateway := &mcv1alpha1.Gateway{}
	err := v.decoder.Decode(req, gateway)
	if err != nil {
		klog.ErrorS(err, "Error while decoding Gateway", "Gateway", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Gateway can only be updated or created by antrea-mc-controller
	if req.Operation == admissionv1.Update || req.Operation == admissionv1.Create {
		ui := req.UserInfo
		saNamespace, saName, err := serviceaccount.SplitUsername(ui.Username)
		if err != nil {
			klog.ErrorS(err, "Error getting ServiceAccount name", "Gateway", req.Namespace+"/"+req.Name)
			return admission.Errored(http.StatusBadRequest, err)
		}
		// Each allowed ServiceAccount must be in its expected Namespace, so that a
		// same-named ServiceAccount in another Namespace cannot create or update Gateways.
		switch saName {
		case mcControllerSAName:
			if saNamespace != v.namespace {
				return admission.Denied(fmt.Sprintf("ServiceAccount %q is not in Namespace %q", ui.Username, v.namespace))
			}
		case antreaAgentSAName:
			// A Gateway has the same name as its Node. Only the Antrea Agent running on
			// that Node is allowed to create or update it.
			agentNamespace, err := v.getAntreaAgentNamespace(ctx, req.Name)
			if err != nil {
				if apierrors.IsNotFound(err) {
					return admission.Denied(fmt.Sprintf("no Antrea Agent is running on Node %q", req.Name))
				}
				klog.ErrorS(err, "Error getting Antrea Agent Namespace", "Gateway", klog.KRef(req.Namespace, req.Name))
				return admission.Errored(http.StatusInternalServerError, err)
			}
			if saNamespace != agentNamespace {
				return admission.Denied(fmt.Sprintf("ServiceAccount %q is not the Antrea Agent ServiceAccount of Node %q",
					ui.Username, req.Name))
			}
		default:
			return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("Gateway can only be created or updated by Antrea Agent or Multi-cluster Controller"))
		}
	}
	return admission.Allowed("")
}

// getAntreaAgentNamespace returns the Namespace of the Antrea Agent Pod running on
// the given Node, based on the Node's AntreaAgentInfo, which has the same name as
// the Node.
func (v *gatewayValidator) getAntreaAgentNamespace(ctx context.Context, nodeName string) (string, error) {
	agentInfo := &crdv1beta1.AntreaAgentInfo{}
	if err := v.agentInfoReader.Get(ctx, types.NamespacedName{Name: nodeName}, agentInfo); err != nil {
		return "", err
	}
	if agentInfo.PodRef.Namespace == "" {
		return "", fmt.Errorf("AntreaAgentInfo %s has no Pod information yet", nodeName)
	}
	return agentInfo.PodRef.Namespace, nil
}

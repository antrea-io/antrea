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
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

const (
	antreaAgentSAName  = "antrea-agent"
	mcControllerSAName = "antrea-mc-controller"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-gateway,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=gateways,verbs=create;update,versions=v1alpha1,name=vgateway.kb.io,admissionReviewVersions={v1,v1beta1}

// Gateway validator
type gatewayValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
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
		_, saName, err := serviceaccount.SplitUsername(ui.Username)
		if err != nil {
			klog.ErrorS(err, "Error getting ServiceAccount name", "Gateway", req.Namespace+"/"+req.Name)
			return admission.Errored(http.StatusBadRequest, err)
		}
		if saName != mcControllerSAName && saName != antreaAgentSAName {
			return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("Gateway can only be created or updated by Antrea Agent or Multi-cluster Controller"))
		}
	}
	return admission.Allowed("")
}

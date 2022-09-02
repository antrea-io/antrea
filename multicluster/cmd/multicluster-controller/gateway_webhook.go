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
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
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

	// Check if there is any existing Gateway.
	gatewayList := &mcv1alpha1.GatewayList{}
	if err := v.Client.List(context.TODO(), gatewayList, client.InNamespace(v.namespace)); err != nil {
		klog.ErrorS(err, "Error reading Gateway", "Namespace", v.namespace)
		return admission.Errored(http.StatusPreconditionFailed, err)
	}

	if req.Operation == admissionv1.Create && len(gatewayList.Items) > 0 {
		err := fmt.Errorf("multiple Gateways in a Namespace are not allowed")
		klog.ErrorS(err, "failed to create Gateway", "Gateway", klog.KObj(gateway), "Namespace", v.namespace)
		return admission.Errored(http.StatusPreconditionFailed, err)
	}
	return admission.Allowed("")
}

func (v *gatewayValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

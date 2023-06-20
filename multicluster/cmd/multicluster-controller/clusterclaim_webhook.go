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
	"encoding/json"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha2-clusterclaim,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clusterclaims,verbs=create;update;delete,versions=v1alpha2,name=vclusterclaim.kb.io,admissionReviewVersions={v1,v1beta1}

// ClusterClaim validator
type clusterClaimValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
	namespace string
}

// Handle handles admission requests.
func (v *clusterClaimValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	clusterClaim := &mcv1alpha2.ClusterClaim{}

	reqObj := req.Object
	if req.Operation == admissionv1.Delete {
		reqObj = req.OldObject
	}
	err := v.decoder.DecodeRaw(reqObj, clusterClaim)
	if err != nil {
		klog.ErrorS(err, "Error while decoding ClusterClaim", "ClusterClaim", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	switch req.Operation {
	case admissionv1.Create:
		if clusterClaim.Name != mcv1alpha2.WellKnownClusterClaimClusterSet && clusterClaim.Name != mcv1alpha2.WellKnownClusterClaimID {
			return admission.Denied(fmt.Sprintf("name %s is not valid. Only 'id.k8s.io' and 'clusterset.k8s.io' are valid names for ClusterClaim\n", clusterClaim.Name))
		}
	case admissionv1.Update:
		oldClusterClaim := &mcv1alpha2.ClusterClaim{}
		if req.OldObject.Raw != nil {
			if err := json.Unmarshal(req.OldObject.Raw, &oldClusterClaim); err != nil {
				klog.ErrorS(err, "Error while decoding old ClusterClaim", "ClusterClaim", klog.KObj(clusterClaim))
				return admission.Errored(http.StatusBadRequest, err)
			}
			if oldClusterClaim.Value != clusterClaim.Value {
				klog.ErrorS(err, "The field 'value' is immutable", "ClusterClaim", klog.KObj(clusterClaim))
				return admission.Denied("the field 'value' is immutable")
			}
			return admission.Allowed("")
		}
	case admissionv1.Delete:
		clusterSetList := &mcv1alpha1.ClusterSetList{}
		if err := v.Client.List(context.TODO(), clusterSetList, client.InNamespace(v.namespace)); err != nil {
			klog.ErrorS(err, "Error reading ClusterSet", "Namespace", v.namespace)
			return admission.Errored(http.StatusPreconditionFailed, err)
		}
		deny := false
		var existingClusterSet mcv1alpha1.ClusterSet
		if len(clusterSetList.Items) > 0 {
			// ClusterSet webhook will guarantee that there is at most one ClusterSet in a given Namespace.
			existingClusterSet = clusterSetList.Items[0]
			if clusterClaim.Value == existingClusterSet.Name || clusterClaim.Value == existingClusterSet.Spec.Leaders[0].ClusterID {
				deny = true
			} else {
				for _, member := range existingClusterSet.Spec.Members {
					if clusterClaim.Value == member.ClusterID {
						deny = true
						break
					}
				}
			}
		}
		// Deny ClusterClaim deletion if the ClusterClaim is referred in a ClusterSet.
		if deny {
			klog.ErrorS(err, "The ClusterClaim is referred by a ClusterSet. Cannot delete it", "ClusterClaim", klog.KObj(clusterClaim), "ClusterSet", klog.KObj(&existingClusterSet))
			return admission.Denied(fmt.Sprintf("the ClusterClaim %s is referred by a ClusterSet %s. Please delete the ClusterSet first\n", klog.KObj(clusterClaim), klog.KObj(&existingClusterSet)))
		}
		return admission.Allowed("")
	}
	return admission.Allowed("")
}

func (v *clusterClaimValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

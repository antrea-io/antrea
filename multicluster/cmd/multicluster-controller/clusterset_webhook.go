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

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha2-clusterset,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clustersets,verbs=create;update;delete,versions=v1alpha2,name=vclusterset.kb.io,admissionReviewVersions={v1,v1beta1}

// ClusterSet validator
type clusterSetValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
	namespace string
	role      string
}

// Handle handles admission requests.
func (v *clusterSetValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation == admissionv1.Delete {
		if v.role == "leader" {
			mcaList := &mcv1alpha1.MemberClusterAnnounceList{}
			if err := v.Client.List(context.TODO(), mcaList, client.InNamespace(v.namespace)); err != nil {
				return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("failed to check existing MemberClusterAnnounce before deleting the ClusterSet %s", req.Namespace+"/"+req.Name))
			}
			if len(mcaList.Items) > 0 {
				return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("failed to delete the ClusterSet %s since there are still member clusters connecting to this leader cluster", req.Namespace+"/"+req.Name))
			}
		}
		return admission.Allowed("")
	}

	clusterSet := &mcv1alpha2.ClusterSet{}
	err := v.decoder.Decode(req, clusterSet)
	if err != nil {
		klog.ErrorS(err, "Error while decoding ClusterSet", "ClusterSet", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	oldClusterSet := &mcv1alpha2.ClusterSet{}
	if req.OldObject.Raw != nil {
		if err := json.Unmarshal(req.OldObject.Raw, &oldClusterSet); err != nil {
			klog.ErrorS(err, "Error while decoding old ClusterSet", "ClusterSet", klog.KObj(clusterSet))
			return admission.Errored(http.StatusBadRequest, err)
		}

		if oldClusterSet.Spec.ClusterID != "" && oldClusterSet.Spec.ClusterID != clusterSet.Spec.ClusterID {
			klog.ErrorS(err, "the field 'clusterID' is immutable", "ClusterSet", klog.KObj(clusterSet))
			return admission.Denied("the field 'clusterID' is immutable")
		}
		// The `Leaders` is a required field, and OpenAPI spec also limits only a single item is allowed.
		if oldClusterSet.Spec.Leaders[0].ClusterID != clusterSet.Spec.Leaders[0].ClusterID {
			klog.ErrorS(err, "the field 'clusterID' of the leader is immutable", "ClusterSet", klog.KObj(clusterSet))
			return admission.Denied("the field 'clusterID' of the leader is immutable")
		}

		return admission.Allowed("")
	}

	// Check if there is any existing ClusterSet.
	clusterSetList := &mcv1alpha2.ClusterSetList{}
	if err := v.Client.List(context.TODO(), clusterSetList, client.InNamespace(v.namespace)); err != nil {
		klog.ErrorS(err, "Error reading ClusterSet", "Namespace", v.namespace)
		return admission.Errored(http.StatusPreconditionFailed, err)
	}

	if len(clusterSetList.Items) > 0 {
		err := fmt.Errorf("multiple ClusterSets in a Namespace are not allowed")
		klog.ErrorS(err, "ClusterSet", klog.KObj(clusterSet), "Namespace", v.namespace)
		return admission.Errored(http.StatusPreconditionFailed, err)
	}
	return admission.Allowed("")
}

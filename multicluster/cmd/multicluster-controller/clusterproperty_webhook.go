/*
Copyright 2023 Antrea Authors.

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
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-clusterproperty,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=clusterproperties,verbs=create;update;delete,versions=v1alpha1,name=vclusterproperty.kb.io,admissionReviewVersions={v1,v1beta1}

// ClusterProperty validator
type clusterPropertyValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
	namespace string
}

// Handle handles admission requests.
func (v *clusterPropertyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	clusterProperty := &mcv1alpha1.ClusterProperty{}
	err := v.decoder.Decode(req, clusterProperty)
	if err != nil {
		klog.ErrorS(err, "Error while decoding ClusterProperty", "ClusterProperty", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	if clusterProperty.Name == mcv1alpha1.WellKnownClusterPropertyID {
		if errs := validation.IsDNS1035Label(clusterProperty.Value); len(errs) != 0 {
			return admission.Denied(fmt.Sprintf("value %s is not valid. cluster.clusterset.k8s.io ClusterProperty must be strictly a valid DNS label %v\n", clusterProperty.Value, errs))
		}

	}

	switch req.Operation {
	case admissionv1.Create:
		if clusterProperty.Name != mcv1alpha1.WellKnownClusterPropertyClusterSet && clusterProperty.Name != mcv1alpha1.WellKnownClusterPropertyID {
			return admission.Denied(fmt.Sprintf("name %s is not valid. Only 'cluster.clusterset.k8s.io' and 'clusterset.k8s.io' are valid names for ClusterProperty\n", clusterProperty.Name))
		}
	case admissionv1.Update:
		oldClusterProperty := &mcv1alpha1.ClusterProperty{}
		if req.OldObject.Raw != nil {
			if err := json.Unmarshal(req.OldObject.Raw, &oldClusterProperty); err != nil {
				klog.ErrorS(err, "Error while decoding old ClusterProperty", "ClusterProperty", klog.KObj(clusterProperty))
				return admission.Errored(http.StatusBadRequest, err)
			}
			if oldClusterProperty.Value != clusterProperty.Value {
				klog.ErrorS(err, "The field 'value' is immutable", "ClusterProperty", klog.KObj(clusterProperty))
				return admission.Denied("the field 'value' is immutable")
			}
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
			if clusterProperty.Value == existingClusterSet.Spec.Leaders[0].ClusterID {
				deny = true
			} else {
				for _, member := range existingClusterSet.Spec.Members {
					if clusterProperty.Value == member.ClusterID {
						deny = true
						break
					}
				}
			}
		}
		// Deny ClusterProperty deletion if the ClusterProperty is referred in a ClusterSet.
		if deny {
			klog.ErrorS(err, "The ClusterProperty is referred by a ClusterSet. Cannot delete it", "ClusterProperty", klog.KObj(clusterProperty), "ClusterSet", klog.KObj(&existingClusterSet))
			return admission.Denied(fmt.Sprintf("the ClusterProperty %s is referred by a ClusterSet %s. Please delete the ClusterSet first\n", klog.KObj(clusterProperty), klog.KObj(&existingClusterSet)))
		}
	}
	return admission.Allowed("")
}

func (v *clusterPropertyValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

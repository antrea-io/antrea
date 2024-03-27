/*
Copyright 2021 Antrea Authors.

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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-memberclusterannounce,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=memberclusterannounces,verbs=create;update,versions=v1alpha1,name=vmemberclusterannounce.kb.io,admissionReviewVersions={v1,v1beta1}

type memberClusterAnnounceValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
	namespace string
}

// Handle handles admission requests.
func (v *memberClusterAnnounceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	memberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
	e := v.decoder.Decode(req, memberClusterAnnounce)
	if e != nil {
		klog.ErrorS(e, "Error while decoding")
		return admission.Errored(http.StatusBadRequest, e)
	}

	ui := req.UserInfo
	_, saName, err := serviceaccount.SplitUsername(ui.Username)
	if err != nil {
		klog.ErrorS(err, "Error getting ServiceAccount name", "MemberClusterAnnounce", req.Namespace+"/"+req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	serviceAccount := &v1.ServiceAccount{}
	if err := v.Client.Get(ctx, client.ObjectKey{Namespace: v.namespace, Name: saName}, serviceAccount); err != nil {
		klog.ErrorS(err, "Error getting ServiceAccount", "ServiceAccount", saName, "Namespace", v.namespace, "MemberClusterAnnounce", klog.KObj(memberClusterAnnounce))
		return admission.Errored(http.StatusPreconditionFailed, err)
	}

	var newObj, oldObj *mcv1alpha1.MemberClusterAnnounce
	if req.Object.Raw != nil {
		if err := json.Unmarshal(req.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error while decoding new MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberClusterAnnounce))
			return admission.Errored(http.StatusBadRequest, err)
		}
	}
	if req.OldObject.Raw != nil {
		if err := json.Unmarshal(req.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error while decoding old MemberClusterAnnounce", "MemberClusterAnnounce", klog.KObj(memberClusterAnnounce))
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	switch req.Operation {
	case admissionv1.Create:
		// Read the ClusterSet info
		clusterSetList := &mcv1alpha2.ClusterSetList{}
		if err := v.Client.List(context.TODO(), clusterSetList, client.InNamespace(v.namespace)); err != nil {
			klog.ErrorS(err, "Error reading ClusterSet", "Namespace", v.namespace)
			return admission.Errored(http.StatusPreconditionFailed, err)
		}

		if len(clusterSetList.Items) == 0 {
			klog.ErrorS(nil, "No ClusterSet found", "Namespace", v.namespace)
			return admission.Errored(http.StatusPreconditionFailed, fmt.Errorf("no ClusterSet found in Namespace %s", v.namespace))
		}
		clusterSet := clusterSetList.Items[0]
		if clusterSet.Name != memberClusterAnnounce.ClusterSetID {
			return admission.Denied("Unknown ClusterSet ID")
		}
		if clusterSet.Spec.Leaders[0].ClusterID != memberClusterAnnounce.LeaderClusterID {
			return admission.Denied("Leader cluster ID in the MemberClusterAnnounce does not match that in the ClusterSet")
		}
		return admission.Allowed("")
	case admissionv1.Update:
		// Member cluster will never change ClusterSet ID in MemberClusterAnnounce
		if newObj.ClusterSetID != oldObj.ClusterSetID || newObj.LeaderClusterID != oldObj.LeaderClusterID {
			return admission.Denied("ClusterSet ID or Leader Cluster ID cannot be changed")
		}
		return admission.Allowed("")
	default:
		return admission.Allowed("")
	}
}

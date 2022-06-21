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
	"fmt"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

//+kubebuilder:webhook:path=/validate-multicluster-crd-antrea-io-v1alpha1-memberclusterannounce,mutating=false,failurePolicy=fail,sideEffects=None,groups=multicluster.crd.antrea.io,resources=memberclusterannounces,verbs=create;update,versions=v1alpha1,name=vmemberclusterannounce.kb.io,admissionReviewVersions={v1,v1beta1}

// member cluster announce validator
type memberClusterAnnounceValidator struct {
	Client    client.Client
	decoder   *admission.Decoder
	namespace string
}

// Handle handles admission requests.
func (v *memberClusterAnnounceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	memberClusterAnnounce := &multiclusterv1alpha1.MemberClusterAnnounce{}
	e := v.decoder.Decode(req, memberClusterAnnounce)
	if e != nil {
		klog.ErrorS(e, "Error while decoding")
		return admission.Errored(http.StatusBadRequest, e)
	}

	ui := req.UserInfo
	_, saName, err := serviceaccount.SplitUsername(ui.Username)
	if err != nil {
		klog.ErrorS(err, "Error getting ServiceAccount name", "request", req)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// read the ClusterSet info
	clusterSetList := &multiclusterv1alpha1.ClusterSetList{}
	if err := v.Client.List(context.TODO(), clusterSetList, client.InNamespace(v.namespace)); err != nil {
		klog.ErrorS(err, "Error reading ClusterSet", "Namespace", v.namespace)
		return admission.Errored(http.StatusPreconditionFailed, err)
	}

	if len(clusterSetList.Items) != 1 {
		return admission.Errored(http.StatusPreconditionFailed,
			fmt.Errorf("invalid ClusterSet config in the leader cluster, please contact your administrator"))
	}

	clusterSet := clusterSetList.Items[0]
	if clusterSet.Name == memberClusterAnnounce.ClusterSetID {
		for _, member := range clusterSet.Spec.Members {
			if member.ClusterID == memberClusterAnnounce.ClusterID {
				// validate the ServiceAccount used is correct
				if member.ServiceAccount == saName {
					return admission.Allowed("")
				} else {
					return admission.Denied("Member does not have permissions")
				}
			}
		}
	}

	return admission.Denied("Unknown member")
}

func (v *memberClusterAnnounceValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}

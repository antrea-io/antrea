// Copyright 2021 Antrea Authors
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

package webhook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type jsonPatchOperation string

const (
	jsonPatchReplaceOp jsonPatchOperation = "replace"
	// LabelMetadataName is a well known reserved label key used by Antrea to store the resource's name
	// as a label value.
	LabelMetadataName = "antrea.io/metadata.name"
)

// jsonPatch contains necessary info that MutatingWebhook required
type jsonPatch struct {
	// Op represents the operation of this mutation
	Op jsonPatchOperation `json:"op"`
	// Path is a jsonPath to locate the value that need to be mutated
	Path string `json:"path"`
	// Value represents the value which is used in mutation
	Value interface{} `json:"value,omitempty"`
}

func HandleMutationLabels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		klog.V(2).Info("Received request to mutate resource labels")
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = ioutil.ReadAll(r.Body)
		}
		if len(reqBody) == 0 {
			klog.Errorf("Mutation webhook labelsmutator received empty request body")
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}
		// verify the content type is accurate
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			klog.Errorf("Invalid Content-Type=%s, expected application/json", contentType)
			http.Error(w, "invalid Content-Type, expected `application/json`", http.StatusUnsupportedMediaType)
			return
		}
		var admissionResponse *admv1.AdmissionResponse
		ar := admv1.AdmissionReview{}
		ar.TypeMeta.Kind = "AdmissionReview"
		ar.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if err := json.Unmarshal(reqBody, &ar); err != nil {
			klog.Errorf("Label mutation received incorrect body")
			admissionResponse = getAdmissionResponseForErr(err)
		} else {
			admissionResponse = mutateResourceLabels(&ar)
		}
		aReview := admv1.AdmissionReview{}
		aReview.TypeMeta.Kind = "AdmissionReview"
		aReview.TypeMeta.APIVersion = "admission.k8s.io/v1"
		if admissionResponse != nil {
			aReview.Response = admissionResponse
			if ar.Request != nil {
				aReview.Response.UID = ar.Request.UID
			}
		}
		resp, err := json.Marshal(aReview)
		if err != nil {
			klog.Errorf("Unable to encode response during mutation: %v", err)
			http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		}
		klog.V(2).Infof("Writing mutation response to MutationAdmissionHook")
		if _, err := w.Write(resp); err != nil {
			klog.Errorf("Unable to write response during mutation: %v", err)
			http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
		}
	}
}

// mutateResourceLabels mutates the resource labels and inserts Antrea required labels.
func mutateResourceLabels(ar *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var patch []byte
	var allowed bool
	var msg string
	// At the moment we only mutate Namespace labels.
	var nsObj v1.Namespace
	patchType := admv1.PatchTypeJSONPatch

	op := ar.Request.Operation
	curRaw := ar.Request.Object.Raw
	klog.V(2).Info("Mutating resource labels")
	if curRaw != nil {
		if err := json.Unmarshal(curRaw, &nsObj); err != nil {
			klog.Errorf("Error de-serializing current resource")
			return getAdmissionResponseForErr(err)
		}
	}
	msg, allowed, patch = mutateLabels(op, nsObj.Labels, nsObj.Name)
	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	rsp := &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
	if patch != nil {
		rsp.PatchType = &patchType
		rsp.Patch = patch
	}
	return rsp
}

// mutateLabels mutates the resource's labels and forcefully inserts the resource's name as a well
// known label to ensure that the label is never modified or removed by CREATE and UPDATE events.
func mutateLabels(op admv1.Operation, l map[string]string, name string) (string, bool, []byte) {
	switch op {
	case admv1.Create, admv1.Update:
		if l == nil {
			l = map[string]string{}
		} else {
			metaNameLabelVal, exists := l[LabelMetadataName]
			if exists && metaNameLabelVal == name {
				return "", true, nil
			}
		}
		// Forcefully stomp the resource's metadata.name value as a label.
		l[LabelMetadataName] = name
		patch, err := createLabelsReplacePatch(l)
		if err != nil {
			return fmt.Sprintf("unable to generate mutating patch: %v", err), false, patch
		}
		return "", true, patch
	}
	return "", true, nil
}

// createLabelsReplacePatch generates a serialized patch from the new list of labels.
func createLabelsReplacePatch(l map[string]string) ([]byte, error) {
	var patch []jsonPatch
	patch = append(patch, jsonPatch{
		Op:    jsonPatchReplaceOp,
		Path:  fmt.Sprintf("/metadata/labels"),
		Value: l,
	})
	return json.Marshal(patch)
}

func getAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	if err == nil {
		return nil
	}
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetAdmissionResponseForErr(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		expResp *admv1.AdmissionResponse
	}{
		{
			name:    "error-nil",
			err:     nil,
			expResp: nil,
		},
		{
			name: "error-resp",
			err:  errors.New("Error de-serializing current resource"),
			expResp: &admv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "Error de-serializing current resource",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualValue := getAdmissionResponseForErr(tt.err)
			assert.Equal(t, tt.expResp, actualValue)
		})
	}
}

func TestCreateLabelsReplacePatch(t *testing.T) {
	labelsPath := "/metadata/labels"
	nameLabel := map[string]string{
		LabelMetadataName: "my-ns",
	}
	tests := []struct {
		name    string
		labels  map[string]string
		expResp []jsonPatch
	}{
		{
			name:   "labels-empty",
			labels: map[string]string{},
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: map[string]string{},
				},
			},
		},
		{
			name:   "labels-ns-name",
			labels: nameLabel,
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: nameLabel,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualValue, _ := createLabelsReplacePatch(tt.labels)
			expValue, _ := json.Marshal(tt.expResp)
			assert.Equal(t, expValue, actualValue)
		})
	}
}

func TestMutateLabels(t *testing.T) {
	labelsPath := "/metadata/labels"
	nameLabel := map[string]string{
		LabelMetadataName: "my-ns",
	}
	randomLabel := map[string]string{
		"random": "label",
	}
	randomLabelPlusNameLabel := map[string]string{
		"random":          "label",
		LabelMetadataName: "my-ns",
	}
	tests := []struct {
		name      string
		op        admv1.Operation
		resName   string
		labels    map[string]string
		isAllowed bool
		msg       string
		expResp   []jsonPatch
	}{
		{
			name:      "mutate-labels-empty-create",
			op:        admv1.Create,
			resName:   "my-ns",
			labels:    map[string]string{},
			isAllowed: true,
			msg:       "",
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: nameLabel,
				},
			},
		},
		{
			name:      "mutate-labels-empty-update",
			op:        admv1.Update,
			resName:   "my-ns",
			labels:    map[string]string{},
			isAllowed: true,
			msg:       "",
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: nameLabel,
				},
			},
		},
		{
			name:      "mutate-labels-empty-delete",
			op:        admv1.Delete,
			resName:   "my-ns",
			labels:    map[string]string{},
			isAllowed: true,
			msg:       "",
			expResp:   []jsonPatch{},
		},
		{
			name:      "mutate-labels-random-create",
			op:        admv1.Create,
			resName:   "my-ns",
			labels:    randomLabel,
			isAllowed: true,
			msg:       "",
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: randomLabelPlusNameLabel,
				},
			},
		},
		{
			name:      "mutate-labels-random-update",
			op:        admv1.Update,
			resName:   "my-ns",
			labels:    randomLabel,
			isAllowed: true,
			msg:       "",
			expResp: []jsonPatch{
				{
					Op:    jsonPatchReplaceOp,
					Path:  labelsPath,
					Value: randomLabelPlusNameLabel,
				},
			},
		},
		{
			name:      "mutate-labels-random-delete",
			op:        admv1.Delete,
			resName:   "my-ns",
			labels:    randomLabel,
			isAllowed: true,
			msg:       "",
			expResp:   []jsonPatch{},
		},
		{
			name:      "mutate-labels-existing-name-label-create",
			op:        admv1.Create,
			resName:   "my-ns",
			labels:    nameLabel,
			isAllowed: true,
			msg:       "",
			expResp:   []jsonPatch{},
		},
		{
			name:      "mutate-labels-existing-name-label-update",
			op:        admv1.Update,
			resName:   "my-ns",
			labels:    nameLabel,
			isAllowed: true,
			msg:       "",
			expResp:   []jsonPatch{},
		},
		{
			name:      "mutate-labels-existing-name-label-delete",
			op:        admv1.Delete,
			resName:   "my-ns",
			labels:    nameLabel,
			isAllowed: true,
			msg:       "",
			expResp:   []jsonPatch{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expValue []byte
			labelsToMutate := map[string]string{}
			for k, v := range tt.labels {
				labelsToMutate[k] = v
			}
			actualMsg, actualAllowed, actualResp := mutateLabels(tt.op, labelsToMutate, tt.resName)
			if len(tt.expResp) > 0 {
				expValue, _ = json.Marshal(tt.expResp)
			}
			assert.Equal(t, expValue, actualResp)
			assert.Equal(t, tt.isAllowed, actualAllowed)
			assert.Equal(t, tt.msg, actualMsg)
		})
	}
}

// Copyright 2026 Antrea Authors
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

package crdconversion

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	registrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func TestValidateAdmissionRequest(t *testing.T) {
	for _, kind := range []string{"Egress", "ExternalIPPool"} {
		for _, version := range []string{"v1beta1", "v1beta2"} {
			t.Run(kind+"/"+version, func(t *testing.T) {
				object := func(annotations map[string]string) runtime.RawExtension {
					raw, err := json.Marshal(map[string]interface{}{
						"apiVersion": "crd.antrea.io/" + version, "kind": kind,
						"metadata": map[string]interface{}{"annotations": annotations},
					})
					require.NoError(t, err)
					return runtime.RawExtension{Raw: raw}
				}
				for _, tc := range []struct {
					name                        string
					operation                   admv1.Operation
					oldAnnotations, annotations map[string]string
					requestVersion              string
					allowed                     bool
				}{
					{name: "ordinary create", operation: admv1.Create, allowed: true},
					{name: "annotated create", operation: admv1.Create, annotations: map[string]string{conversionDataAnnotation: "{}"}},
					{name: "empty reserved annotation on create", operation: admv1.Create, annotations: map[string]string{conversionDataAnnotation: ""}},
					{name: "ordinary metadata update", operation: admv1.Update, annotations: map[string]string{"example.com/note": "updated"}, allowed: true},
					{name: "unchanged conversion state", operation: admv1.Update, oldAnnotations: map[string]string{conversionDataAnnotation: "stored"}, annotations: map[string]string{conversionDataAnnotation: "stored", "example.com/note": "updated"}, allowed: true},
					{name: "added conversion state", operation: admv1.Update, annotations: map[string]string{conversionDataAnnotation: "forged"}},
					{name: "changed conversion state", operation: admv1.Update, oldAnnotations: map[string]string{conversionDataAnnotation: "stored"}, annotations: map[string]string{conversionDataAnnotation: "forged"}},
					{name: "removed conversion state", operation: admv1.Update, oldAnnotations: map[string]string{conversionDataAnnotation: "stored"}},
					{name: "delete despite invalid annotation", operation: admv1.Delete, annotations: map[string]string{conversionDataAnnotation: "invalid"}, allowed: true},
					{name: "exact request", operation: admv1.Create, requestVersion: version, allowed: true},
					{name: "converted request", operation: admv1.Create, requestVersion: map[string]string{"v1beta1": "v1beta2", "v1beta2": "v1beta1"}[version]},
				} {
					t.Run(tc.name, func(t *testing.T) {
						req := &admv1.AdmissionRequest{
							Operation: tc.operation,
							Resource:  metav1.GroupVersionResource{Group: "crd.antrea.io", Version: version},
							Object:    object(tc.annotations), OldObject: object(tc.oldAnnotations),
						}
						if tc.requestVersion != "" {
							req.RequestResource = &metav1.GroupVersionResource{Group: "crd.antrea.io", Version: tc.requestVersion}
						}
						err := ValidateAdmissionRequest(req)
						if tc.allowed {
							require.NoError(t, err)
						} else {
							require.Error(t, err)
						}
					})
				}
			})
		}
	}
}

func TestVersionedWebhookRegistrations(t *testing.T) {
	// With Exact matching, omitting a served version silently bypasses validation.
	// Check every distributed manifest, including cloud-specific installation variants.
	for _, name := range []string{"antrea", "antrea-aks", "antrea-eks", "antrea-gke", "antrea-ipsec"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open("../../../build/yamls/" + name + ".yml")
			require.NoError(t, err)
			defer f.Close()
			decoder := utilyaml.NewYAMLOrJSONDecoder(f, 4096)
			found := map[string]bool{}
			for {
				var configuration registrationv1.ValidatingWebhookConfiguration
				err = decoder.Decode(&configuration)
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				if configuration.Kind != "ValidatingWebhookConfiguration" {
					continue
				}
				for _, webhook := range configuration.Webhooks {
					if webhook.Name != "egressvalidator.antrea.io" && webhook.Name != "externalippoolvalidator.antrea.io" {
						continue
					}
					found[webhook.Name] = true
					require.NotNil(t, webhook.MatchPolicy)
					assert.Equal(t, registrationv1.Exact, *webhook.MatchPolicy)
					require.Len(t, webhook.Rules, 1)
					assert.Contains(t, webhook.Rules[0].APIVersions, "v1beta1")
					assert.Contains(t, webhook.Rules[0].APIVersions, "v1beta2")
				}
			}
			require.Len(t, found, 2)
		})
	}
}

// Copyright 2022 Antrea Authors
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

package get

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcscheme "antrea.io/antrea/pkg/antctl/raw/multicluster/scheme"
)

func TestGetAccessToken(t *testing.T) {
	secretList := &corev1.SecretList{
		Items: []corev1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "default-member-token",
					Annotations: map[string]string{
						"multicluster.antrea.io/created-by-antctl": "true",
					},
				},
				Data: map[string][]byte{"token": []byte("12345")},
			},
		},
	}

	secretListNoAnnotations := &corev1.SecretList{
		Items: []corev1.Secret{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "default-member-token",
				},
				Data: map[string][]byte{"token": []byte("12345")},
			},
		},
	}

	tests := []struct {
		name            string
		existingSecrets *corev1.SecretList
		output          string
		args            []string
		expectedOutput  string
		namespace       string
		allNamespaces   bool
	}{
		{
			name:            "get single Secret",
			existingSecrets: secretList,
			args:            []string{"default-member-token"},
			namespace:       "default",
			expectedOutput:  "NAMESPACE NAME                \ndefault   default-member-token\n",
		},
		{
			name:            "get single Secret with json output",
			existingSecrets: secretList,
			args:            []string{"default-member-token"},
			namespace:       "default",
			output:          "json",
			expectedOutput:  "[\n  {\n    \"kind\": \"Secret\",\n    \"apiVersion\": \"v1\",\n    \"metadata\": {\n      \"name\": \"default-member-token\",\n      \"creationTimestamp\": null\n    },\n    \"data\": {\n      \"token\": \"MTIzNDU=\"\n    },\n    \"type\": \"Opaque\"\n  }\n]\n",
		},
		{
			name:            "get single Secret with yaml output",
			existingSecrets: secretList,
			args:            []string{"default-member-token"},
			namespace:       "default",
			output:          "yaml",
			expectedOutput:  "- apiVersion: v1\n  data:\n    token: MTIzNDU=\n  kind: Secret\n  metadata:\n    creationTimestamp: null\n    name: default-member-token\n  type: Opaque\n",
		},
		{
			name:           "get non-existing Secret",
			args:           []string{"default-member-token"},
			namespace:      "default",
			expectedOutput: "No token found in Namespace default\n",
		},
		{
			name:            "get all Secret but empty result",
			existingSecrets: secretListNoAnnotations,
			args:            []string{"default-member-token"},
			namespace:       "default",
			expectedOutput:  "No token found in Namespace default\n",
		},
		{
			name:          "get all Secrets",
			allNamespaces: true,
			existingSecrets: &corev1.SecretList{
				Items: []corev1.Secret{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "default-member-token",
							Annotations: map[string]string{
								"multicluster.antrea.io/created-by-antctl": "true",
							},
						},
						Data: map[string][]byte{"token": []byte("12345")},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default1",
							Name:      "default-member-token1",
							Annotations: map[string]string{
								"multicluster.antrea.io/created-by-antctl": "true",
							},
						},
						Data: map[string][]byte{"token": []byte("123451")},
					},
				},
			},
			expectedOutput: "NAMESPACE NAME                 \ndefault   default-member-token \ndefault1  default-member-token1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewMemberTokenCommand()
			buf := new(bytes.Buffer)
			cmd.SetOutput(buf)
			cmd.SetOut(buf)
			cmd.SetErr(buf)

			fakeClient := fake.NewClientBuilder().WithScheme(mcscheme.Scheme).Build()
			if tt.existingSecrets != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(mcscheme.Scheme).WithLists(tt.existingSecrets).Build()
			}
			optionsToken.k8sClient = fakeClient
			if tt.allNamespaces {
				optionsToken.allNamespaces = true
			}
			if tt.namespace != "" {
				optionsToken.namespace = tt.namespace
			}
			if tt.output != "" {
				optionsToken.outputFormat = tt.output
			}
			err := cmd.Execute()
			if err != nil {
				assert.Equal(t, tt.expectedOutput, err.Error())
			} else {
				assert.Equal(t, tt.expectedOutput, buf.String())
			}
		})
	}
}

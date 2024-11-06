// Copyright 2024 Antrea Authors.
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

package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testKeyString   = "it is a valid API key"
	testTokenString = "it is a valid token"
)

type secretConfig struct {
	name string
	data map[string][]byte
}

func prepareSecrets(ns string, secretConfigs []secretConfig) []*corev1.Secret {
	secrets := make([]*corev1.Secret, 0)
	for _, s := range secretConfigs {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      s.name,
				Namespace: ns,
			},
			Data: s.data,
		}
		secrets = append(secrets, secret)
	}
	return secrets
}

type testAuthConfig struct {
	AuthType   AuthType
	AuthSecret *corev1.SecretReference
}

func TestParseFileServerAuth(t *testing.T) {
	ns := "ns-auth"
	apiKey := testKeyString
	token := testTokenString
	usr := "user"
	pwd := "pwd123456"
	var secretObjects []runtime.Object
	for _, s := range prepareSecrets(ns, []secretConfig{
		{name: "s1", data: map[string][]byte{SecretKeyWithAPIKey: []byte(apiKey)}},
		{name: "s2", data: map[string][]byte{SecretKeyWithBearerToken: []byte(token)}},
		{name: "s3", data: map[string][]byte{SecretKeyWithUsername: []byte(usr), SecretKeyWithPassword: []byte(pwd)}},
		{name: "invalid-base64", data: map[string][]byte{SecretKeyWithAPIKey: []byte("invalid string to decode with base64")}},
		{name: "invalid-secret", data: map[string][]byte{"unknown": []byte(apiKey)}},
	}) {
		secretObjects = append(secretObjects, s)
	}

	testClient := fake.NewSimpleClientset(secretObjects...)
	for _, tc := range []struct {
		authentication testAuthConfig
		expectedError  string
		expectedAuth   *AuthConfiguration
	}{
		{
			authentication: testAuthConfig{
				AuthType: APIKeyType,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s1",
				},
			},
			expectedAuth: &AuthConfiguration{
				AuthType: APIKeyType,
				APIKey:   testKeyString,
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerTokenType,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s2",
				},
			},
			expectedAuth: &AuthConfiguration{
				AuthType:    BearerTokenType,
				BearerToken: testTokenString,
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BasicAuthenticationType,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "s3",
				},
			},
			expectedAuth: &AuthConfiguration{
				AuthType: BasicAuthenticationType,
				BasicAuthentication: &BasicAuthentication{
					Username: usr,
					Password: pwd,
				},
			},
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerTokenType,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "invalid-secret",
				},
			},
			expectedError: fmt.Sprintf("missing key \"%s\" in authentication Secret %s/invalid-secret", SecretKeyWithBearerToken, ns),
		},
		{
			authentication: testAuthConfig{
				AuthType: BearerTokenType,
				AuthSecret: &corev1.SecretReference{
					Namespace: ns,
					Name:      "not-exist",
				},
			},
			expectedError: fmt.Sprintf("unable to get Secret with name not-exist in Namespace %s", ns),
		},
		{
			authentication: testAuthConfig{
				AuthType:   APIKeyType,
				AuthSecret: nil,
			},
			expectedError: "authentication is not specified",
		},
	} {
		auth, err := GetAuthConfigurationFromSecret(context.TODO(), tc.authentication.AuthType, tc.authentication.AuthSecret, testClient)
		if tc.expectedError != "" {
			assert.Contains(t, err.Error(), tc.expectedError)
		} else {
			assert.Equal(t, tc.expectedAuth, auth)
		}
	}
}

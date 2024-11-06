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

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	SecretKeyWithAPIKey      = "apikey"
	SecretKeyWithBearerToken = "token"
	SecretKeyWithUsername    = "username"
	SecretKeyWithPassword    = "password"
)

// AuthType defines the authentication type to access a file server.
type AuthType string

const (
	APIKeyType              AuthType = "APIKey"
	BearerTokenType         AuthType = "BearerToken"
	BasicAuthenticationType AuthType = "BasicAuthentication"
)

type BasicAuthentication struct {
	Username string
	Password string
}

type AuthConfiguration struct {
	AuthType            AuthType
	BearerToken         string
	APIKey              string
	BasicAuthentication *BasicAuthentication
}

// GetAuthConfigurationFromSecret returns the authentication from a Secret.
// The authentication is stored in the Secret Data with a key decided by the authType, and encoded using base64.
func GetAuthConfigurationFromSecret(ctx context.Context, authType AuthType, secretRef *v1.SecretReference, kubeClient clientset.Interface) (*AuthConfiguration, error) {
	if secretRef == nil {
		return nil, fmt.Errorf("authentication is not specified")
	}
	secret, err := kubeClient.CoreV1().Secrets(secretRef.Namespace).Get(ctx, secretRef.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get Secret with name %s in Namespace %s: %w", secretRef.Name, secretRef.Namespace, err)
	}
	parseAuthValue := func(secretData map[string][]byte, key string) (string, error) {
		authValue, found := secret.Data[key]
		if !found {
			return "", fmt.Errorf("missing key %q in authentication Secret %s/%s", key, secretRef.Namespace, secretRef.Name)
		}
		return string(authValue), nil
	}
	switch authType {
	case APIKeyType:
		value, err := parseAuthValue(secret.Data, SecretKeyWithAPIKey)
		if err != nil {
			return nil, err
		}
		return &AuthConfiguration{
			AuthType: APIKeyType,
			APIKey:   value,
		}, nil
	case BearerTokenType:
		value, err := parseAuthValue(secret.Data, SecretKeyWithBearerToken)
		if err != nil {
			return nil, err
		}
		return &AuthConfiguration{
			AuthType:    BearerTokenType,
			BearerToken: value,
		}, nil
	case BasicAuthenticationType:
		username, err := parseAuthValue(secret.Data, SecretKeyWithUsername)
		if err != nil {
			return nil, err
		}
		password, err := parseAuthValue(secret.Data, SecretKeyWithPassword)
		if err != nil {
			return nil, err
		}
		return &AuthConfiguration{
			AuthType: BasicAuthenticationType,
			BasicAuthentication: &BasicAuthentication{
				Username: username,
				Password: password,
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported authentication type %s", authType)
}

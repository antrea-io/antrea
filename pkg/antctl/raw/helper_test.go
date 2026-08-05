// Copyright 2023 Antrea Authors
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

package raw

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	cert "antrea.io/antrea/pkg/apiserver/certificate"
	antreafakeclient "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/util/k8s"
)

const nodeIP = "8.8.8.8"

var (
	node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeExternalIP,
					Address: nodeIP,
				},
			},
		},
	}
	controllerInfo = &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-controller",
		},
		NodeRef: corev1.ObjectReference{
			Kind: "Node",
			Name: node.Name,
		},
		PodRef: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: "kube-system",
			Name:      "antrea-controller-foo",
		},
		APIPort: apis.AntreaControllerAPIPort,
	}
	agentInfo = &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.Name,
		},
		NodeRef: corev1.ObjectReference{
			Kind: "Node",
			Name: node.Name,
		},
		PodRef: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: "kube-system",
			Name:      "antrea-agent-1",
		},
		APIPort: apis.AntreaAgentAPIPort,
	}
	antreaAgentDaemonSet = &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "antrea-agent",
			Namespace: "kube-system",
			Labels: map[string]string{
				"app":       "antrea",
				"component": "antrea-agent",
			},
		},
	}
)

const fakeToken = "antctl-token"

// newFakeK8sClient returns a fake clientset which serves TokenRequests, as the default object
// tracker does not support the "token" subresource.
func newFakeK8sClient(objects ...runtime.Object) *fakeclient.Clientset {
	k8sClient := fakeclient.NewSimpleClientset(objects...)
	k8sClient.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token:               fakeToken,
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(10 * time.Minute)),
			},
		}, nil
	})
	return k8sClient
}

// tokenRequestNamespaces returns the Namespace of every TokenRequest issued through the client, in
// order.
func tokenRequestNamespaces(k8sClient *fakeclient.Clientset) []string {
	var namespaces []string
	for _, action := range k8sClient.Actions() {
		if action.Matches("create", "serviceaccounts") && action.GetSubresource() == "token" {
			namespaces = append(namespaces, action.GetNamespace())
		}
	}
	return namespaces
}

type fakeRoundTripper struct {
	request *http.Request
}

func (rt *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.request = req
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestCreateAgentClientCfg(t *testing.T) {
	ctx := context.Background()
	fakeCertData := []byte("foobar")
	apiHost := fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP, fmt.Sprint(apis.AntreaAgentAPIPort)))

	testCases := []struct {
		name        string
		certData    []byte
		insecure    bool
		expectedErr string
	}{
		{
			name:     "insecure",
			certData: nil,
			insecure: true,
		},
		{
			name:     "secure",
			certData: fakeCertData,
			insecure: false,
		},
		{
			name:        "secure missing cert",
			certData:    nil,
			insecure:    false,
			expectedErr: "no cert available",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := newFakeK8sClient(node, antreaAgentDaemonSet)
			agentInfo := agentInfo.DeepCopy()
			agentInfo.APICABundle = tc.certData
			// Written by the Agent itself, hence not to be trusted.
			agentInfo.PodRef.Namespace = "attacker-controlled"
			antreaClient := antreafakeclient.NewSimpleClientset(agentInfo)
			// The Agent client must not inherit any of the caller's credentials.
			kubeconfig := &rest.Config{
				BearerToken:     "operator-token",
				BearerTokenFile: "/operator/token",
				Username:        "operator",
				Password:        "operator-password",
				TLSClientConfig: rest.TLSClientConfig{
					CertFile: "/operator/cert",
					CertData: []byte("operator-cert"),
					KeyFile:  "/operator/key",
					KeyData:  []byte("operator-key"),
				},
				AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "oidc"},
				ExecProvider: &clientcmdapi.ExecConfig{Command: "get-credentials"},
				Impersonate: rest.ImpersonationConfig{
					UserName: "impersonated-operator",
					Groups:   []string{"impersonated-group"},
				},
			}

			cfg, err := CreateAgentClientCfg(ctx, k8sClient, antreaClient, kubeconfig, node.Name, tc.insecure)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Empty(t, cfg.BearerToken)
				assert.Empty(t, cfg.BearerTokenFile)
				assert.Empty(t, cfg.Username)
				assert.Empty(t, cfg.Password)
				assert.Empty(t, cfg.CertFile)
				assert.Empty(t, cfg.CertData)
				assert.Empty(t, cfg.KeyFile)
				assert.Empty(t, cfg.KeyData)
				assert.Nil(t, cfg.AuthProvider)
				assert.Nil(t, cfg.ExecProvider)
				assert.Empty(t, cfg.Impersonate)
				assert.Equal(t, tc.insecure, cfg.Insecure)
				if !tc.insecure {
					assert.Equal(t, "localhost", cfg.ServerName)
					assert.Equal(t, tc.certData, cfg.CAData)
					assert.Equal(t, apiHost, cfg.Host)
				} else {
					assert.Empty(t, cfg.ServerName)
					assert.Empty(t, cfg.CAData)
					assert.Empty(t, cfg.CAFile)
				}
				// Requests must be authenticated with a token minted for the "antctl"
				// ServiceAccount, in the Namespace of the antrea-agent DaemonSet: the
				// Namespace must never come from the Agent-written AntreaAgentInfo.
				require.NotNil(t, cfg.WrapTransport)
				rt := &fakeRoundTripper{}
				req := httptest.NewRequest(http.MethodGet, "https://antrea-agent/agentinfo", nil)
				_, err = cfg.WrapTransport(rt).RoundTrip(req)
				require.NoError(t, err)
				assert.Equal(t, "Bearer "+fakeToken, rt.request.Header.Get("Authorization"))
				assert.Equal(t, []string{antreaAgentDaemonSet.Namespace}, tokenRequestNamespaces(k8sClient))
			}
		})
	}
}

func TestResolveAntreaNamespace(t *testing.T) {
	ctx := context.Background()
	otherDaemonSet := antreaAgentDaemonSet.DeepCopy()
	otherDaemonSet.Namespace = "antrea-system"

	t.Run("from DaemonSet", func(t *testing.T) {
		namespace, err := ResolveAntreaNamespace(ctx, fakeclient.NewSimpleClientset(otherDaemonSet))
		require.NoError(t, err)
		assert.Equal(t, "antrea-system", namespace)
	})
	t.Run("POD_NAMESPACE ignored out of cluster", func(t *testing.T) {
		// Out of a Pod, POD_NAMESPACE is an arbitrary environment variable of the user's
		// shell and must not determine which ServiceAccount antctl uses.
		t.Setenv("POD_NAMESPACE", "not-antrea")
		namespace, err := ResolveAntreaNamespace(ctx, fakeclient.NewSimpleClientset(otherDaemonSet))
		require.NoError(t, err)
		assert.Equal(t, "antrea-system", namespace)
	})
	t.Run("no DaemonSet", func(t *testing.T) {
		// Guessing a Namespace would either fail later, when minting the token, or use the
		// ServiceAccount of an unrelated Antrea installation.
		_, err := ResolveAntreaNamespace(ctx, fakeclient.NewSimpleClientset())
		assert.ErrorContains(t, err, "no antrea-agent DaemonSet found")
	})
	t.Run("multiple DaemonSets in the same Namespace", func(t *testing.T) {
		// A cluster with Windows Nodes runs both the antrea-agent and the
		// antrea-agent-windows DaemonSets, and both carry the labels we select on.
		windowsDaemonSet := antreaAgentDaemonSet.DeepCopy()
		windowsDaemonSet.Name = "antrea-agent-windows"
		namespace, err := ResolveAntreaNamespace(ctx, fakeclient.NewSimpleClientset(antreaAgentDaemonSet, windowsDaemonSet))
		require.NoError(t, err)
		assert.Equal(t, antreaAgentDaemonSet.Namespace, namespace)
	})
	t.Run("DaemonSets in multiple Namespaces", func(t *testing.T) {
		// We cannot tell which installation the Agents belong to, and picking one could
		// authenticate as the ServiceAccount of the other installation.
		_, err := ResolveAntreaNamespace(ctx, fakeclient.NewSimpleClientset(antreaAgentDaemonSet, otherDaemonSet))
		assert.ErrorContains(t, err, "antrea-agent DaemonSets found in multiple Namespaces")
	})
}

func TestServiceAccountTokenSource(t *testing.T) {
	k8sClient := fakeclient.NewSimpleClientset()
	var requestCount int
	k8sClient.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		tokenRequest := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest)
		// The token must be bound to a short lifetime.
		require.NotNil(t, tokenRequest.Spec.ExpirationSeconds)
		assert.Equal(t, int64(600), *tokenRequest.Spec.ExpirationSeconds)
		requestCount++
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token:               fmt.Sprintf("token-%d", requestCount),
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(10 * time.Minute)),
			},
		}, nil
	})
	tokenSource := NewServiceAccountTokenSource(k8sClient, "kube-system")
	// No API call is made until a token is actually needed.
	assert.Zero(t, requestCount)

	token, err := tokenSource.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token)
	token, err = tokenSource.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token, "cached token should be reused")
	assert.Equal(t, 1, requestCount)

	// Once the renew time is reached the token is renewed, which is what keeps long-running
	// commands such as "antctl proxy" working.
	tokenSource.renewTime = time.Now().Add(-time.Second)
	token, err = tokenSource.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-2", token)
	assert.Equal(t, 2, requestCount)
}

func TestCreateControllerClientCfg(t *testing.T) {
	ctx := context.Background()
	fakeCAData := "foobar"
	apiHost := fmt.Sprintf("https://%s", net.JoinHostPort(nodeIP, fmt.Sprint(apis.AntreaControllerAPIPort)))
	goodCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cert.GetCAConfigMapNamespace(),
			Name:      apis.AntreaCAConfigMapName,
		},
		Data: map[string]string{
			apis.CAConfigMapKey: fakeCAData,
		},
	}
	badCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cert.GetCAConfigMapNamespace(),
			Name:      apis.AntreaCAConfigMapName,
		},
		Data: map[string]string{
			"foo": "bar",
		},
	}

	testCases := []struct {
		name        string
		cm          *corev1.ConfigMap
		insecure    bool
		expectedErr string
	}{
		{
			name:     "insecure",
			cm:       nil,
			insecure: true,
		},
		{
			name:     "secure",
			cm:       goodCM,
			insecure: false,
		},
		{
			name:        "secure misssing config map",
			cm:          nil,
			insecure:    false,
			expectedErr: "error when getting cert",
		},
		{
			name:        "secure wrong config map",
			cm:          badCM,
			insecure:    false,
			expectedErr: "error when getting cert",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []runtime.Object{node}
			if tc.cm != nil {
				objs = append(objs, tc.cm)
			}
			k8sClient := fakeclient.NewSimpleClientset(objs...)
			antreaClient := antreafakeclient.NewSimpleClientset(controllerInfo)
			kubeconfig := &rest.Config{}

			cfg, err := CreateControllerClientCfg(ctx, k8sClient, antreaClient, kubeconfig, tc.insecure)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Equal(t, tc.insecure, cfg.Insecure)
				if !tc.insecure {
					assert.Equal(t, k8s.GetServiceDNSNames("kube-system", apis.AntreaServiceName)[0], cfg.ServerName)
					assert.Equal(t, []byte(fakeCAData), cfg.CAData)
					assert.Equal(t, apiHost, cfg.Host)
				} else {
					assert.Empty(t, cfg.ServerName)
					assert.Empty(t, cfg.CAData)
					assert.Empty(t, cfg.CAFile)
				}
			}
		})
	}
}

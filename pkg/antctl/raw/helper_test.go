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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

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
)

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
			k8sClient := fakeclient.NewSimpleClientset(node)
			agentInfo := agentInfo.DeepCopy()
			agentInfo.APICABundle = tc.certData
			antreaClient := antreafakeclient.NewSimpleClientset(agentInfo)
			kubeconfig := &rest.Config{}

			cfg, err := CreateAgentClientCfg(ctx, k8sClient, antreaClient, kubeconfig, node.Name, tc.insecure)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
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
			}
		})
	}
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

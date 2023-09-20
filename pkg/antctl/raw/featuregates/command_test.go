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

package featuregates

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/rest/fake"

	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	antreafakeclient "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
)

var (
	clientConfig = &rest.Config{
		APIPath: "/featuregates",
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: scheme.Codecs,
			GroupVersion:         &appsv1.SchemeGroupVersion,
		},
	}
	controllerInfo = v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-controller",
		},
		NodeRef: v1.ObjectReference{
			Kind: "Node",
			Name: "node-1",
		},
	}
	node1 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Type:    v1.NodeInternalIP,
					Address: "170.10.0.10",
				},
			},
		},
	}
)

func TestGetFeatureGates(t *testing.T) {
	controllerRemoteResponse := []byte(`[
		{
			"component": "agent",
			"name": "AntreaIPAM",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "AntreaProxy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "CleanupStaleUDPSvcConntrack",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Egress",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "EndpointSlice",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "ExternalNode",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "FlowExporter",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "IPsecCertAuth",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "L7NetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "LoadBalancerModeDSR",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Multicast",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Multicluster",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "NodePortLocal",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "SecondaryNetwork",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "ServiceExternalIP",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "TopologyAwareHints",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "TrafficControl",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AdminNetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AntreaIPAM",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "Egress",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "IPsecCertAuth",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "L7NetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "Multicast",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "Multicluster",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "NodeIPAM",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "ServiceExternalIP",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		}
	]`)

	agentResponse := []byte(`[
		{
			"component": "agent",
			"name": "AntreaIPAM",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "AntreaProxy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "CleanupStaleUDPSvcConntrack",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Egress",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "EndpointSlice",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "ExternalNode",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "FlowExporter",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "IPsecCertAuth",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "L7NetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "LoadBalancerModeDSR",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Multicast",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Multicluster",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "NodePortLocal",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "SecondaryNetwork",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "ServiceExternalIP",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "TopologyAwareHints",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "TrafficControl",
			"status": "Disabled",
			"version": "ALPHA"
		}
	]`)

	controllerRemoteWithWindowsAgentResponse := []byte(`[
		{
			"component": "agent",
			"name": "AntreaIPAM",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "AntreaProxy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "CleanupStaleUDPSvcConntrack",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Egress",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "EndpointSlice",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "ExternalNode",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "FlowExporter",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "IPsecCertAuth",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "L7NetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "LoadBalancerModeDSR",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "Multicast",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Multicluster",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "NodePortLocal",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "SecondaryNetwork",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "ServiceExternalIP",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent",
			"name": "TopologyAwareHints",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent",
			"name": "TrafficControl",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent-windows",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "AntreaProxy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "EndpointSlice",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "ExternalNode",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent-windows",
			"name": "FlowExporter",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent-windows",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "NodePortLocal",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "agent-windows",
			"name": "TopologyAwareHints",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "agent-windows",
			"name": "TrafficControl",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AdminNetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AntreaIPAM",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "AntreaPolicy",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "Egress",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "IPsecCertAuth",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "L7NetworkPolicy",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "Multicast",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "Multicluster",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "NetworkPolicyStats",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "NodeIPAM",
			"status": "Enabled",
			"version": "BETA"
		},
		{
			"component": "controller",
			"name": "ServiceExternalIP",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "SupportBundleCollection",
			"status": "Disabled",
			"version": "ALPHA"
		},
		{
			"component": "controller",
			"name": "Traceflow",
			"status": "Enabled",
			"version": "BETA"
		}
	]`)

	k8sClient := k8sfake.NewSimpleClientset(node1.DeepCopyObject())
	antreaClientset := antreafakeclient.NewSimpleClientset(controllerInfo.DeepCopyObject())

	tests := []struct {
		name           string
		runE           func(cmd *cobra.Command, _ []string) error
		response       []byte
		expectedOutput string
	}{
		{
			name: "get featuregates out of Pod",
			runE: controllerRemoteRunE,
			expectedOutput: `Antrea Agent Feature Gates
FEATUREGATE                     STATUS       VERSION
AntreaIPAM                      Disabled     ALPHA
AntreaPolicy                    Enabled      BETA
AntreaProxy                     Enabled      BETA
CleanupStaleUDPSvcConntrack     Disabled     ALPHA
Egress                          Enabled      BETA
EndpointSlice                   Enabled      BETA
ExternalNode                    Disabled     ALPHA
FlowExporter                    Disabled     ALPHA
IPsecCertAuth                   Disabled     ALPHA
L7NetworkPolicy                 Disabled     ALPHA
LoadBalancerModeDSR             Disabled     ALPHA
Multicast                       Enabled      BETA
Multicluster                    Disabled     ALPHA
NetworkPolicyStats              Enabled      BETA
NodePortLocal                   Enabled      BETA
SecondaryNetwork                Disabled     ALPHA
ServiceExternalIP               Disabled     ALPHA
SupportBundleCollection         Disabled     ALPHA
TopologyAwareHints              Enabled      BETA
Traceflow                       Enabled      BETA
TrafficControl                  Disabled     ALPHA

Antrea Controller Feature Gates
FEATUREGATE                 STATUS       VERSION
AdminNetworkPolicy          Disabled     ALPHA
AntreaIPAM                  Disabled     ALPHA
AntreaPolicy                Enabled      BETA
Egress                      Enabled      BETA
IPsecCertAuth               Disabled     ALPHA
L7NetworkPolicy             Disabled     ALPHA
Multicast                   Enabled      BETA
Multicluster                Disabled     ALPHA
NetworkPolicyStats          Enabled      BETA
NodeIPAM                    Enabled      BETA
ServiceExternalIP           Disabled     ALPHA
SupportBundleCollection     Disabled     ALPHA
Traceflow                   Enabled      BETA
`,
			response: controllerRemoteResponse,
		},
		{
			name: "get featuregates in agent Pod",
			runE: agentRunE,
			expectedOutput: `Antrea Agent Feature Gates
FEATUREGATE                     STATUS       VERSION
AntreaIPAM                      Disabled     ALPHA
AntreaPolicy                    Enabled      BETA
AntreaProxy                     Enabled      BETA
CleanupStaleUDPSvcConntrack     Disabled     ALPHA
Egress                          Enabled      BETA
EndpointSlice                   Enabled      BETA
ExternalNode                    Disabled     ALPHA
FlowExporter                    Disabled     ALPHA
IPsecCertAuth                   Disabled     ALPHA
L7NetworkPolicy                 Disabled     ALPHA
LoadBalancerModeDSR             Disabled     ALPHA
Multicast                       Enabled      BETA
Multicluster                    Disabled     ALPHA
NetworkPolicyStats              Enabled      BETA
NodePortLocal                   Enabled      BETA
SecondaryNetwork                Disabled     ALPHA
ServiceExternalIP               Disabled     ALPHA
SupportBundleCollection         Disabled     ALPHA
TopologyAwareHints              Enabled      BETA
Traceflow                       Enabled      BETA
TrafficControl                  Disabled     ALPHA
`,
			response: agentResponse,
		},
		{
			name: "get featuregates in controller Pod",
			runE: controllerLocalRunE,
			expectedOutput: `Antrea Agent Feature Gates
FEATUREGATE                     STATUS       VERSION
AntreaIPAM                      Disabled     ALPHA
AntreaPolicy                    Enabled      BETA
AntreaProxy                     Enabled      BETA
CleanupStaleUDPSvcConntrack     Disabled     ALPHA
Egress                          Enabled      BETA
EndpointSlice                   Enabled      BETA
ExternalNode                    Disabled     ALPHA
FlowExporter                    Disabled     ALPHA
IPsecCertAuth                   Disabled     ALPHA
L7NetworkPolicy                 Disabled     ALPHA
LoadBalancerModeDSR             Disabled     ALPHA
Multicast                       Enabled      BETA
Multicluster                    Disabled     ALPHA
NetworkPolicyStats              Enabled      BETA
NodePortLocal                   Enabled      BETA
SecondaryNetwork                Disabled     ALPHA
ServiceExternalIP               Disabled     ALPHA
SupportBundleCollection         Disabled     ALPHA
TopologyAwareHints              Enabled      BETA
Traceflow                       Enabled      BETA
TrafficControl                  Disabled     ALPHA

Antrea Controller Feature Gates
FEATUREGATE                 STATUS       VERSION
AdminNetworkPolicy          Disabled     ALPHA
AntreaIPAM                  Disabled     ALPHA
AntreaPolicy                Enabled      BETA
Egress                      Enabled      BETA
IPsecCertAuth               Disabled     ALPHA
L7NetworkPolicy             Disabled     ALPHA
Multicast                   Enabled      BETA
Multicluster                Disabled     ALPHA
NetworkPolicyStats          Enabled      BETA
NodeIPAM                    Enabled      BETA
ServiceExternalIP           Disabled     ALPHA
SupportBundleCollection     Disabled     ALPHA
Traceflow                   Enabled      BETA
`,
			response: controllerRemoteResponse,
		},
		{
			name: "get featuregates in controller Pod with Windows agent",
			runE: controllerLocalRunE,
			expectedOutput: `Antrea Agent Feature Gates
FEATUREGATE                     STATUS       VERSION
AntreaIPAM                      Disabled     ALPHA
AntreaPolicy                    Enabled      BETA
AntreaProxy                     Enabled      BETA
CleanupStaleUDPSvcConntrack     Disabled     ALPHA
Egress                          Enabled      BETA
EndpointSlice                   Enabled      BETA
ExternalNode                    Disabled     ALPHA
FlowExporter                    Disabled     ALPHA
IPsecCertAuth                   Disabled     ALPHA
L7NetworkPolicy                 Disabled     ALPHA
LoadBalancerModeDSR             Disabled     ALPHA
Multicast                       Enabled      BETA
Multicluster                    Disabled     ALPHA
NetworkPolicyStats              Enabled      BETA
NodePortLocal                   Enabled      BETA
SecondaryNetwork                Disabled     ALPHA
ServiceExternalIP               Disabled     ALPHA
SupportBundleCollection         Disabled     ALPHA
TopologyAwareHints              Enabled      BETA
Traceflow                       Enabled      BETA
TrafficControl                  Disabled     ALPHA

Antrea Agent Feature Gates (Windows)
FEATUREGATE                 STATUS       VERSION
AntreaPolicy                Enabled      BETA
AntreaProxy                 Enabled      BETA
EndpointSlice               Enabled      BETA
ExternalNode                Disabled     ALPHA
FlowExporter                Disabled     ALPHA
NetworkPolicyStats          Enabled      BETA
NodePortLocal               Enabled      BETA
SupportBundleCollection     Disabled     ALPHA
TopologyAwareHints          Enabled      BETA
Traceflow                   Enabled      BETA
TrafficControl              Disabled     ALPHA

Antrea Controller Feature Gates
FEATUREGATE                 STATUS       VERSION
AdminNetworkPolicy          Disabled     ALPHA
AntreaIPAM                  Disabled     ALPHA
AntreaPolicy                Enabled      BETA
Egress                      Enabled      BETA
IPsecCertAuth               Disabled     ALPHA
L7NetworkPolicy             Disabled     ALPHA
Multicast                   Enabled      BETA
Multicluster                Disabled     ALPHA
NetworkPolicyStats          Enabled      BETA
NodeIPAM                    Enabled      BETA
ServiceExternalIP           Disabled     ALPHA
SupportBundleCollection     Disabled     ALPHA
Traceflow                   Enabled      BETA
`,
			response: controllerRemoteWithWindowsAgentResponse,
		},
	}

	getClients = func(cmd *cobra.Command) (*rest.Config, kubernetes.Interface, antrea.Interface, error) {
		return clientConfig, k8sClient, antreaClientset, nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getRestClient = getFakeFunc(tt.response)
			buf := new(bytes.Buffer)
			Command.SetOutput(buf)
			Command.SetOut(buf)
			Command.SetErr(buf)

			err := tt.runE(Command, nil)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedOutput, buf.String())
		})
	}
}

func getFakeFunc(response []byte) func(ctx context.Context, kubeconfig *rest.Config, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, mode string) (*rest.RESTClient, error) {
	restClient, _ := rest.RESTClientFor(clientConfig)
	return func(ctx context.Context, kubeconfig *rest.Config, k8sClientset kubernetes.Interface, antreaClientset antrea.Interface, mode string) (*rest.RESTClient, error) {
		fakeHttpClient := fake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(response))}, nil
		})
		restClient.Client = fakeHttpClient
		return restClient, nil
	}
}

func TestGetConfigAndClients(t *testing.T) {
	fakeConfigs := []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJeU1EWXhNREEzTVRrME5Gb1hEVE15TURZd056QTNNVGswTkZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTG5DCktIcUgzcW5FS1dCazFrdVIvM1MrR0F4WmNLZlBJUjcvdld5L1d5QXpJZkxnbUh5NmpMenU5QlF0WkI3cjNIa2cKR0xWOEJ6eDdqK0VTMjdUWDZFS3UzVGVsV01WYitSM2l2Y1czZUJ6SWVxYm9BK1ZkTE1GK3d3eENseFZERVRZTwpMMTRGZy9ZdWhya0kybmtqbWs4Z01jUm5jNW9IZXh3WEJnNXRuUWd6aWF6WHBuVC9MeGZLaHZINFFkRzlmVUlFCm1lMGt1K01sR21ZeUNkbjc0MXJuNE1JcFFoZGtKU1hwNElvOGt1RElDYVBGM01IQWRMZjFqcWZydUU5bmJpOW8KQWI0ZWV6bFNIUi9GWUVIQlUxVG9Zd0V3RWU5Vm1CMHU5R3plSFZsVEtFMzY5L05nR3RVMnFHWjVCTEp3b3FKUgpEbk5FWDVnRkFnZE54SlFTSEpVQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZDbGk0SXRidlJibDBmTG40L3YycG5jd0ZoUVJNQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFCVlNsV3ZBZGV1MzJBRzNuRmZNejdRM25xOHlVLzJrQ0RnZUVtdGNSci9yVkExanBERQpST3Jha001WXB2aEtFOWY2OG9BODRFaEVnSi8wbVNFblBkUCsyeUhWQUhoSG5WVXE3M1Ywb0JDbFhMTzR2d0tBCkJlMDhOZkV3by9KNzFBRUNtYWFnSGFuckVhT2swK3RkdkVOQkZ1bFFpVGNORFkxTWtoK0hiaXJrMHRHVE9lMkoKQXdOaU1uZ0ZMVEpIWUVFTTVtNzJtNjRzMFFGbkxJSDRuNFdXN3ZGK0gzSks1VFVkR1Rwc2ZvT0M1d2ZmenVUZwpRSVRjU241N2JXYk9CaEFiZTI0bmN0YzVSc2hJWkp4UE5XUDFjc2lpalJEWjRiMXRwMVN0WGNWRThmSDhlVEVUCkJ6d3BRdy9STTdmL2JyVEMwZDR2SmFJam1XVGY5cTJEci9ldAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`)

	var err error
	fakeKubeconfig, err := os.CreateTemp("", "fakeKubeconfig")
	require.NoError(t, err)
	defer os.Remove(fakeKubeconfig.Name())
	fakeKubeconfig.Write(fakeConfigs)
	kubeconfig := ""
	Command.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", fakeKubeconfig.Name(), "path of kubeconfig")
	// Get kubeconfig with default config.
	config, _, _, err := getConfigAndClients(Command)
	require.NoError(t, err)
	assert.Equal(t, "https://localhost", config.Host)

	// Get kubeconfig with new server option.
	server := ""
	Command.Flags().StringVarP(&server, "server", "", "http://192.168.1.10", "address and port of the API server")
	newconfig, _, _, err := getConfigAndClients(Command)
	require.NoError(t, err)
	assert.Equal(t, "http://192.168.1.10", newconfig.Host)
}

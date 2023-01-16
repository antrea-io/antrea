// Copyright 2020 Antrea Authors
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

package supportbundle

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
)

var (
	clientConfig = &rest.Config{
		APIPath: "/supportbundle",
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
			Name:            "node-1",
			ResourceVersion: "0",
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
	node2 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-2",
		},
	}
	node3 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "node-3",
			ResourceVersion: "0",
		},
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{
					Type:    v1.NodeInternalIP,
					Address: "170.10.0.11",
				},
			},
		},
	}
	agentInfo1 = &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-agent-1",
		},
		APIPort: 0,
		PodRef: v1.ObjectReference{
			ResourceVersion: "0",
		},
		NodeRef: v1.ObjectReference{
			Kind: "Node",
			Name: "node-1",
		},
	}
	agentInfo2 = &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "antrea-agent-2",
		},
		APIPort: 0,
		PodRef: v1.ObjectReference{
			ResourceVersion: "0",
		},
		NodeRef: v1.ObjectReference{
			Kind: "Node",
			Name: "node-3",
		},
	}
	nameList = []string{"node-1", "node-2"}
)

func TestControllerRemoteRunE(t *testing.T) {
	fakeConfigs := []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJTHJac3Z6ZFQ3ekF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TWpBNE1qSXdNakl6TXpkYUZ3MHlNekE0TWpJd01qSXpNemxhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTB4N2JEd2NqSzN3VjRGSzkKYUtrd0FUdjVoT2NsbHhUSEI1ejFUbHZJV3pmdTNYNjZtaWkxUE04ODI1dTArdDRRdisxUVRIRHFzUkNvWFA1awpuNGNWZkxkeTlad25uN01uSDExVTRsRWRoeXBrdlZsc0RmajlBdWh3WHBZVE82eE5kM2o2Y3BIZGNMOW9PbGw2CkowcGU2RzBleHpTSHMvbHRUZXlyalRGbXM2Sm5zSWV6T2lHRmhZOTJCbDBmZ1krb2p6MFEwM2cvcE5QZUszcGMKK05wTWh4eG1UY1lVNzlaZVRqV1JPYTFQSituNk1SMEhDbW0xQk5QNmdwWmozbGtWSktkZnBEYmovWHYvQWNkVQpab3E5Ym95aGNDUCtiYmgyaWVtaTc0bnZqZ1BUTkVDZWU2a3ZHY3VNaXRKUkdvWjBxbFpZbXZDaWdEeGlSTnBNClBPa1dud0lEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JSc2VoZXVkM0l5VWRNdkhhRS9YU3MrOFErLwpiVEFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBcmg4UFRadFgvWjlHVzlMYmxZZ1FWWE04VlRrWEtGSEpTZldOCkJLNXo2NWNWdGN2cFZ0WDZNTlppTFhuYkFzQ0JPY1RqejBJRlphYkNNUkZzYmdYbEVqV0ZuRE5abzBMVHFTZUcKQ2RqTWljK0JzbmFGUThZOXJ5TTVxZ0RhQzNWQkdTSXVscklXeGxPYmRmUEpWRnpUaVNTcmJBR1Z3Uk5sQlpmYgpYOXBlRlpNNmNFNUhTOE5RTmNoZkh2SWhGSUVuR2YxOUx2enp0WGUzQWwwb3hYNjdRKzhyWXd0Tm56dS9xM29BCmJIN1dsNld5ODVYNS90RWlQcWU0ZU1GalRDME9tR2NHZ2lQdU90NjlIejAwV2hvaWNYYWpma1FZOHNKMk5Uc1cKdUcxbWZqb0tTdUN0OC9BRmhPNURlaHZ3eFNIQU12eG1VQUJYL294bU1DNzdwV0VnRWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
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
	fmt.Println(fakeKubeconfig.Name())
	Command.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", fakeKubeconfig.Name(), "path of kubeconfig")
	os.Setenv("KUBECONFIG", fakeKubeconfig.Name())
	fmt.Println(kubeconfig)
	err1 := controllerRemoteRunE(Command, nil)
	fmt.Println(err1.Error())
}

func TestCreateControllerClient(t *testing.T) {
	tests := []struct {
		name            string
		expectedErr     string
		k8sClientset    kubernetes.Interface
		antreaClientset antrea.Interface
	}{
		{
			name:            "create controller client successfully",
			expectedErr:     "",
			k8sClientset:    fake.NewSimpleClientset(&node1),
			antreaClientset: fakeclientset.NewSimpleClientset(&controllerInfo),
		},
		{
			name:            "failed to create controller client due to no pre-existing antreacontrollerinfos",
			expectedErr:     "antreacontrollerinfos.crd.antrea.io \"antrea-controller\" not found",
			k8sClientset:    fake.NewSimpleClientset(),
			antreaClientset: fakeclientset.NewSimpleClientset(),
		},
		{
			name:            "failed to create controller client due to no pre-existing controller node",
			expectedErr:     "error when searching the Node of the controller: nodes \"node-1\" not found",
			k8sClientset:    fake.NewSimpleClientset(),
			antreaClientset: fakeclientset.NewSimpleClientset(&controllerInfo),
		},
		{
			name:            "failed to create controller client due to error when parsing controller IP",
			expectedErr:     "error when parsing controller IP: Node node-1 has neither external ip nor internal ip",
			k8sClientset:    fake.NewSimpleClientset(&node2),
			antreaClientset: fakeclientset.NewSimpleClientset(&controllerInfo),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createControllerClient(tt.k8sClientset, tt.antreaClientset, clientConfig)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr)
			}
		})
	}
}

func TestCreateAgentClients(t *testing.T) {
	k8sClientset := fake.NewSimpleClientset(&node1, &node3)
	antreaClientset := fakeclientset.NewSimpleClientset(agentInfo1, agentInfo2)
	_, err := createAgentClients(k8sClientset, antreaClientset, clientConfig, "", nameList)
	assert.NoError(t, err)
}

func TestRequest(t *testing.T) {
	k8sClientset := fake.NewSimpleClientset(&node1, &node3)
	antreaClientset := fakeclientset.NewSimpleClientset(agentInfo1, agentInfo2, &controllerInfo)
	agentClients, err := createAgentClients(k8sClientset, antreaClientset, clientConfig, "", nameList)
	require.NoError(t, err)
	controllerClient, err := createControllerClient(k8sClientset, antreaClientset, clientConfig)
	require.NoError(t, err)
	amount := len(agentClients)*2 + 2
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	results := requestAll(agentClients, controllerClient, bar)
	assert.NotNil(t, results)
}

func TestDownload(t *testing.T) {
	if option.dir == "" {
		cwd, _ := os.Getwd()
		option.dir = filepath.Join(cwd, "support-bundles_"+time.Now().Format(timeFormat))
	}
	dir, err := filepath.Abs(option.dir)
	require.NoError(t, err)
	k8sClientset := fake.NewSimpleClientset(&node1, &node3)
	antreaClientset := fakeclientset.NewSimpleClientset(agentInfo1, agentInfo2, &controllerInfo)
	agentClients, err := createAgentClients(k8sClientset, antreaClientset, clientConfig, "", nameList)
	require.NoError(t, err)
	controllerClient, err := createControllerClient(k8sClientset, antreaClientset, clientConfig)
	require.NoError(t, err)
	amount := len(agentClients)*2 + 2
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	f, err := os.Create(filepath.Join(option.dir, "clusterinfo"))
	require.NoError(t, err)
	defer f.Close()
	err = getClusterInfo(f, k8sClientset)
	require.NoError(t, err)
	results := requestAll(agentClients, controllerClient, bar)
	results = downloadAll(agentClients, controllerClient, dir, bar, results)
	assert.NotNil(t, results)
}

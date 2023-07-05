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

package supportbundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	systemv1beta1 "antrea.io/antrea/pkg/apis/system/v1beta1"
	antreaclientset "antrea.io/antrea/pkg/client/clientset/versioned"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	"antrea.io/antrea/pkg/client/clientset/versioned/scheme"
	systemclientset "antrea.io/antrea/pkg/client/clientset/versioned/typed/system/v1beta1"
)

var (
	clientConfig = &rest.Config{
		APIPath: "/supportbundle",
		ContentConfig: rest.ContentConfig{
			NegotiatedSerializer: scheme.Codecs,
			GroupVersion:         &systemv1beta1.SchemeGroupVersion,
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
					Address: "172.16.0.0",
				},
			},
		},
	}
	node2 = v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-1",
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
					Address: "127.0.0.1",
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
	nameList = []string{"node-1", "node-3"}
)

func createFakeSupportBundleClient() systemclientset.SupportBundleInterface {
	fakeClient := fakeclientset.NewSimpleClientset()
	fakeClient.PrependReactor("create", "supportbundles", k8stesting.ReactionFunc(
		func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
			supportBundle := action.(k8stesting.CreateAction).GetObject().(*systemv1beta1.SupportBundle)
			// Make the supportBundle "ready" as soon as it is created:
			supportBundle.Status = systemv1beta1.SupportBundleStatusCollected
			return false, supportBundle, nil
		}),
	)
	return fakeClient.SystemV1beta1().SupportBundles()
}

func TestLocalSupportBundleRequest(t *testing.T) {
	getSupportBundleClient = func(cmd *cobra.Command) (systemclientset.SupportBundleInterface, error) {
		return createFakeSupportBundleClient(), nil
	}
	defer func() {
		getSupportBundleClient = setupSupportBundleClient
	}()
	cmd := &cobra.Command{}
	// Make sure that the test does not hang even in case of failure:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd.SetContext(ctx)
	writer := new(bytes.Buffer)
	expected := "Created bundle under"
	err := localSupportBundleRequest(cmd, "agent", writer)
	require.NoError(t, err)
	assert.Contains(t, writer.String(), expected)
}

func TestCreateControllerClient(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name            string
		expectedErr     string
		k8sClientset    kubernetes.Interface
		antreaClientset antreaclientset.Interface
	}{
		{
			name:            "created controller client successfully",
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
			expectedErr:     "error when getting controller IP: no IP",
			k8sClientset:    fake.NewSimpleClientset(&node2),
			antreaClientset: fakeclientset.NewSimpleClientset(&controllerInfo),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createControllerClient(ctx, tt.k8sClientset, tt.antreaClientset, clientConfig, true /* insecure */)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestCreateAgentClients(t *testing.T) {
	tests := []struct {
		name            string
		expectedErr     string
		k8sClientset    *fake.Clientset
		antreaClientset *fakeclientset.Clientset
		prepareReactor  func(antreaClientset *fakeclientset.Clientset, k8sClientset *fake.Clientset)
		expectedClients []string
	}{
		{
			name:            "created both agent clients successfully",
			k8sClientset:    fake.NewSimpleClientset(&node1, &node3),
			antreaClientset: fakeclientset.NewSimpleClientset(agentInfo1, agentInfo2),
			expectedClients: []string{"node-1", "node-3"},
		},
		{
			name:            "failure to create one agent client due to error when parsing controller IP",
			k8sClientset:    fake.NewSimpleClientset(&node2, &node3),
			antreaClientset: fakeclientset.NewSimpleClientset(agentInfo1, agentInfo2),
			expectedClients: []string{"node-3"},
		},
		{
			name:            "no-op due to error in listing antreaagentinfos",
			antreaClientset: fakeclientset.NewSimpleClientset(),
			prepareReactor: func(antreaClientset *fakeclientset.Clientset, k8sClientset *fake.Clientset) {
				antreaClientset.PrependReactor("list", "antreaagentinfos", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &v1beta1.AntreaAgentInfoList{}, errors.New("error listing antreaagentinfos")
				})
			},
			expectedErr: "error listing antreaagentinfos",
		},
		{
			name:            "no-op due to error in listing nodes",
			antreaClientset: fakeclientset.NewSimpleClientset(),
			k8sClientset:    fake.NewSimpleClientset(),
			prepareReactor: func(antreaClientset *fakeclientset.Clientset, k8sClientset *fake.Clientset) {
				k8sClientset.PrependReactor("list", "nodes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &v1.NodeList{}, errors.New("error listing nodes")
				})
			},
			expectedErr: "error listing nodes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepareReactor != nil {
				tt.prepareReactor(tt.antreaClientset, tt.k8sClientset)
			}
			clients, err := createAgentClients(context.Background(), tt.k8sClientset, tt.antreaClientset, clientConfig, "", nameList, true /* insecure */)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				agentClients := []string{}
				for client := range clients {
					agentClients = append(agentClients, client)
				}
				assert.ElementsMatch(t, tt.expectedClients, agentClients)
			}
		})
	}
}

func TestRequest(t *testing.T) {
	agentClients := map[string]systemclientset.SupportBundleInterface{}
	for _, name := range nameList {
		agentClients[name] = createFakeSupportBundleClient()
	}
	controllerClient := createFakeSupportBundleClient()
	amount := len(agentClients)*2 + 2
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	// Make sure that the test does not hang even in case of failure:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results := requestAll(ctx, agentClients, controllerClient, bar)
	//results[""] corresponds to error received for controller node
	assert.Equal(t, map[string]error{"": nil, "node-1": nil, "node-3": nil}, results)
}

func TestDownload(t *testing.T) {
	path := option.dir
	option.dir = "/out"
	defaultFS = afero.NewMemMapFs()
	defaultFS.MkdirAll(option.dir, 0755)
	defer func() {
		defaultFS = afero.NewOsFs()
		option.dir = path
	}()
	agentClients := map[string]systemclientset.SupportBundleInterface{}
	for _, name := range nameList {
		agentClients[name] = createFakeSupportBundleClient()
	}
	controllerClient := createFakeSupportBundleClient()
	amount := len(agentClients)*2 + 2
	bar := barTmpl.Start(amount)
	defer bar.Finish()
	defer bar.Set("prefix", "Finish ")
	// Make sure that the test does not hang even in case of failure:
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resultMap := requestAll(ctx, agentClients, controllerClient, bar)
	results := downloadAll(ctx, agentClients, controllerClient, option.dir, bar, resultMap)
	//results[""] corresponds to error received for controller node
	require.Equal(t, map[string]error{"": nil, "node-1": nil, "node-3": nil}, results)
	for _, fileName := range []string{"controller.tar.gz", "agent_node-1.tar.gz", "agent_node-3.tar.gz"} {
		ok, err := afero.Exists(defaultFS, filepath.Join(option.dir, fileName))
		require.NoError(t, err)
		assert.True(t, ok, "expected support bundle file not found")
	}
}

func TestProcessResults(t *testing.T) {
	path := option.dir
	option.dir = "/out"
	defer func() {
		option.dir = path
	}()
	tests := []struct {
		name        string
		resultMap   map[string]error
		expectedErr string
	}{
		{
			name: "All nodes failed",
			resultMap: map[string]error{
				"":       fmt.Errorf("error-0"),
				"node-1": fmt.Errorf("error-1"),
				"node-2": fmt.Errorf("error-2"),
			},
			expectedErr: "no data was collected:",
		},
		{
			name: "Not all nodes failed",
			resultMap: map[string]error{
				"":       fmt.Errorf("error-0"),
				"node-1": fmt.Errorf("error-1"),
				"node-2": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultFS = afero.NewMemMapFs()
			defaultFS.MkdirAll(option.dir, 0755)
			defer func() {
				defaultFS = afero.NewOsFs()
			}()

			err := processResults(tt.resultMap, option.dir)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
			// Both test cases above have failed Nodes, hence this file should always be created/
			b, err := afero.ReadFile(defaultFS, filepath.Join(option.dir, "failed_nodes"))
			require.NoError(t, err)
			data := string(b)
			for node, err := range tt.resultMap {
				if node == "" {
					continue
				}
				if err != nil {
					assert.Contains(t, data, node)
				} else {
					assert.NotContains(t, data, node)
				}
			}
		})
	}
}

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

package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	cgtesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/agent/config"
	interfacestoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/querier"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

const ovsVersion = "2.10.0"

var fakeCertData = []byte("foobar")

func TestSyncAgentCRD(t *testing.T) {
	ctx := context.Background()
	crdName := "antrea-agent-foo"
	existingCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testAgentCRD",
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 1,
		},
		APIPort: 0,
	}
	partiallyUpdatedCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 10,
		},
		APIPort: 0,
	}
	entirelyUpdatedCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 0,
		},
		APIPort:     10349,
		APICABundle: fakeCertData,
	}
	t.Run("partial update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD()
		crd, err := monitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, "testAgentCRD", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, partiallyUpdatedCRD.NetworkPolicyControllerInfo.NetworkPolicyNum, crd.NetworkPolicyControllerInfo.NetworkPolicyNum)
	})
	t.Run("partial update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error updating agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD()
		assert.Nil(t, monitor.agentCRD)
	})
	t.Run("get-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset()
		clientset.PrependReactor("get", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error getting agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD()
		assert.Nil(t, monitor.agentCRD)
	})
	t.Run("entire update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		monitor := newAgentMonitor(clientset, t)
		monitor.syncAgentCRD()
		crd, err := monitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, "testAgentCRD", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, entirelyUpdatedCRD.APIPort, crd.APIPort)
		assert.Equal(t, entirelyUpdatedCRD.APICABundle, crd.APICABundle)
	})
	t.Run("entire update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error updating agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.syncAgentCRD()
		assert.Nil(t, monitor.agentCRD)
	})
}

func newAgentMonitor(crdClient *fakeclientset.Clientset, t *testing.T) *agentMonitor {
	client := fake.NewSimpleClientset()
	ctrl := gomock.NewController(t)

	nodeConfig := &config.NodeConfig{
		Name: "testAgentCRD",
	}

	interfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	interfaceStore.EXPECT().GetContainerInterfaceNum().Return(2).AnyTimes()

	ofClient := openflowtest.NewMockClient(ctrl)
	ofClient.EXPECT().GetFlowTableStatus().Return([]binding.TableStatus{
		{
			ID:        1,
			Name:      "1",
			FlowCount: 2,
		},
	}).AnyTimes()
	ofClient.EXPECT().IsConnected().Return(true).AnyTimes()

	ovsBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	ovsBridgeClient.EXPECT().GetOVSVersion().Return(ovsVersion, nil).AnyTimes()

	networkPolicyInfoQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	networkPolicyInfoQuerier.EXPECT().GetNetworkPolicyNum().Return(10).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAppliedToGroupNum().Return(20).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAddressGroupNum().Return(30).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetControllerConnectionStatus().Return(true).AnyTimes()

	querier := querier.NewAgentQuerier(nodeConfig, nil, interfaceStore, client, ofClient, ovsBridgeClient, nil, networkPolicyInfoQuerier, 10349, "", nil, nil)

	return NewAgentMonitor(crdClient, querier, fakeCertData)
}

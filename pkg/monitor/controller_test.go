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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	errortesting "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	cgtesting "k8s.io/client-go/testing"
	fakepolicyversioned "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/fake"
	policyv1a1informers "sigs.k8s.io/network-policy-api/pkg/client/informers/externalversions"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/labelidentity"
	"antrea.io/antrea/pkg/controller/networkpolicy"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/controller/querier"
)

const (
	informerDefaultResync = 12 * time.Hour
)

type fakeController struct {
	controllerMonitor  *controllerMonitor
	crdClient          *fakeclientset.Clientset
	client             *fake.Clientset
	informerFactory    informers.SharedInformerFactory
	crdInformerFactory crdinformers.SharedInformerFactory
}

func newControllerMonitor(crdClient *fakeclientset.Clientset) *fakeController {
	client := fake.NewSimpleClientset()
	policyClient := fakepolicyversioned.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	policyInformerFactory := policyv1a1informers.NewSharedInformerFactory(policyClient, informerDefaultResync)
	namespaceInformer := informerFactory.Core().V1().Namespaces()
	serviceInformer := informerFactory.Core().V1().Services()
	networkPolicyInformer := informerFactory.Networking().V1().NetworkPolicies()
	nodeInformer := informerFactory.Core().V1().Nodes()
	acnpInformer := crdInformerFactory.Crd().V1beta1().ClusterNetworkPolicies()
	annpInformer := crdInformerFactory.Crd().V1beta1().NetworkPolicies()
	adminNPInformer := policyInformerFactory.Policy().V1alpha1().AdminNetworkPolicies()
	banpInformer := policyInformerFactory.Policy().V1alpha1().BaselineAdminNetworkPolicies()
	tierInformer := crdInformerFactory.Crd().V1beta1().Tiers()
	cgInformer := crdInformerFactory.Crd().V1beta1().ClusterGroups()
	grpInformer := crdInformerFactory.Crd().V1beta1().Groups()
	externalNodeInformer := crdInformerFactory.Crd().V1alpha1().ExternalNodes()

	addressGroupStore := store.NewAddressGroupStore()
	appliedToGroupStore := store.NewAppliedToGroupStore()
	networkPolicyStore := store.NewNetworkPolicyStore()
	groupStore := store.NewGroupStore()
	groupEntityIndex := grouping.NewGroupEntityIndex()
	labelIdentityIndex := labelidentity.NewLabelIdentityIndex()

	networkPolicyController := networkpolicy.NewNetworkPolicyController(client,
		crdClient,
		groupEntityIndex,
		labelIdentityIndex,
		namespaceInformer,
		serviceInformer,
		networkPolicyInformer,
		nodeInformer,
		acnpInformer,
		annpInformer,
		adminNPInformer,
		banpInformer,
		tierInformer,
		cgInformer,
		grpInformer,
		addressGroupStore,
		appliedToGroupStore,
		networkPolicyStore,
		groupStore,
		false)

	controllerQuerier := querier.NewControllerQuerier(networkPolicyController, 10349)
	externalNodeEnabled := true
	controllerMonitor := NewControllerMonitor(crdClient, nodeInformer, externalNodeInformer, controllerQuerier, externalNodeEnabled)

	return &fakeController{
		controllerMonitor,
		crdClient,
		client,
		informerFactory,
		crdInformerFactory,
	}
}

func initController(controller *fakeController, stopCh chan struct{}) {
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
}

func TestSyncExternalNode(t *testing.T) {
	ctx := context.Background()
	en := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "TestExternalNode",
			Namespace: "ns1",
			Labels:    map[string]string{"en": "vm2"},
		},
	}
	tc := []struct {
		name                 string
		key                  string
		existingExternalNode *v1alpha1.ExternalNode
		expectedAgentCR      *v1beta1.AntreaAgentInfo
		expectedError        string
	}{
		{
			name:          "Invalid key format",
			key:           "namespace/name/error",
			expectedError: "unexpected key format: \"namespace/name/error\"",
		},
		{
			name:          "Key does not exist",
			key:           "default/vm2-e8be5",
			expectedError: "",
		},
		{
			name:                 "Key exists",
			key:                  "ns1/TestExternalNode",
			existingExternalNode: en,
			expectedAgentCR: &v1beta1.AntreaAgentInfo{
				ObjectMeta: metav1.ObjectMeta{
					Name: "TestExternalNode",
				},
			},
			expectedError: "",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			var clientset *fakeclientset.Clientset
			if tt.existingExternalNode != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingExternalNode)
			} else {
				clientset = fakeclientset.NewSimpleClientset()
			}
			clientset.Resources = []*metav1.APIResourceList{
				{
					GroupVersion: v1beta1.SchemeGroupVersion.String(),
					APIResources: []metav1.APIResource{{Name: agentInfoResourceKind}},
				},
			}
			controller := newControllerMonitor(clientset)
			stopCh := make(chan struct{})
			initController(controller, stopCh)
			defer close(stopCh)
			err := controller.controllerMonitor.syncExternalNode(tt.key)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				if tt.expectedAgentCR == nil {
					_, name, _ := splitKeyFunc(tt.key)
					_, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, name, metav1.GetOptions{})
					assert.True(t, errortesting.IsNotFound(err))
				} else {
					crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, tt.expectedAgentCR.Name, metav1.GetOptions{})
					require.NoError(t, err)
					assert.Equal(t, tt.expectedAgentCR, crd)
				}
			}
		})
	}
}

func TestSyncNode(t *testing.T) {
	ctx := context.Background()
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "TestNode",
			Labels: map[string]string{"en": "vm2"},
		},
	}
	tc := []struct {
		name             string
		key              string
		existingNode     *v1.Node
		expectedAgentCRD *v1beta1.AntreaAgentInfo
		expectedError    string
	}{
		{
			name:          "Invalid key format",
			key:           "namespace/name/error",
			expectedError: "unexpected key format: \"namespace/name/error\"",
		},
		{
			name:          "Key does not exist",
			key:           "default/vm2-e8be5",
			expectedError: "",
		},
		{
			name:         "Key exists",
			key:          "default/TestNode",
			existingNode: node,
			expectedAgentCRD: &v1beta1.AntreaAgentInfo{
				ObjectMeta: metav1.ObjectMeta{
					Name: "TestNode",
				},
			},
			expectedError: "",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			clientset.Resources = []*metav1.APIResourceList{
				{
					GroupVersion: v1beta1.SchemeGroupVersion.String(),
					APIResources: []metav1.APIResource{{Name: agentInfoResourceKind}},
				},
			}
			controller := newControllerMonitor(clientset)
			if tt.existingNode != nil {
				controller.client = fake.NewSimpleClientset(node)
				controller.informerFactory = informers.NewSharedInformerFactory(controller.client, informerDefaultResync)
				controller.controllerMonitor.nodeInformer = controller.informerFactory.Core().V1().Nodes()
				controller.controllerMonitor.nodeLister = controller.controllerMonitor.nodeInformer.Lister()
			}
			stopCh := make(chan struct{})
			initController(controller, stopCh)
			defer close(stopCh)
			err := controller.controllerMonitor.syncNode(tt.key)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				if tt.expectedAgentCRD == nil {
					_, name, _ := splitKeyFunc(tt.key)
					_, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, name, metav1.GetOptions{})
					assert.True(t, errortesting.IsNotFound(err))
				} else {
					crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, tt.expectedAgentCRD.Name, metav1.GetOptions{})
					require.NoError(t, err)
					assert.Equal(t, tt.expectedAgentCRD, crd)
				}
			}
		})
	}
}

func TestDeleteAgentCRD(t *testing.T) {
	ctx := context.Background()
	testAgentCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "testAgentCRD",
			ResourceVersion: "0",
			Generation:      0,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum:  1,
			AddressGroupNum:   1,
			AppliedToGroupNum: 1,
		},
	}
	tc := []struct {
		name             string
		existingAgentCRD *v1beta1.AntreaAgentInfo
		prepareReactor   func(clientset *fakeclientset.Clientset)
		expectedError    string
	}{
		{
			name:             "deleted CRD AntreaAgentInfo with given name successfully",
			prepareReactor:   func(clientset *fakeclientset.Clientset) {},
			existingAgentCRD: testAgentCRD,
			expectedError:    "",
		},
		{
			name:           "no-ops when the CRD AntreaAgentInfo with given name does not exist",
			prepareReactor: func(clientset *fakeclientset.Clientset) {},
			expectedError:  "",
		},
		{
			name: "fail to delete CRD AntreaAgentInfo with given name due to error",
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("delete", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &v1beta1.AntreaAgentInfo{}, errors.New("error deleting agent crd")
				})
			},
			expectedError: "error deleting agent crd",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			if tt.existingAgentCRD != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingAgentCRD)
			}
			tt.prepareReactor(clientset)
			controller := newControllerMonitor(clientset)
			stopCh := make(chan struct{})
			initController(controller, stopCh)
			defer close(stopCh)
			err := controller.controllerMonitor.deleteAgentCRD("testAgentCRD")
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				_, err = controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, "testAgentCRD", metav1.GetOptions{})
				assert.True(t, errortesting.IsNotFound(err))
			}
		})
	}
}

func TestCreateAgentCRD(t *testing.T) {
	ctx := context.Background()
	testAgentCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "testAgentCRD",
			ResourceVersion: "",
			Generation:      0,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum:  0,
			AddressGroupNum:   0,
			AppliedToGroupNum: 0,
		},
	}
	tc := []struct {
		name             string
		existingAgentCRD *v1beta1.AntreaAgentInfo
		prepareReactor   func(clientset *fakeclientset.Clientset)
		expectedAgentCRD *v1beta1.AntreaAgentInfo
		expectedError    string
	}{
		{
			name:             "created CRD AntreaAgentInfo with given name successfully",
			prepareReactor:   func(clientset *fakeclientset.Clientset) {},
			expectedAgentCRD: testAgentCRD,
			expectedError:    "",
		},
		{
			name:             "no-ops when the CRD AntreaAgentInfo with given name already exists",
			prepareReactor:   func(clientset *fakeclientset.Clientset) {},
			existingAgentCRD: testAgentCRD,
			expectedAgentCRD: testAgentCRD,
			expectedError:    "",
		},
		{
			name: "fail to create CRD AntreaAgentInfo with given name due to error",
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("create", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &v1beta1.AntreaAgentInfo{}, errors.New("error creating agent crd as crd already exists")
				})
			},
			existingAgentCRD: testAgentCRD,
			expectedError:    "error creating agent crd as crd already exists",
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			if tt.existingAgentCRD != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingAgentCRD)
			}
			tt.prepareReactor(clientset)
			controller := newControllerMonitor(clientset)
			stopCh := make(chan struct{})
			initController(controller, stopCh)
			defer close(stopCh)
			err := controller.controllerMonitor.createAgentCRD("testAgentCRD")
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, tt.expectedAgentCRD.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, tt.expectedAgentCRD, crd)
			}
		})
	}
}

func TestDeleteStaleAgentCRD(t *testing.T) {
	ctx := context.Background()
	tc := []struct {
		name                 string
		agentCRDs            []string
		existingExternalNode *v1alpha1.ExternalNode
		prepareReactor       func(clientset *fakeclientset.Clientset)
		expectedError        string
		remainingAgentCRDs   []string
	}{
		{
			name:               "No external Nodes present",
			agentCRDs:          []string{"testAgentCRD1", "testAgentCRD2", "testAgentCRD3", "testAgentCRD4"},
			prepareReactor:     func(clientset *fakeclientset.Clientset) {},
			remainingAgentCRDs: []string{},
		},
		{
			name: "No Agent CRDs present",
			prepareReactor: func(clientset *fakeclientset.Clientset) {
				clientset.PrependReactor("list", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &v1beta1.AntreaAgentInfoList{}, errors.New("error getting agent crds")
				})
			},
			expectedError: "error getting agent crds",
		},
		{
			name:      "Both Agent CRDs and external Node present",
			agentCRDs: []string{"testAgentCRD1", "testAgentCRD2"},
			existingExternalNode: &v1alpha1.ExternalNode{ObjectMeta: metav1.ObjectMeta{
				Name:      "testAgentCRD1",
				Namespace: "ns1",
				Labels:    map[string]string{"en": "vm2"},
			},
			},
			prepareReactor:     func(clientset *fakeclientset.Clientset) {},
			remainingAgentCRDs: []string{"testAgentCRD1"},
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			if tt.existingExternalNode != nil {
				clientset = fakeclientset.NewSimpleClientset(tt.existingExternalNode)
			}
			clientset.Resources = []*metav1.APIResourceList{
				{
					GroupVersion: v1beta1.SchemeGroupVersion.String(),
					APIResources: []metav1.APIResource{{Name: agentInfoResourceKind}},
				},
			}
			tt.prepareReactor(clientset)
			controller := newControllerMonitor(clientset)
			stopCh := make(chan struct{})
			initController(controller, stopCh)
			defer close(stopCh)
			controller.controllerMonitor.externalNodeEnabled = true
			for _, crd := range tt.agentCRDs {
				agentCRD := new(v1beta1.AntreaAgentInfo)
				agentCRD.Name = crd
				agentCRD.ResourceVersion = "0"
				_, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().Create(ctx, agentCRD, metav1.CreateOptions{})
				assert.NoError(t, err)
			}
			controller.controllerMonitor.deleteStaleAgentCRDs()
			crds, err := controller.controllerMonitor.client.CrdV1beta1().AntreaAgentInfos().List(ctx, metav1.ListOptions{ResourceVersion: "0"})
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				require.NoError(t, err)
				remainingAgentCRDs := []string{}
				for _, crd := range crds.Items {
					remainingAgentCRDs = append(remainingAgentCRDs, crd.Name)
				}
				assert.Equal(t, tt.remainingAgentCRDs, remainingAgentCRDs)
			}
		})
	}
}

func TestSyncControllerCRD(t *testing.T) {
	ctx := context.Background()
	crdName := v1beta1.AntreaControllerInfoResourceName
	existingCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 1,
		},
		APIPort: 0,
	}
	partiallyUpdatedCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 0,
		},
		APIPort: 0,
	}
	entirelyUpdatedCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 0,
		},
		APIPort: 10349,
	}
	newCRD := &v1beta1.AntreaControllerInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		Version: "UNKNOWN",
		NodeRef: v1.ObjectReference{
			Kind: "Node",
		},
		ServiceRef: v1.ObjectReference{
			Kind: "Service",
			Name: "antrea",
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum:  0,
			AddressGroupNum:   0,
			AppliedToGroupNum: 0,
		},
		APIPort: 10349,
	}
	t.Run("partial update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.controllerCRD = existingCRD
		controller.controllerMonitor.syncControllerCRD()
		crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaControllerInfos().Get(ctx, crdName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, partiallyUpdatedCRD.NetworkPolicyControllerInfo.NetworkPolicyNum, crd.NetworkPolicyControllerInfo.NetworkPolicyNum)
	})
	t.Run("partial update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreacontrollerinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaControllerInfo{}, errors.New("error updating controller crd")
		})
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.controllerCRD = existingCRD
		controller.controllerMonitor.syncControllerCRD()
		assert.Nil(t, controller.controllerMonitor.controllerCRD)
	})
	t.Run("get-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset()
		clientset.PrependReactor("get", "antreacontrollerinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaControllerInfo{}, errors.New("error getting controller crd")
		})
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.syncControllerCRD()
		assert.Nil(t, controller.controllerMonitor.controllerCRD)
	})
	t.Run("create-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset()
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.querier.GetControllerInfo(newCRD, false)
		controller.controllerMonitor.syncControllerCRD()
		crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaControllerInfos().Get(ctx, crdName, metav1.GetOptions{})
		newCRD.ControllerConditions[0].LastHeartbeatTime.Time = crd.ControllerConditions[0].LastHeartbeatTime.Time
		require.NoError(t, err)
		assert.Equal(t, newCRD, crd)
	})
	t.Run("create-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset()
		clientset.PrependReactor("create", "antreacontrollerinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaControllerInfo{}, errors.New("error in creating controller crd")
		})
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.syncControllerCRD()
		assert.Nil(t, controller.controllerMonitor.controllerCRD)
	})
	t.Run("entire update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.syncControllerCRD()
		crd, err := controller.controllerMonitor.client.CrdV1beta1().AntreaControllerInfos().Get(ctx, crdName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, entirelyUpdatedCRD.APIPort, crd.APIPort)
	})
	t.Run("entire update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreacontrollerinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaControllerInfo{}, errors.New("error updating controller crd")
		})
		controller := newControllerMonitor(clientset)
		stopCh := make(chan struct{})
		initController(controller, stopCh)
		defer close(stopCh)
		controller.controllerMonitor.syncControllerCRD()
		assert.Nil(t, controller.controllerMonitor.controllerCRD)
	})
}

func TestEnqueueNode(t *testing.T) {
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "TestNode",
			Namespace: "ns1",
			Labels:    map[string]string{"en": "vm2"},
		},
	}
	clientset := fakeclientset.NewSimpleClientset()
	controller := newControllerMonitor(clientset)
	controller.controllerMonitor.enqueueNode(node)
	expectedkey, _ := keyFunc(node)
	obj, _ := controller.controllerMonitor.nodeQueue.Get()
	assert.Equal(t, expectedkey, obj.(string))
}

func TestEnqueueExternalNode(t *testing.T) {
	externalNode := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "TestExternalNode",
			Namespace: "ns1",
			Labels:    map[string]string{"en": "vm2"},
		},
	}
	clientset := fakeclientset.NewSimpleClientset()
	controller := newControllerMonitor(clientset)
	controller.controllerMonitor.enqueueExternalNode(externalNode)
	expectedkey, _ := keyFunc(externalNode)
	obj, _ := controller.controllerMonitor.externalNodeQueue.Get()
	assert.Equal(t, expectedkey, obj.(string))
}

func TestAntreaAgentInfoAPIAvailable(t *testing.T) {
	for _, tc := range []struct {
		name         string
		resources    []*metav1.APIResourceList
		expectResult bool
	}{
		{
			name: "AntreaAgentInfo API unavailable",
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: v1beta1.SchemeGroupVersion.String(),
				},
			},
			expectResult: false,
		}, {
			name: "AntreaAgentInfo API available",
			resources: []*metav1.APIResourceList{
				{
					GroupVersion: v1beta1.SchemeGroupVersion.String(),
					APIResources: []metav1.APIResource{{Kind: agentInfoResourceKind}},
				},
			},
			expectResult: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fakeclientset.NewSimpleClientset()
			clientset.Resources = tc.resources
			c := &controllerMonitor{client: clientset}
			stopCh := make(chan struct{})
			assert.Equal(t, tc.expectResult, c.antreaAgentInfoAPIAvailable(stopCh))
		})
	}
}

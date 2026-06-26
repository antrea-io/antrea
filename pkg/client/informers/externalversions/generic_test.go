// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package externalversions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

func TestGenericInformer_Informer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	gvr := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1alpha1",
		Resource: "bgppolicies",
	}

	genericInf, err := factory.ForResource(gvr)
	require.NoError(t, err, "ForResource should not return an error for valid resource")
	require.NotNil(t, genericInf, "GenericInformer should not be nil")

	informer := genericInf.Informer()
	assert.NotNil(t, informer, "Informer should not be nil")
	assert.Implements(t, (*cache.SharedIndexInformer)(nil), informer, "Should implement SharedIndexInformer interface")
}

func TestGenericInformer_Lister(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	gvr := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1alpha1",
		Resource: "bgppolicies",
	}

	genericInf, err := factory.ForResource(gvr)
	require.NoError(t, err, "ForResource should not return an error for valid resource")
	require.NotNil(t, genericInf, "GenericInformer should not be nil")

	lister := genericInf.Lister()
	assert.NotNil(t, lister, "Lister should not be nil")
	assert.Implements(t, (*cache.GenericLister)(nil), lister, "Should implement GenericLister interface")
}

func TestForResource_ValidResources(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	tests := []struct {
		name string
		gvr  schema.GroupVersionResource
	}{
		{
			name: "BGPPolicies v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "bgppolicies",
			},
		},
		{
			name: "ExternalNodes v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "externalnodes",
			},
		},
		{
			name: "FlowExporterDestinations v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "flowexporterdestinations",
			},
		},
		{
			name: "NodeLatencyMonitors v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "nodelatencymonitors",
			},
		},
		{
			name: "PacketCaptures v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "packetcaptures",
			},
		},
		{
			name: "SupportBundleCollections v1alpha1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "supportbundlecollections",
			},
		},
		{
			name: "ExternalEntities v1alpha2",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha2",
				Resource: "externalentities",
			},
		},
		{
			name: "IPPools v1alpha2",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha2",
				Resource: "ippools",
			},
		},
		{
			name: "TrafficControls v1alpha2",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha2",
				Resource: "trafficcontrols",
			},
		},
		{
			name: "AntreaAgentInfos v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "antreaagentinfos",
			},
		},
		{
			name: "AntreaControllerInfos v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "antreacontrollerinfos",
			},
		},
		{
			name: "ClusterGroups v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "clustergroups",
			},
		},
		{
			name: "ClusterNetworkPolicies v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "clusternetworkpolicies",
			},
		},
		{
			name: "Egresses v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "egresses",
			},
		},
		{
			name: "ExternalIPPools v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "externalippools",
			},
		},
		{
			name: "Groups v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "groups",
			},
		},
		{
			name: "IPPools v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "ippools",
			},
		},
		{
			name: "NetworkPolicies v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "networkpolicies",
			},
		},
		{
			name: "Tiers v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "tiers",
			},
		},
		{
			name: "Traceflows v1beta1",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1beta1",
				Resource: "traceflows",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genericInf, err := factory.ForResource(tt.gvr)
			assert.NoError(t, err, "ForResource should not return an error for valid resource")
			assert.NotNil(t, genericInf, "GenericInformer should not be nil")

			informer := genericInf.Informer()
			assert.NotNil(t, informer, "Informer should not be nil")

			lister := genericInf.Lister()
			assert.NotNil(t, lister, "Lister should not be nil")
		})
	}
}

func TestForResource_InvalidResource(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	tests := []struct {
		name        string
		gvr         schema.GroupVersionResource
		expectedErr string
	}{
		{
			name: "Unknown resource",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "unknownresource",
			},
			expectedErr: "no informer found",
		},
		{
			name: "Wrong version",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha3",
				Resource: "bgppolicies",
			},
			expectedErr: "no informer found",
		},
		{
			name: "Wrong group",
			gvr: schema.GroupVersionResource{
				Group:    "wrong.group",
				Version:  "v1alpha1",
				Resource: "bgppolicies",
			},
			expectedErr: "no informer found",
		},
		{
			name: "Empty resource",
			gvr: schema.GroupVersionResource{
				Group:    "crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "",
			},
			expectedErr: "no informer found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			genericInf, err := factory.ForResource(tt.gvr)
			assert.Error(t, err, "ForResource should return an error for invalid resource")
			assert.Contains(t, err.Error(), tt.expectedErr, "Error message should contain expected text")
			assert.Nil(t, genericInf, "GenericInformer should be nil for invalid resource")
		})
	}
}

func TestGenericInformer_ResourceGroupResource(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	gvr := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1alpha1",
		Resource: "bgppolicies",
	}

	genericInf, err := factory.ForResource(gvr)
	require.NoError(t, err, "ForResource should not return an error for valid resource")

	gi, ok := genericInf.(*genericInformer)
	require.True(t, ok, "Should be able to cast to *genericInformer")

	expectedGR := schema.GroupResource{
		Group:    "crd.antrea.io",
		Resource: "bgppolicies",
	}

	assert.Equal(t, expectedGR, gi.resource, "GroupResource should match expected value")
}

func TestForResource_ConsistentBehavior(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	factory := NewSharedInformerFactory(fakeClient, 0)

	gvr := schema.GroupVersionResource{
		Group:    "crd.antrea.io",
		Version:  "v1beta1",
		Resource: "egresses",
	}

	genericInf1, err1 := factory.ForResource(gvr)
	require.NoError(t, err1, "First call should not return an error")

	genericInf2, err2 := factory.ForResource(gvr)
	require.NoError(t, err2, "Second call should not return an error")

	assert.Equal(t, genericInf1.Informer(), genericInf2.Informer(),
		"Multiple calls to ForResource should return the same informer instance")
}

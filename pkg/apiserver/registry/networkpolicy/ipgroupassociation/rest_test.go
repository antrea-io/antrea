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

package ipgroupassociation

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

const informerDefaultResync = 30 * time.Second

type fakeIPBQuerier struct {
	ipGroupMap map[string][]types.Group
}

func (iq fakeIPBQuerier) GetAssociatedIPBlockGroups(ip net.IP) []types.Group {
	if groupList, ok := iq.ipGroupMap[ip.String()]; ok {
		return groupList
	}
	return nil
}

type fakeQuerier struct {
	groups map[string][]types.Group
}

func (q fakeQuerier) GetAssociatedGroups(name, namespace string) []types.Group {
	memberKey := k8s.NamespacedName(namespace, name)
	if refs, ok := q.groups[memberKey]; ok {
		return refs
	}
	return []types.Group{}
}

func TestREST(t *testing.T) {
	r := NewREST(nil, nil, nil, nil)
	assert.Equal(t, &controlplane.IPGroupAssociation{}, r.New())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	podA := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podA",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{IP: "10.10.0.1"},
			},
		},
	}
	podB := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podB",
			Namespace: "default",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{IP: "10.10.0.2"},
			},
		},
	}
	eeA := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeA",
			Namespace: "prod",
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "172.60.0.1"},
			},
		},
	}
	eeB := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "eeB",
			Namespace: "prod",
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "172.60.0.2"},
			},
		},
	}
	groups := map[string][]types.Group{
		"default/podA": {
			{
				UID: "groupUID1",
				SourceReference: &controlplane.GroupReference{
					Name: "cg1",
					UID:  "groupUID1",
				},
			},
		},
		"default/podB": {
			{
				UID: "groupUID1",
				SourceReference: &controlplane.GroupReference{
					Name: "cg1",
					UID:  "groupUID1",
				},
			},
			{
				UID: "groupUID2",
				SourceReference: &controlplane.GroupReference{
					Name: "cg2",
					UID:  "groupUID2",
				},
			},
		},
		"prod/eeA": {
			{
				UID: "groupUID4",
				SourceReference: &controlplane.GroupReference{
					Name: "cg4",
					UID:  "groupUID4",
				},
			},
		},
		"prod/eeB": {
			{
				UID: "groupUID5",
				SourceReference: &controlplane.GroupReference{
					Name: "cg5",
					UID:  "groupUID5",
				},
			},
		},
	}
	ipGroups := map[string][]types.Group{
		"192.168.0.1": {
			{
				UID: "groupUID6",
				SourceReference: &controlplane.GroupReference{
					Name: "cg6",
					UID:  "groupUID6",
				},
			},
		},
		"172.60.0.1": {
			{
				UID: "groupUID7",
				SourceReference: &controlplane.GroupReference{
					Name: "cg7",
					UID:  "groupUID7",
				},
			},
		},
		"172.60.0.2": {
			{
				UID: "groupUID7",
				SourceReference: &controlplane.GroupReference{
					Name: "cg7",
					UID:  "groupUID7",
				},
			},
		},
	}
	tests := []struct {
		name        string
		ipString    string
		expectedObj *controlplane.IPGroupAssociation
		expectErr   bool
	}{
		{
			name:        "bad-input",
			ipString:    "10.0.2",
			expectedObj: nil,
			expectErr:   true,
		},
		{
			name:     "pod-a-ip",
			ipString: "10.10.0.1",
			expectedObj: &controlplane.IPGroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg1",
						UID:       "groupUID1",
					},
				},
			},
			expectErr: false,
		},
		{
			name:     "pod-b-ip",
			ipString: "10.10.0.2",
			expectedObj: &controlplane.IPGroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg1",
						UID:       "groupUID1",
					},
					{
						Namespace: "",
						Name:      "cg2",
						UID:       "groupUID2",
					},
				},
			},
			expectErr: false,
		},
		{
			name:     "ee-a-ip",
			ipString: "172.60.0.1",
			expectedObj: &controlplane.IPGroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg4",
						UID:       "groupUID4",
					},
					{
						Namespace: "",
						Name:      "cg7",
						UID:       "groupUID7",
					},
				},
			},
			expectErr: false,
		},
		{
			name:     "ee-b-ip",
			ipString: "172.60.0.2",
			expectedObj: &controlplane.IPGroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg5",
						UID:       "groupUID5",
					},
					{
						Namespace: "",
						Name:      "cg7",
						UID:       "groupUID7",
					},
				},
			},
			expectErr: false,
		},
		{
			name:     "ip-block-ip",
			ipString: "192.168.0.1",
			expectedObj: &controlplane.IPGroupAssociation{
				AssociatedGroups: []controlplane.GroupReference{
					{
						Namespace: "",
						Name:      "cg6",
						UID:       "groupUID6",
					},
				},
			},
			expectErr: false,
		},
	}

	podObjs := []runtime.Object{podA, podB}
	client := fake.NewSimpleClientset(podObjs...)
	informerFactory := informers.NewSharedInformerFactory(client, informerDefaultResync)
	crdObjs := []runtime.Object{eeA, eeB}
	crdClient := fakeversioned.NewSimpleClientset(crdObjs...)
	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, informerDefaultResync)
	podInformer := informerFactory.Core().V1().Pods()
	eeInformer := crdInformerFactory.Crd().V1alpha2().ExternalEntities()
	podInformer.Informer().AddIndexers(cache.Indexers{grouping.PodIPsIndex: grouping.PodIPsIndexFunc})
	eeInformer.Informer().AddIndexers(cache.Indexers{grouping.ExternalEntityIPsIndex: grouping.ExternalEntityIPsIndexFunc})

	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	crdInformerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	crdInformerFactory.WaitForCacheSync(stopCh)

	rest := NewREST(podInformer, eeInformer, fakeIPBQuerier{ipGroupMap: ipGroups}, fakeQuerier{groups: groups})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualGroupListObj, err := rest.Get(request.NewDefaultContext(), tt.ipString, &metav1.GetOptions{})
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				actualGroupList, ok := actualGroupListObj.(*controlplane.IPGroupAssociation)
				if !ok {
					t.Errorf("returned query result is not of type IPGroupAssociation")
				}
				assert.ElementsMatch(t, tt.expectedObj.AssociatedGroups, actualGroupList.AssociatedGroups)
			}
		})
	}
}

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

package externalnode

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	fakeclientset "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
)

var (
	informerFactory crdinformers.SharedInformerFactory
)

func TestAddExternalNode(t *testing.T) {
	for _, tc := range []struct {
		name             string
		externalNode     *v1alpha1.ExternalNode
		expectedEntities []*v1alpha2.ExternalEntity
	}{
		{
			name: "add-interface-without-name",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.2"}}},
				},
			},
			expectedEntities: []*v1alpha2.ExternalEntity{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vm1",
						Namespace: "ns1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "crd.antrea.io/v1alpha1",
								Kind:       "ExternalNode",
								Name:       "vm1",
							},
						},
						Labels: map[string]string{"en": "vm1"},
					},
					Spec: v1alpha2.ExternalEntitySpec{
						Endpoints: []v1alpha2.Endpoint{
							{IP: "1.1.1.2"},
						},
						ExternalNode: "vm1",
					},
				},
			},
		},
		{
			name: "add-interface-with-name",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm2", Namespace: "ns1", Labels: map[string]string{"en": "vm2"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{Name: "ens192", IPs: []string{"1.1.1.3"}}},
				},
			},
			expectedEntities: []*v1alpha2.ExternalEntity{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vm2-e8be5",
						Namespace: "ns1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "crd.antrea.io/v1alpha1",
								Kind:       "ExternalNode",
								Name:       "vm2",
							},
						},
						Labels: map[string]string{"en": "vm2"},
					},
					Spec: v1alpha2.ExternalEntitySpec{
						Endpoints: []v1alpha2.Endpoint{
							{Name: "ens192", IP: "1.1.1.3"},
						},
						ExternalNode: "vm2",
					},
				},
			},
		},
		{
			name: "add-interface-multiple-ips",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4", "2.2.2.4"}}},
				},
			},
			expectedEntities: []*v1alpha2.ExternalEntity{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vm3",
						Namespace: "ns1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "crd.antrea.io/v1alpha1",
								Kind:       "ExternalNode",
								Name:       "vm3",
							},
						},
						Labels: map[string]string{"en": "vm3"},
					},
					Spec: v1alpha2.ExternalEntitySpec{
						Endpoints: []v1alpha2.Endpoint{
							{IP: "1.1.1.4"},
							{IP: "2.2.2.4"},
						},
						ExternalNode: "vm3",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := newExternalNodeController([]runtime.Object{tc.externalNode})
			stopCh := make(chan struct{})
			defer close(stopCh)
			informerFactory.Start(stopCh)
			go controller.Run(stopCh)
			err := wait.PollUntilContextTimeout(context.Background(), time.Millisecond*50, time.Second, true, func(ctx context.Context) (done bool, err error) {
				for _, ee := range tc.expectedEntities {
					ok, err := checkExternalEntityExists(controller.crdClient, ee)
					if err != nil {
						return false, err
					}
					if !ok {
						return false, nil
					}
				}
				return true, nil
			})
			assert.NoError(t, err)
		})
	}
}

func TestUpdateExternalNode(t *testing.T) {
	for _, tc := range []struct {
		name                string
		externalNode        *v1alpha1.ExternalNode
		existingEntity      *v1alpha2.ExternalEntity
		updatedExternalNode *v1alpha1.ExternalNode
		expectedEntity      *v1alpha2.ExternalEntity
	}{
		{
			name: "update-interface-ip",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.2"}}},
				},
			},
			existingEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm1",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm1",
						},
					},
					Labels: map[string]string{"en": "vm1"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.2"},
					},
					ExternalNode: "vm1",
				},
			},
			updatedExternalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.3"}}},
				},
			},
			expectedEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm1",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm1",
						},
					},
					Labels: map[string]string{"en": "vm1"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.3"},
					},
					ExternalNode: "vm1",
				},
			},
		},
		{
			name: "update-interface-name",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm2", Namespace: "ns1", Labels: map[string]string{"en": "vm2"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.3"}}},
				},
			},
			existingEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm2",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm2",
						},
					},
					Labels: map[string]string{"en": "vm2"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.3"},
					},
					ExternalNode: "vm2",
				},
			},
			updatedExternalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm2", Namespace: "ns1", Labels: map[string]string{"en": "vm2"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{Name: "ens192", IPs: []string{"1.1.1.3"}}},
				},
			},
			expectedEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm2-e8be5",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm2",
						},
					},
					Labels: map[string]string{"en": "vm2"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{Name: "ens192", IP: "1.1.1.3"},
					},
					ExternalNode: "vm2",
				},
			},
		},
		{
			name: "entity-removed-before-update",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm2", Namespace: "ns1", Labels: map[string]string{"en": "vm2"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.3"}}},
				},
			},
			existingEntity: nil,
			updatedExternalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm2", Namespace: "ns1", Labels: map[string]string{"en": "vm2"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{Name: "ens192", IPs: []string{"1.1.1.3"}}},
				},
			},
			expectedEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm2-e8be5",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm2",
						},
					},
					Labels: map[string]string{"en": "vm2"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{Name: "ens192", IP: "1.1.1.3"},
					},
					ExternalNode: "vm2",
				},
			},
		},
		{
			name: "update-label",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4"}}},
				},
			},
			existingEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm3",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm3",
						},
					},
					Labels: map[string]string{"en": "vm3"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.4"},
					},
					ExternalNode: "vm3",
				},
			},
			updatedExternalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3", "app": "db"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4"}}},
				},
			},
			expectedEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm3",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm3",
						},
					},
					Labels: map[string]string{"en": "vm3", "app": "db"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.4"},
					},
					ExternalNode: "vm3",
				},
			},
		},
		{
			name: "entity-removed-before-update-label",
			externalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4"}}},
				},
			},
			existingEntity: nil,
			updatedExternalNode: &v1alpha1.ExternalNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3", "app": "db"}},
				Spec: v1alpha1.ExternalNodeSpec{
					Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4"}}},
				},
			},
			expectedEntity: &v1alpha2.ExternalEntity{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "vm3",
					Namespace: "ns1",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "crd.antrea.io/v1alpha1",
							Kind:       "ExternalNode",
							Name:       "vm3",
						},
					},
					Labels: map[string]string{"en": "vm3", "app": "db"},
				},
				Spec: v1alpha2.ExternalEntitySpec{
					Endpoints: []v1alpha2.Endpoint{
						{IP: "1.1.1.4"},
					},
					ExternalNode: "vm3",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := newExternalNodeController([]runtime.Object{tc.externalNode})
			stopCh := make(chan struct{})
			defer close(stopCh)
			informerFactory.Start(stopCh)
			go controller.Run(stopCh)
			err := wait.PollUntilContextTimeout(context.Background(), time.Millisecond*50, time.Second, true, func(ctx context.Context) (done bool, err error) {
				entities, listErr := controller.crdClient.CrdV1alpha2().ExternalEntities(tc.externalNode.Namespace).List(context.TODO(), metav1.ListOptions{})
				if listErr != nil {
					return false, listErr
				}
				if len(entities.Items) == 0 {
					return false, nil
				}
				tempEE := entities.Items[0]
				if tc.existingEntity == nil {
					deleteErr := controller.crdClient.CrdV1alpha2().ExternalEntities(tc.externalNode.Namespace).Delete(context.TODO(), tempEE.Name, metav1.DeleteOptions{})
					if deleteErr != nil {
						return false, nil
					}
				}
				return true, nil
			})
			require.NoError(t, err)

			_, err = controller.crdClient.CrdV1alpha1().ExternalNodes(tc.externalNode.Namespace).Update(context.TODO(), tc.updatedExternalNode, metav1.UpdateOptions{})
			require.NoError(t, err)
			err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*50, time.Second, true, func(ctx context.Context) (done bool, err error) {
				return checkExternalEntityExists(controller.crdClient, tc.expectedEntity)
			})
			assert.NoError(t, err)
			if tc.existingEntity != nil {
				exists, err := checkExternalEntityExists(controller.crdClient, tc.existingEntity)
				assert.NoError(t, err)
				assert.False(t, exists)
			}
		})

	}
}

func TestDeleteExternalNode(t *testing.T) {
	externalNode := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "vm1", Namespace: "ns1", Labels: map[string]string{"en": "vm1"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.2"}}},
		},
	}
	expectedEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vm1",
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "crd.antrea.io/v1alpha1",
					Kind:       "ExternalNode",
					Name:       "vm1",
				},
			},
			Labels: map[string]string{"en": "vm1"},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "1.1.1.2"},
			},
			ExternalNode: "vm1",
		},
	}
	controller := newExternalNodeController([]runtime.Object{externalNode, expectedEntity})
	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	go controller.Run(stopCh)
	controller.syncedExternalNode.Add(externalNode)
	err := controller.crdClient.CrdV1alpha1().ExternalNodes(externalNode.Namespace).Delete(context.TODO(), externalNode.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	key, _ := keyFunc(externalNode)
	err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond*50, time.Second, true, func(ctx context.Context) (done bool, err error) {
		entities, listErr := controller.crdClient.CrdV1alpha2().ExternalEntities(externalNode.Namespace).List(context.TODO(), metav1.ListOptions{})
		if listErr != nil {
			return false, listErr
		}
		if len(entities.Items) > 0 {
			return false, nil
		}
		_, exists, _ := controller.syncedExternalNode.GetByKey(key)
		if exists {
			return false, nil
		}
		return true, nil
	})
	assert.NoError(t, err)
}

func TestReconcileExternalNodes(t *testing.T) {
	existingExternalNode := &v1alpha1.ExternalNode{
		ObjectMeta: metav1.ObjectMeta{Name: "vm3", Namespace: "ns1", Labels: map[string]string{"en": "vm3"}},
		Spec: v1alpha1.ExternalNodeSpec{
			Interfaces: []v1alpha1.NetworkInterface{{IPs: []string{"1.1.1.4", "2.2.2.4"}}},
		},
	}
	existingEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vm1",
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "crd.antrea.io/v1alpha1",
					Kind:       "ExternalNode",
					Name:       "vm1",
				},
			},
			Labels: map[string]string{"en": "vm1"},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "1.1.1.4"},
			},
			ExternalNode: "vm1",
		},
	}
	expectedEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vm3",
			Namespace: "ns1",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "crd.antrea.io/v1alpha1",
					Kind:       "ExternalNode",
					Name:       "vm3",
				},
			},
			Labels: map[string]string{"en": "vm3"},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "1.1.1.4"},
				{IP: "2.2.2.4"},
			},
			ExternalNode: "vm3",
		},
	}
	crdObjects := []runtime.Object{existingExternalNode, existingEntity}
	controller := newExternalNodeController(crdObjects)
	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	err := controller.reconcileExternalNodes()
	require.NoError(t, err)
	ok, checkErr := checkExternalEntityExists(controller.crdClient, expectedEntity)
	assert.NoError(t, checkErr)
	assert.True(t, ok)
	ok, checkErr = checkExternalEntityExists(controller.crdClient, existingEntity)
	assert.NoError(t, checkErr)
	assert.False(t, ok)
}

func TestUpdateExternalEntity(t *testing.T) {
	existingEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vm2",
			Namespace: "ns1",
			Labels:    map[string]string{"en": "vm2"},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "1.1.1.3"},
			},
			ExternalNode: "vm2",
		},
	}
	updatedEntity := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vm2",
			Namespace: "ns1",
			Labels:    map[string]string{"en": "vm2", "app": "db"},
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints: []v1alpha2.Endpoint{
				{IP: "1.1.1.4"},
			},
			ExternalNode: "vm2",
		},
	}
	t.Run("get-failure", func(t *testing.T) {
		crdClient := fakeclientset.NewSimpleClientset()
		crdClient.PrependReactor("get", "externalentities", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("unable to get externalEntity ")
		})
		controller := &ExternalNodeController{
			crdClient: crdClient,
		}
		err := controller.updateExternalEntity(updatedEntity)
		assert.Error(t, err)
	})
	t.Run("create-failure", func(t *testing.T) {
		crdClient := fakeclientset.NewSimpleClientset()
		crdClient.PrependReactor("create", "externalentities", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("unable to create externalEntity ")
		})
		controller := &ExternalNodeController{
			crdClient: crdClient,
		}
		err := controller.updateExternalEntity(updatedEntity)
		assert.Error(t, err)
	})
	t.Run("create-success", func(t *testing.T) {
		crdClient := fakeclientset.NewSimpleClientset()
		controller := &ExternalNodeController{
			crdClient: crdClient,
		}
		err := controller.updateExternalEntity(updatedEntity)
		require.NoError(t, err)
		entity, err := crdClient.CrdV1alpha2().ExternalEntities(existingEntity.Namespace).Get(context.TODO(), existingEntity.Name, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.True(t, reflect.DeepEqual(updatedEntity, entity))
	})
	t.Run("update-success", func(t *testing.T) {
		crdClient := fakeclientset.NewSimpleClientset(existingEntity)
		controller := &ExternalNodeController{
			crdClient: crdClient,
		}
		err := controller.updateExternalEntity(updatedEntity)
		require.NoError(t, err)
		entity, err := crdClient.CrdV1alpha2().ExternalEntities(existingEntity.Namespace).Get(context.TODO(), existingEntity.Name, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.True(t, reflect.DeepEqual(updatedEntity, entity))
	})
}

func checkExternalEntityExists(crdClient versioned.Interface, ee *v1alpha2.ExternalEntity) (bool, error) {
	entity, getErr := crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Get(context.TODO(), ee.Name, metav1.GetOptions{})
	if getErr != nil {
		if errors.IsNotFound(getErr) {
			return false, nil
		}
		return false, getErr
	}
	if !reflect.DeepEqual(ee, entity) {
		return false, nil
	}
	return true, nil
}

func newExternalNodeController(objects []runtime.Object) *ExternalNodeController {
	crdClient := fakeclientset.NewSimpleClientset(objects...)
	informerFactory = crdinformers.NewSharedInformerFactory(crdClient, resyncPeriod)
	externalNodeInformer := informerFactory.Crd().V1alpha1().ExternalNodes()
	externalEntityInformer := informerFactory.Crd().V1alpha2().ExternalEntities()
	return NewExternalNodeController(crdClient, externalNodeInformer, externalEntityInformer)
}

// Copyright 2026 Antrea Authors
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

package informers

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

func TestEgressInformersReadStorageVersion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// List items need not have TypeMeta, and the conversion webhook / v1beta2 API is unavailable.
		egress := &crdv1beta1.Egress{
			ObjectMeta: metav1.ObjectMeta{
				Name: "egress", ResourceVersion: "1", Labels: map[string]string{"app": "test"},
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "test"}},
			},
			Spec:   crdv1beta1.EgressSpec{EgressIP: "192.0.2.10", ExternalIPPool: "pool"},
			Status: crdv1beta1.EgressStatus{EgressIP: "192.0.2.10", EgressNode: "node-a"},
		}
		pool := &crdv1beta1.ExternalIPPool{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pool", ResourceVersion: "1",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "test"}},
			},
			Spec: crdv1beta1.ExternalIPPoolSpec{
				IPRanges:   []crdv1beta1.IPRange{{CIDR: "192.0.2.0/24"}},
				SubnetInfo: &crdv1beta1.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 10},
			},
		}
		client := fake.NewSimpleClientset(egress, pool)
		client.PrependReactor("*", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
			if action.GetResource().Version != "v1beta1" {
				return true, nil, fmt.Errorf("conversion webhook unavailable")
			}
			return false, nil, nil
		})
		client.PrependWatchReactor("*", func(action clienttesting.Action) (bool, watch.Interface, error) {
			if action.GetResource().Version != "v1beta1" {
				return true, nil, fmt.Errorf("conversion webhook unavailable")
			}
			return false, nil, nil
		})
		factory := crdinformers.NewSharedInformerFactoryWithOptions(client, 0, crdinformers.WithTransform(k8s.NewTrimmer()))
		egresses, pools, err := NewEgressInformers(factory)
		require.NoError(t, err)
		deleted := make(chan interface{}, 2)
		for _, informer := range []cache.SharedIndexInformer{egresses.Informer(), pools.Informer()} {
			_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{DeleteFunc: func(obj interface{}) {
				deleted <- obj
			}})
			require.NoError(t, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer factory.Shutdown()
		defer cancel()
		factory.Start(ctx.Done())
		require.True(t, cache.WaitForCacheSync(ctx.Done(), egresses.Informer().HasSynced, pools.Informer().HasSynced))

		actualEgress, err := egresses.Lister().Get(egress.Name)
		require.NoError(t, err)
		assert.Equal(t, []string{"192.0.2.10"}, actualEgress.Spec.EgressIPs)
		assert.Empty(t, actualEgress.Spec.IPFamilies)
		assert.Equal(t, []string{"192.0.2.10"}, actualEgress.Status.EgressIPs)
		assert.Equal(t, "node-a", actualEgress.Status.EgressNode)
		assert.Nil(t, actualEgress.ManagedFields)
		listed, err := egresses.Lister().List(labels.SelectorFromSet(egress.Labels))
		require.NoError(t, err)
		assert.Equal(t, []*crdv1beta2.Egress{actualEgress}, listed)
		actualPool, err := pools.Lister().Get(pool.Name)
		require.NoError(t, err)
		assert.Equal(t, []crdv1beta2.SubnetInfo{{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 10}}, actualPool.Spec.Subnets)
		assert.Nil(t, actualPool.ManagedFields)

		updatedEgress := egress.DeepCopy()
		updatedEgress.ResourceVersion = "2"
		updatedEgress.Spec.EgressIP = "192.0.2.11"
		updatedEgress.Status.EgressIP = "192.0.2.11"
		_, err = client.CrdV1beta1().Egresses().Update(ctx, updatedEgress, metav1.UpdateOptions{})
		require.NoError(t, err)
		updatedPool := pool.DeepCopy()
		updatedPool.ResourceVersion = "2"
		updatedPool.Spec.SubnetInfo.VLAN = 20
		_, err = client.CrdV1beta1().ExternalIPPools().Update(ctx, updatedPool, metav1.UpdateOptions{})
		require.NoError(t, err)
		synctest.Wait()
		e, err := egresses.Lister().Get(egress.Name)
		require.NoError(t, err)
		assert.Equal(t, []string{"192.0.2.11"}, e.Spec.EgressIPs)
		assert.Equal(t, []string{"192.0.2.11"}, e.Status.EgressIPs)
		p, err := pools.Lister().Get(pool.Name)
		require.NoError(t, err)
		assert.Equal(t, []crdv1beta2.SubnetInfo{{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 20}}, p.Spec.Subnets)

		require.NoError(t, client.CrdV1beta1().Egresses().Delete(ctx, egress.Name, metav1.DeleteOptions{}))
		require.NoError(t, client.CrdV1beta1().ExternalIPPools().Delete(ctx, pool.Name, metav1.DeleteOptions{}))
		for range 2 {
			select {
			case obj := <-deleted:
				switch obj.(type) {
				case *crdv1beta2.Egress, *crdv1beta2.ExternalIPPool:
				default:
					t.Fatalf("delete handler received unexpected type %T", obj)
				}
			case <-ctx.Done():
				t.Fatal("timed out waiting for delete events")
			}
		}
		_, err = egresses.Lister().Get(egress.Name)
		assert.True(t, errors.IsNotFound(err))
		_, err = pools.Lister().Get(pool.Name)
		assert.True(t, errors.IsNotFound(err))
		seen := map[string]bool{}
		for _, action := range client.Actions() {
			assert.Equal(t, "v1beta1", action.GetResource().Version)
			seen[action.GetVerb()+" "+action.GetResource().Resource] = true
		}
		for _, action := range []string{"list egresses", "watch egresses", "list externalippools", "watch externalippools"} {
			assert.True(t, seen[action], "missing %s request", action)
		}
	})
}

func TestConvertToV1beta2ConversionDataCompatibility(t *testing.T) {
	const annotation = "crd.antrea.io/conversion-data"
	// Keep these v1 envelope fixtures independent of the current encoder. Agents and Controllers may run different
	// versions: old envelopes must remain readable, and additive fields from newer writers must be ignored.
	for _, tc := range []struct {
		name     string
		object   runtime.Object
		expected runtime.Object
	}{
		{
			name: "Egress",
			object: &crdv1beta1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egress", Annotations: map[string]string{
					"user":     "keep",
					annotation: `{"version":"v1","kind":"Egress","data":{"sourceVersion":"crd.antrea.io/v1beta2","egressIPs":["192.0.2.10","2001:db8::10"],"ipFamilies":["IPv4","IPv6"],"projectedEgressIP":"192.0.2.10","projectedExternalIPPool":"pool","statusEgressIPs":["192.0.2.10","2001:db8::10"],"projectedStatusEgressIP":"192.0.2.10"}}`,
				}},
				Spec:   crdv1beta1.EgressSpec{EgressIP: "192.0.2.10", ExternalIPPool: "pool"},
				Status: crdv1beta1.EgressStatus{EgressIP: "192.0.2.10", EgressNode: "node-a"},
			},
			expected: &crdv1beta2.Egress{
				TypeMeta:   metav1.TypeMeta{APIVersion: crdv1beta2.SchemeGroupVersion.String(), Kind: "Egress"},
				ObjectMeta: metav1.ObjectMeta{Name: "egress", Annotations: map[string]string{"user": "keep"}},
				Spec: crdv1beta2.EgressSpec{
					EgressIPs: []string{"192.0.2.10", "2001:db8::10"}, ExternalIPPool: "pool",
					IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
				},
				Status: crdv1beta2.EgressStatus{EgressIPs: []string{"192.0.2.10", "2001:db8::10"}, EgressNode: "node-a"},
			},
		},
		{
			name: "ExternalIPPool",
			object: &crdv1beta1.ExternalIPPool{
				ObjectMeta: metav1.ObjectMeta{Name: "pool", Annotations: map[string]string{
					"user":     "keep",
					annotation: `{"version":"v1","kind":"ExternalIPPool","data":{"sourceVersion":"crd.antrea.io/v1beta2","subnets":[{"gateway":"192.0.2.1","prefixLength":24},{"gateway":"2001:db8::1","prefixLength":64}],"projectedGateway":"192.0.2.1","projectedPrefixLength":24}}`,
				}},
				Spec: crdv1beta1.ExternalIPPoolSpec{
					IPRanges:   []crdv1beta1.IPRange{{CIDR: "192.0.2.0/24"}, {CIDR: "2001:db8::/64"}},
					SubnetInfo: &crdv1beta1.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 24},
				},
			},
			expected: &crdv1beta2.ExternalIPPool{
				TypeMeta:   metav1.TypeMeta{APIVersion: crdv1beta2.SchemeGroupVersion.String(), Kind: "ExternalIPPool"},
				ObjectMeta: metav1.ObjectMeta{Name: "pool", Annotations: map[string]string{"user": "keep"}},
				Spec: crdv1beta2.ExternalIPPoolSpec{
					IPRanges: []crdv1beta2.IPRange{{CIDR: "192.0.2.0/24"}, {CIDR: "2001:db8::/64"}},
					Subnets:  []crdv1beta2.SubnetInfo{{Gateway: "192.0.2.1", PrefixLength: 24}, {Gateway: "2001:db8::1", PrefixLength: 64}},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, unknownFields := range []bool{false, true} {
				t.Run(fmt.Sprintf("unknownFields=%t", unknownFields), func(t *testing.T) {
					object := tc.object.DeepCopyObject()
					if unknownFields {
						accessor, err := meta.Accessor(object)
						require.NoError(t, err)
						var envelope map[string]interface{}
						require.NoError(t, json.Unmarshal([]byte(accessor.GetAnnotations()[annotation]), &envelope))
						envelope["futureField"] = "ignored"
						envelope["data"].(map[string]interface{})["futureField"] = "ignored"
						raw, err := json.Marshal(envelope)
						require.NoError(t, err)
						accessor.GetAnnotations()[annotation] = string(raw)
					}
					before := object.DeepCopyObject()
					converted, err := convertToV1beta2(object)
					require.NoError(t, err)
					assert.Equal(t, tc.expected, converted)
					assert.Equal(t, before, object, "conversion must not mutate the source object")
					again, err := convertToV1beta2(converted)
					require.NoError(t, err)
					assert.Same(t, converted, again, "already converted objects must pass through unchanged")
				})
			}
		})
	}
}

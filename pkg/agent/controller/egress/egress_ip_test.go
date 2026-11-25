//go:build !windows

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

package egress

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"

	cpv1b2 "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	crdv1b2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
)

const fakeLocalEgressIPv6 = "2001:db8::10"

func parseEgressTestIPs(ips []string) []net.IP {
	parsed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsed = append(parsed, net.ParseIP(ip))
	}
	return parsed
}

func newIPGroupTestController(t *testing.T, objects ...runtime.Object) *fakeController {
	c := newFakeController(t, objects)
	t.Cleanup(c.queue.ShutDown)
	t.Cleanup(c.egressIPScheduler.queue.ShutDown)
	t.Cleanup(c.eventBroadcaster.Shutdown)
	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(fakeLocalEgressIP1, fakeLocalEgressIPv6)}
	for _, object := range objects {
		switch object := object.(type) {
		case *crdv1b2.Egress:
			require.NoError(t, c.egressInformer.GetIndexer().Add(object))
		case *crdv1b2.ExternalIPPool:
			require.NoError(t, c.crdInformerFactory.Crd().V1beta2().ExternalIPPools().Informer().GetIndexer().Add(object))
		}
	}
	return c
}

func TestSyncEgressIPGroup(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("IPv6First=%t", reverse), func(t *testing.T) {
			ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			if reverse {
				slices.Reverse(ips)
			}
			egress := &crdv1b2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "dual-stack"},
				Spec:       crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool, Bandwidth: &fakeBandwidth},
				Status:     crdv1b2.EgressStatus{Conditions: []metav1.Condition{{Type: crdv1b2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated"}}},
			}
			pool := &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}}
			c := newIPGroupTestController(t, egress, pool)
			c.egressIPScheduler.schedule()
			c.addEgressGroup(&cpv1b2.EgressGroup{ObjectMeta: egress.ObjectMeta,
				GroupMembers: []cpv1b2.GroupMember{{Pod: &cpv1b2.PodReference{Namespace: "ns1", Name: "pod1"}}}})
			parsedIPs := []net.IP{net.ParseIP(ips[0]), net.ParseIP(ips[1])}
			c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true).Return(true, nil)
			}
			c.mockOFClient.EXPECT().InstallSNATMarkFlows(parsedIPs, uint32(1))
			c.mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
			c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), parsedIPs, uint32(1))
			require.NoError(t, c.syncEgress(egress.Name))

			stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, ips, stored.Status.EgressIPs)
			assert.Equal(t, fakeNode, stored.Status.EgressNode)
			assert.Equal(t, metav1.ConditionTrue, meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAssigned).Status)
			assert.Equal(t, metav1.ConditionTrue, meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAllocated).Status)
			for _, family := range []bool{false, true} {
				ip, err := c.GetEgressIPByMark(1, family)
				require.NoError(t, err)
				assert.Equal(t, family, net.ParseIP(ip).To4() == nil)
			}

			// A later sync is idempotent and does not reinstall either family's datapath.
			require.NoError(t, c.egressInformer.GetIndexer().Update(stored))
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().AssignIP(ip, nil, false).Return(false, nil)
			}
			require.NoError(t, c.syncEgress(egress.Name))

			c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
			c.mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))
			c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
			c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().UnassignIP(ip)
			}
			require.NoError(t, c.egressInformer.GetIndexer().Delete(stored))
			require.NoError(t, c.syncEgress(egress.Name))
			assert.Empty(t, c.egressIPGroups)
			assert.Empty(t, c.egressStates)
		})
	}
}

func TestAssignEgressIPGroupRollback(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollbackFails=%t", rollbackFails), func(t *testing.T) {
			ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool}}
			pool := &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}}
			c := newIPGroupTestController(t, egress, pool)
			c.egressIPScheduler.schedule()
			assignErr := fmt.Errorf("second assignment failed")
			var rollbackErr error
			if rollbackFails {
				rollbackErr = fmt.Errorf("rollback failed")
			}
			gomock.InOrder(
				c.mockIPAssigner.EXPECT().AssignIP(ips[0], nil, true).Return(true, nil),
				c.mockIPAssigner.EXPECT().AssignIP(ips[1], nil, true).Return(false, assignErr),
				c.mockIPAssigner.EXPECT().UnassignIP(ips[0]).Return(!rollbackFails, rollbackErr),
			)
			err := c.syncEgress(egress.Name)
			require.ErrorIs(t, err, assignErr)
			if rollbackFails {
				require.ErrorIs(t, err, rollbackErr)
			}
			// Deletion retries the complete group's cleanup, including a failed rollback.
			require.NoError(t, c.egressInformer.GetIndexer().Delete(egress))
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().UnassignIP(ip)
			}
			require.NoError(t, c.syncEgress(egress.Name))
			assert.Empty(t, c.egressIPGroups)
		})
	}
}

func TestSyncEgressStatusVersionAfterConflict(t *testing.T) {
	pair := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	for _, tt := range []struct {
		name     string
		result   scheduleResult
		versions []string
	}{
		{"dual-stack scheduler result", scheduleResult{ips: pair, node: fakeNode}, []string{"v1beta2", "v1beta2"}},
		{"clearing assignment after a dual-stack refresh", scheduleResult{err: fmt.Errorf("no Node available")}, []string{"v1beta1", "v1beta2"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stale := &crdv1b2.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egress", ResourceVersion: "1"},
				Spec:       crdv1b2.EgressSpec{EgressIPs: pair[:1], ExternalIPPool: fakeExternalIPPool},
			}
			c := newIPGroupTestController(t, stale, &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}})
			c.egressIPScheduler.scheduleResults[stale.Name] = &tt.result
			latest := stale.DeepCopy()
			latest.Spec.EgressIPs = pair
			latest.ResourceVersion = "2"
			latest.Status = crdv1b2.EgressStatus{
				EgressNode: fakeNode2,
				EgressIPs:  pair,
				Conditions: []metav1.Condition{{
					Type: crdv1b2.IPAllocated, Status: metav1.ConditionTrue, Reason: "Allocated",
					LastTransitionTime: metav1.NewTime(time.Unix(1000, 0)),
				}},
			}
			require.NoError(t, c.crdClient.Tracker().Update(crdv1b2.SchemeGroupVersion.WithResource("egresses"), latest, ""))
			var versions []string
			c.crdClient.PrependReactor("update", "egresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
				require.Equal(t, "status", action.GetSubresource())
				versions = append(versions, action.GetResource().Version)
				if len(versions) == 1 {
					return true, nil, apierrors.NewConflict(crdv1b2.Resource("egresses"), stale.Name, fmt.Errorf("concurrent update"))
				}
				return false, nil, nil
			})
			ips := tt.result.ips
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true)
			}
			if len(ips) > 0 {
				c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
				c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(ips), uint32(1))
			}
			require.NoError(t, c.syncEgress(stale.Name))
			assert.Equal(t, tt.versions, versions)
			stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), stale.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, ips, stored.Status.EgressIPs)
			assert.Equal(t, latest.Spec, stored.Spec)
			assert.Equal(t, &latest.Status.Conditions[0], meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAllocated))
		})
	}
}

func TestEgressIPGroupSharingAndOverlap(t *testing.T) {
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	first := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "first"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, Bandwidth: &fakeBandwidth}}
	second := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "second"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips}}
	c := newIPGroupTestController(t, first, second)
	require.NoError(t, c.referenceEgressIPs("first", ips))
	reversed := []string{fakeLocalEgressIPv6, fakeLocalEgressIP1}
	require.NoError(t, c.referenceEgressIPs("second", reversed))
	assert.Len(t, c.egressIPGroups, 1)
	for _, partial := range [][]string{{fakeLocalEgressIP1}, {fakeLocalEgressIPv6}, {fakeLocalEgressIP1, "2001:db8::11"}, {"1.1.1.2", fakeLocalEgressIPv6}} {
		require.ErrorContains(t, c.referenceEgressIPs("overlap", partial), "already used by a different IP group")
	}
	c.mockOFClient.EXPECT().InstallSNATMarkFlows([]net.IP{net.ParseIP(ips[0]), net.ParseIP(ips[1])}, uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	mark, err := c.realizeEgressIPs(ips, []*crdv1b2.SubnetInfo{nil, nil})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
	mark, err = c.realizeEgressIPs(reversed, []*crdv1b2.SubnetInfo{nil, nil})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
	c.mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
	require.NoError(t, c.realizeEgressQoS("first", c.newEgressState("first", ips), mark, &fakeBandwidth))
	require.NoError(t, c.realizeEgressQoS("second", c.newEgressState("second", reversed), mark, nil))
	// The first deletion must retain addresses, flows, meter and mark for the remaining Egress.
	require.NoError(t, c.unrealizeEgressIPs("first", ips, nil))
	assert.Len(t, c.egressIPGroups, 1)
	assert.Equal(t, 1, c.queue.Len(), "a remaining reference must reconcile its bandwidth")
	second.Spec.Bandwidth = &newFakeBandwidth
	require.NoError(t, c.egressInformer.GetIndexer().Update(second))
	c.mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(10000), uint32(20000))
	require.NoError(t, c.realizeEgressQoS("second", c.newEgressState("second", reversed), mark, &newFakeBandwidth))
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().UnassignIP(ip)
	}
	c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
	c.mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))
	require.NoError(t, c.unrealizeEgressIPs("second", reversed, nil))
	assert.Empty(t, c.egressIPGroups)
}

func TestEgressIPGroupCleanupRetry(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	require.NoError(t, c.referenceEgressIPs("dual", ips))
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(gomock.Any(), uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	_, err := c.realizeEgressIPs(ips, []*crdv1b2.SubnetInfo{nil, nil})
	require.NoError(t, err)
	deleteErr := fmt.Errorf("IPv6 deletion failed")
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1)).Return(deleteErr)
	require.ErrorIs(t, c.unrealizeEgressIPs("dual", ips, nil), deleteErr)
	assert.Equal(t, uint32(1), c.egressIPGroups[egressIPGroupKey(ips)].mark)
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
	c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().UnassignIP(ip)
	}
	require.NoError(t, c.unrealizeEgressIPs("dual", ips, nil))
	assert.Empty(t, c.egressIPGroups)
	mark, err := c.markAllocator.allocate()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
}

func TestEgressIPGroupRequiresColocation(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, "2001:db8::11"}
	require.NoError(t, c.referenceEgressIPs("dual", ips))
	_, err := c.realizeEgressIPs(ips, []*crdv1b2.SubnetInfo{nil, nil})
	require.ErrorContains(t, err, "must be assigned together")
	_, err = c.GetEgressIPByMark(0, true)
	require.Error(t, err, "unrealized IPs must not be returned for the reserved zero mark")
}

func TestReplaceEgressIPGroup(t *testing.T) {
	ips := []string{fakeLocalEgressIPv6, fakeLocalEgressIP1}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"},
		Spec:   crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool},
		Status: crdv1b2.EgressStatus{EgressIPs: ips, EgressNode: fakeNode}}
	pool := &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool},
		Spec: crdv1b2.ExternalIPPoolSpec{Subnets: []crdv1b2.SubnetInfo{
			{Gateway: fakeGatewayIP, PrefixLength: 16}, {Gateway: "2001:db8::1", PrefixLength: 64}}}}
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missingPool=%t", missing), func(t *testing.T) {
			var objects []runtime.Object
			objects = append(objects, egress)
			if !missing {
				objects = append(objects, pool)
			}
			c := newIPGroupTestController(t, objects...)
			desired := map[string]*crdv1b2.SubnetInfo{}
			if !missing {
				desired[ips[0]] = &pool.Spec.Subnets[1]
				desired[ips[1]] = &pool.Spec.Subnets[0]
			}
			c.mockIPAssigner.EXPECT().InitIPs(desired)
			require.NoError(t, c.replaceEgressIPs())
			if missing {
				assert.Empty(t, c.egressIPGroups)
			} else {
				require.NoError(t, c.egressInformer.GetIndexer().Delete(egress))
				for _, ip := range ips {
					c.mockIPAssigner.EXPECT().UnassignIP(ip)
				}
				require.NoError(t, c.syncEgress(egress.Name))
				assert.Empty(t, c.egressIPGroups)
			}
		})
	}
}

func TestSyncEgressIPGroupLosesOneFamily(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed=%t", managed), func(t *testing.T) {
			ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"},
				Spec: crdv1b2.EgressSpec{EgressIPs: ips, Bandwidth: &fakeBandwidth}}
			objects := []runtime.Object{egress}
			if managed {
				egress.Spec.ExternalIPPool = fakeExternalIPPool
				objects = append(objects, &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}})
			}
			c := newIPGroupTestController(t, objects...)
			c.egressIPScheduler.schedule()
			c.addEgressGroup(&cpv1b2.EgressGroup{ObjectMeta: egress.ObjectMeta,
				GroupMembers: []cpv1b2.GroupMember{{Pod: &cpv1b2.PodReference{Namespace: "ns1", Name: "pod1"}}}})
			c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
			c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
			for _, ip := range ips {
				if managed {
					c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true).Return(false, nil)
				} else {
					c.mockIPAssigner.EXPECT().UnassignIP(ip).Times(2)
				}
			}
			c.mockOFClient.EXPECT().InstallSNATMarkFlows(gomock.Any(), uint32(1))
			c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), gomock.Any(), uint32(1))
			c.mockOFClient.EXPECT().InstallEgressQoS(uint32(1), uint32(500), uint32(500))
			require.NoError(t, c.syncEgress(egress.Name))

			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(fakeLocalEgressIP1)}
			expectedError := "must be assigned together"
			if managed {
				expectedError = "replacement failed"
				c.mockIPAssigner.EXPECT().AssignIP(ips[0], nil, true).Return(false, nil)
				c.mockIPAssigner.EXPECT().AssignIP(ips[1], nil, true).Return(false, fmt.Errorf("replacement failed"))
			}
			c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
			c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
			c.mockOFClient.EXPECT().UninstallEgressQoS(uint32(1))
			require.ErrorContains(t, c.syncEgress(egress.Name), expectedError)
			state, exists := c.getEgressState(egress.Name)
			require.True(t, exists)
			assert.Empty(t, state.ofPorts)
			assert.Nil(t, c.egressIPGroups[egressIPGroupKey(ips)].rateLimitMeter)
			_, err := c.GetEgressIPByMark(1, false)
			require.Error(t, err)
		})
	}
}

func TestReplaceEgressIPsSkipsConflictingGroup(t *testing.T) {
	pool := &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"},
		Spec:   crdv1b2.EgressSpec{EgressIPs: []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}, ExternalIPPool: fakeExternalIPPool},
		Status: crdv1b2.EgressStatus{EgressIPs: []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}, EgressNode: fakeNode}}
	c := newIPGroupTestController(t, egress, pool)
	// The existing reservation makes restoration of a partially overlapping group fail.
	require.NoError(t, c.referenceEgressIPs("other", []string{fakeLocalEgressIP1}))
	c.mockIPAssigner.EXPECT().InitIPs(map[string]*crdv1b2.SubnetInfo{})
	require.NoError(t, c.replaceEgressIPs(), "conflicts must not prevent stale address cleanup")
}

func TestEgressIPGroupPolicyRouteRollback(t *testing.T) {
	for _, failRoutes := range []bool{false, true} {
		t.Run(fmt.Sprintf("failRoutes=%t", failRoutes), func(t *testing.T) {
			c := newIPGroupTestController(t)
			ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			subnets := []*crdv1b2.SubnetInfo{{Gateway: fakeGatewayIP, PrefixLength: 16}, {Gateway: "2001:db8::1", PrefixLength: 64}}
			require.NoError(t, c.referenceEgressIPs("dual", ips))
			routeErr := fmt.Errorf("IPv6 policy route failed")
			c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
			c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
			for i, ip := range ips {
				table := uint32(101 + i)
				c.mockIPAssigner.EXPECT().AssignIP(ip, subnets[i], true).Return(false, nil)
				c.mockIPAssigner.EXPECT().GetInterfaceID(subnets[i]).Return(2, true)
				call := c.mockRouteClient.EXPECT().AddEgressRoutes(table, 2, net.ParseIP(subnets[i].Gateway), int(subnets[i].PrefixLength))
				if i == 1 && failRoutes {
					call.Return(routeErr)
				} else {
					call.Return(nil)
					ruleCall := c.mockRouteClient.EXPECT().AddEgressRule(table, uint32(1), i == 1)
					if i == 1 {
						ruleCall.Return(routeErr)
					}
				}
				c.mockRouteClient.EXPECT().DeleteEgressRule(table, uint32(1), i == 1)
				c.mockRouteClient.EXPECT().DeleteEgressRoutes(table)
			}
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"}}
			_, err := c.reconcileEgressIPGroup(egress, c.newEgressState(egress.Name, ips), subnets, fakeNode)
			require.ErrorIs(t, err, routeErr)
			assert.Empty(t, c.egressRouteTables)
			assert.Equal(t, uint32(0), c.egressIPGroups[egressIPGroupKey(ips)].mark)
			for _, table := range []uint32{101, 102} {
				id, err := c.tableAllocator.allocate()
				require.NoError(t, err)
				assert.Equal(t, table, id, "both route table IDs must be available after rollback")
			}
		})
	}
}

func TestSharedEgressIPGroupPolicyRouteRetry(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	subnets := []*crdv1b2.SubnetInfo{{Gateway: fakeGatewayIP, PrefixLength: 16}, {Gateway: "2001:db8::1", PrefixLength: 64}}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "first"}}
	for _, name := range []string{egress.Name, "second"} {
		require.NoError(t, c.referenceEgressIPs(name, ips))
	}
	state := c.newEgressState(egress.Name, ips)
	for i, ip := range ips {
		c.mockIPAssigner.EXPECT().AssignIP(ip, subnets[i], true).Times(3)
	}
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	for i, subnet := range subnets {
		c.mockIPAssigner.EXPECT().GetInterfaceID(subnet).Return(2, true)
		c.mockRouteClient.EXPECT().AddEgressRoutes(uint32(101+i), 2, net.ParseIP(subnet.Gateway), int(subnet.PrefixLength))
	}
	ruleErr := fmt.Errorf("IPv6 policy rule failed")
	gomock.InOrder(
		c.mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(1), false),
		c.mockRouteClient.EXPECT().AddEgressRule(uint32(102), uint32(1), true).Return(ruleErr),
	)
	_, err := c.reconcileEgressIPGroup(egress, state, subnets, fakeNode)
	require.ErrorIs(t, err, ruleErr)
	group := c.getEgressIPGroup(ips)
	assert.Equal(t, uint32(1), group.mark, "shared ownership must survive the failure")
	assert.False(t, group.flowsInstalled)
	require.NotNil(t, group.ips[1].subnetInfo, "retain partially configured state for cleanup")

	// Retry the missing rule before publishing mark flows. The IPv4 rule is already installed.
	c.mockIPAssigner.EXPECT().GetInterfaceID(subnets[1]).Return(2, true)
	gomock.InOrder(
		c.mockRouteClient.EXPECT().DeleteEgressRule(uint32(102), uint32(1), true),
		c.mockRouteClient.EXPECT().DeleteEgressRoutes(uint32(102)),
		c.mockRouteClient.EXPECT().AddEgressRoutes(uint32(102), 2, net.ParseIP(subnets[1].Gateway), int(subnets[1].PrefixLength)),
		c.mockRouteClient.EXPECT().AddEgressRule(uint32(102), uint32(1), true),
		c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(ips), uint32(1)),
	)
	mark, err := c.reconcileEgressIPGroup(egress, state, subnets, fakeNode)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
	assert.True(t, group.flowsInstalled)
	// Once installed, the same subnet must not cause more route or rule operations.
	_, err = c.reconcileEgressIPGroup(egress, state, subnets, fakeNode)
	require.NoError(t, err)
}

func TestEgressRouteTableRetryAcrossIPGroups(t *testing.T) {
	c := newIPGroupTestController(t)
	firstIPs, secondIPs := []string{fakeLocalEgressIP1}, []string{fakeLocalEgressIP2}
	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(firstIPs[0], secondIPs[0])}
	subnet := &crdv1b2.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16}
	subnets := []*crdv1b2.SubnetInfo{subnet}
	first := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "first"}}
	second := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "second"}}
	require.NoError(t, c.referenceEgressIPs(first.Name, firstIPs))
	c.mockIPAssigner.EXPECT().AssignIP(firstIPs[0], subnet, true)
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(firstIPs), uint32(1))
	c.mockIPAssigner.EXPECT().GetInterfaceID(subnet).Return(2, true)
	addErr, deleteErr := fmt.Errorf("route add failed"), fmt.Errorf("route rollback failed")
	gomock.InOrder(
		c.mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 2, net.ParseIP(subnet.Gateway), 16).Return(addErr),
		c.mockRouteClient.EXPECT().DeleteEgressRule(uint32(101), uint32(1), false),
		c.mockRouteClient.EXPECT().DeleteEgressRoutes(uint32(101)).Return(deleteErr),
	)
	_, err := c.reconcileEgressIPGroup(first, c.newEgressState(first.Name, firstIPs), subnets, fakeNode)
	require.ErrorIs(t, err, addErr)
	require.ErrorIs(t, err, deleteErr)

	require.NoError(t, c.referenceEgressIPs(second.Name, secondIPs))
	c.mockIPAssigner.EXPECT().AssignIP(secondIPs[0], subnet, true)
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(secondIPs), uint32(2))
	c.mockIPAssigner.EXPECT().GetInterfaceID(subnet).Return(2, true)
	gomock.InOrder(
		c.mockRouteClient.EXPECT().AddEgressRoutes(uint32(101), 2, net.ParseIP(subnet.Gateway), 16),
		c.mockRouteClient.EXPECT().AddEgressRule(uint32(101), uint32(2), false),
		c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(secondIPs), uint32(2)),
	)
	_, err = c.reconcileEgressIPGroup(second, c.newEgressState(second.Name, secondIPs), subnets, fakeNode)
	require.NoError(t, err)

	// The first group's cleanup must leave the recovered table in use by the second.
	c.mockRouteClient.EXPECT().DeleteEgressRule(uint32(101), uint32(1), false)
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
	c.mockIPAssigner.EXPECT().UnassignIP(firstIPs[0])
	require.NoError(t, c.unrealizeEgressIPs(first.Name, firstIPs, first))
	assert.Equal(t, sets.New(uint32(2)), c.egressRouteTables[*subnet].marks)
}

func TestPolicyRouteCleanupAfterTableRemovalByAnotherGroup(t *testing.T) {
	c := newIPGroupTestController(t)
	subnet := &crdv1b2.SubnetInfo{Gateway: fakeGatewayIP, PrefixLength: 16}
	gateway := net.ParseIP(subnet.Gateway)
	first, second := &egressIPState{}, &egressIPState{}
	const table, firstMark, secondMark uint32 = 101, 1, 2
	deleteErr := fmt.Errorf("route deletion failed")
	gomock.InOrder(
		c.mockIPAssigner.EXPECT().GetInterfaceID(subnet).Return(2, true),
		c.mockRouteClient.EXPECT().AddEgressRoutes(table, 2, gateway, 16),
		c.mockRouteClient.EXPECT().AddEgressRule(table, firstMark, false),
		c.mockRouteClient.EXPECT().DeleteEgressRule(table, firstMark, false),
		c.mockRouteClient.EXPECT().DeleteEgressRoutes(table).Return(deleteErr),
		c.mockIPAssigner.EXPECT().GetInterfaceID(subnet).Return(2, true),
		c.mockRouteClient.EXPECT().AddEgressRoutes(table, 2, gateway, 16),
		c.mockRouteClient.EXPECT().AddEgressRule(table, secondMark, false),
		c.mockRouteClient.EXPECT().DeleteEgressRule(table, secondMark, false),
		c.mockRouteClient.EXPECT().DeleteEgressRoutes(table),
	)
	require.NoError(t, c.installPolicyRoute(first, subnet, firstMark))
	require.ErrorIs(t, c.uninstallPolicyRoute(first, firstMark), deleteErr)
	require.NoError(t, c.installPolicyRoute(second, subnet, secondMark))
	require.NoError(t, c.uninstallPolicyRoute(second, secondMark))
	require.NoError(t, c.installPolicyRoute(first, nil, firstMark))
	assert.Nil(t, first.subnetInfo)
	assert.False(t, first.policyRouteInstalled)
}

func TestEgressIPGroupEquivalentIPv6(t *testing.T) {
	ips := []string{fakeLocalEgressIP1, "2001:0db8:0:0:0:0:0:10"}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "dual"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips}}
	c := newIPGroupTestController(t, egress)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIPv6)
	c.mockOFClient.EXPECT().InstallSNATMarkFlows([]net.IP{net.ParseIP(ips[0]), net.ParseIP(ips[1])}, uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	require.NoError(t, c.syncEgress(egress.Name))
	assert.Equal(t, uint32(1), c.egressIPGroups[egressIPGroupKey([]string{fakeLocalEgressIPv6, fakeLocalEgressIP1})].mark)
	stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, ips, stored.Status.EgressIPs)
	c.onLocalIPUpdate(fakeLocalEgressIPv6, false)
	assert.Equal(t, 1, c.queue.Len(), "canonical local-IP events must find non-canonical Egress spec addresses")
}

func TestAssignEgressIPGroupEvents(t *testing.T) {
	for _, tt := range []struct {
		name          string
		ips           []string
		local         bool
		failSecondIP  bool
		expectedEvent string
	}{
		{name: "single-stack", ips: []string{fakeLocalEgressIP1}, local: true,
			expectedEvent: "Normal IPAssigned Assigned Egress egress with IP " + fakeLocalEgressIP1 + " on Node " + fakeNode},
		{name: "dual-stack", ips: []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}, local: true,
			expectedEvent: "Normal IPAssigned Assigned Egress egress with IPs " + fakeLocalEgressIP1 + ", " + fakeLocalEgressIPv6 + " on Node " + fakeNode},
		{name: "IPv6-first unassignment", ips: []string{fakeLocalEgressIPv6, fakeLocalEgressIP1},
			expectedEvent: "Normal IPUnassigned Unassigned Egress egress with IPs " + fakeLocalEgressIPv6 + ", " + fakeLocalEgressIP1 + " from Node " + fakeNode},
		{name: "assignment rollback", ips: []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}, local: true, failSecondIP: true},
		{name: "partial unassignment", ips: []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}, failSecondIP: true,
			expectedEvent: "Normal IPUnassigned Unassigned Egress egress with IP " + fakeLocalEgressIP1 + " from Node " + fakeNode},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newIPGroupTestController(t)
			recorder := events.NewFakeRecorder(2)
			c.record = recorder
			require.NoError(t, c.referenceEgressIPs("egress", tt.ips))
			node := "other-node"
			if tt.local {
				node = fakeNode
			}
			for i, ip := range tt.ips {
				var err error
				if i == 1 && tt.failSecondIP {
					err = fmt.Errorf("assignment error")
				}
				if tt.local {
					c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true).Return(err == nil, err)
				} else {
					c.mockIPAssigner.EXPECT().UnassignIP(ip).Return(err == nil, err)
				}
			}
			if tt.local && tt.failSecondIP {
				c.mockIPAssigner.EXPECT().UnassignIP(tt.ips[0]).Return(true, nil)
			}
			err := c.assignEgressIPs(&crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "egress"}}, tt.ips, make([]*crdv1b2.SubnetInfo, len(tt.ips)), node)
			if tt.failSecondIP {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.expectedEvent != "" {
				require.Len(t, recorder.Events, 1)
				assert.Equal(t, tt.expectedEvent, <-recorder.Events)
			}
			assert.Empty(t, recorder.Events)
		})
	}
}

func TestSNATRulesPrecedeMarkFlows(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	require.NoError(t, c.referenceEgressIPs("egress", ips))
	gomock.InOrder(
		c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1)),
		c.mockOFClient.EXPECT().InstallSNATMarkFlows(gomock.Any(), uint32(1)),
	)
	_, err := c.realizeEgressIPs(ips, make([]*crdv1b2.SubnetInfo, len(ips)))
	require.NoError(t, err)
}

func TestFailedSNATRestoreRetainsMarkUntilCleanup(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "egress"}}
	require.NoError(t, c.referenceEgressIPs(egress.Name, ips))
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().UnassignIP(ip)
	}
	restoreErr, deleteErr := fmt.Errorf("restore failed"), fmt.Errorf("delete failed")
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1)).Return(restoreErr)
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1)).Return(deleteErr)
	_, err := c.reconcileEgressIPGroup(egress, c.newEgressState(egress.Name, ips), make([]*crdv1b2.SubnetInfo, len(ips)), "")
	require.ErrorIs(t, err, restoreErr)
	require.ErrorIs(t, err, deleteErr)
	group := c.egressIPGroups[egressIPGroupKey(ips)]
	assert.Equal(t, uint32(1), group.mark)
	assert.True(t, group.rulesPending)
	mark, err := c.markAllocator.allocate()
	require.NoError(t, err)
	assert.Equal(t, uint32(2), mark, "a failed deletion must not make the old mark reusable")
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1))
	require.NoError(t, c.uninstallEgressIPGroup(group))
	mark, err = c.markAllocator.allocate()
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
}

func TestSharedEgressFailurePreservesOtherReference(t *testing.T) {
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	first := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "first"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips}}
	second := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "second"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool}}
	pool := &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}}
	c := newIPGroupTestController(t, first, second, pool)
	c.egressIPScheduler.schedule()
	c.addEgressGroup(&cpv1b2.EgressGroup{ObjectMeta: first.ObjectMeta,
		GroupMembers: []cpv1b2.GroupMember{{Pod: &cpv1b2.PodReference{Namespace: "ns1", Name: "pod1"}}}})
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().UnassignIP(ip)
	}
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(gomock.Any(), uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), gomock.Any(), uint32(1))
	require.NoError(t, c.syncEgress(first.Name))
	c.mockIPAssigner.EXPECT().AssignIP(ips[0], nil, true).Return(false, nil)
	assignErr := fmt.Errorf("assignment failed")
	c.mockIPAssigner.EXPECT().AssignIP(ips[1], nil, true).Return(false, assignErr)
	require.ErrorIs(t, c.syncEgress(second.Name), assignErr)
	group := c.egressIPGroups[egressIPGroupKey(ips)]
	assert.Equal(t, uint32(1), group.mark)
	assert.True(t, group.flowsInstalled)
	state, exists := c.getEgressState(first.Name)
	require.True(t, exists)
	assert.True(t, state.ofPorts.Has(1))
	ip, err := c.GetEgressIPByMark(1, true)
	require.NoError(t, err)
	assert.Equal(t, fakeLocalEgressIPv6, ip)
}

func TestSharedEgressFailuresRespectRetryDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
		first := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "first"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips}}
		second := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "second"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips}}
		c := newIPGroupTestController(t, first, second)
		c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(ips[0])}
		names := []string{first.Name, second.Name}
		for _, name := range names {
			require.NoError(t, c.referenceEgressIPs(name, ips))
		}
		for _, ip := range ips {
			c.mockIPAssigner.EXPECT().UnassignIP(ip).Times(2)
		}
		for _, name := range names {
			c.queue.Add(name)
			require.True(t, c.processNextWorkItem())
			require.Zero(t, c.queue.Len(), "a failure must not enqueue the peer immediately")
			assert.Equal(t, 1, c.queue.NumRequeues(name))
		}
		synctest.Wait()
		time.Sleep(minRetryDelay)
		synctest.Wait()
		assert.Equal(t, len(names), c.queue.Len(), "both failed keys should retry after the delay")
	})
}

func TestManagedEgressWaitsForAddressDetection(t *testing.T) {
	for _, detected := range [][]string{nil, {fakeLocalEgressIP1}} {
		t.Run(fmt.Sprint(detected), func(t *testing.T) {
			ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "egress"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool}}
			c := newIPGroupTestController(t, egress, &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}})
			c.egressIPScheduler.schedule()
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(detected...)}
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true).Return(true, nil)
			}
			require.NoError(t, c.syncEgress(egress.Name), "address detection lag must not be reported as an assignment error")
			assert.Zero(t, c.egressIPGroups[egressIPGroupKey(ips)].mark)
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(ips...)}
			c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true).Return(false, nil)
			}
			c.mockOFClient.EXPECT().InstallSNATMarkFlows(gomock.Any(), uint32(1))
			require.NoError(t, c.syncEgress(egress.Name))
			stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), egress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, ips, stored.Status.EgressIPs)
		})
	}
}

func TestEgressIPGroupOverlapReportsCondition(t *testing.T) {
	pair := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	for _, dual := range []bool{false, true} {
		t.Run(fmt.Sprintf("dual=%t", dual), func(t *testing.T) {
			requested, existing := pair[:1], pair
			if dual {
				requested, existing = pair, pair[:1]
			}
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "overlap"}, Spec: crdv1b2.EgressSpec{EgressIPs: requested}}
			c := newIPGroupTestController(t, egress)
			require.NoError(t, c.referenceEgressIPs("existing", existing))
			require.ErrorContains(t, c.syncEgress(egress.Name), "already used by a different IP group")
			stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), egress.Name, metav1.GetOptions{})
			require.NoError(t, err)
			condition := meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAssigned)
			require.NotNil(t, condition)
			assert.Equal(t, metav1.ConditionFalse, condition.Status)
			assert.Equal(t, "AssignmentError", condition.Reason)
			assert.Contains(t, condition.Message, "already used by a different IP group")
		})
	}
}

func TestManagedEgressWaitsForAddressRemoval(t *testing.T) {
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	for _, detected := range [][]string{ips, ips[:1]} {
		t.Run(fmt.Sprint(detected), func(t *testing.T) {
			egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "egress"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool}}
			c := newIPGroupTestController(t, egress)
			require.NoError(t, c.referenceEgressIPs(egress.Name, ips))
			state := c.newEgressState(egress.Name, ips)
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(detected...)}
			for _, ip := range ips {
				c.mockIPAssigner.EXPECT().UnassignIP(ip).Times(2)
			}
			_, err := c.reconcileEgressIPGroup(egress, state, []*crdv1b2.SubnetInfo{nil, nil}, "other-node")
			require.ErrorIs(t, err, errEgressIPsPending)
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New[string]()}
			mark, err := c.reconcileEgressIPGroup(egress, state, []*crdv1b2.SubnetInfo{nil, nil}, "other-node")
			require.NoError(t, err)
			assert.Zero(t, mark)
		})
	}
}

func TestEgressIPGroupsDoNotBlockEachOther(t *testing.T) {
	for _, removing := range []bool{false, true} {
		t.Run(fmt.Sprintf("removing=%t", removing), func(t *testing.T) {
			c := newIPGroupTestController(t)
			first := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
			second := []string{fakeLocalEgressIP2, "2001:db8::20"}
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(append(slices.Clone(first), second...)...)}
			require.NoError(t, c.referenceEgressIPs("first", first))
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var workers sync.WaitGroup
			unblock := func() { once.Do(func() { close(release) }) }
			defer func() { unblock(); workers.Wait() }()
			blocked := func() error { close(entered); <-release; return nil }
			if removing {
				c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(first), uint32(1))
				c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(first), uint32(1))
				_, err := c.realizeEgressIPs(first, make([]*crdv1b2.SubnetInfo, 2))
				require.NoError(t, err)
				c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1)).DoAndReturn(func(uint32) error { return blocked() })
				c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
				for _, ip := range first {
					c.mockIPAssigner.EXPECT().UnassignIP(ip)
				}
			} else {
				c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(first), uint32(1)).DoAndReturn(func([]net.IP, uint32) error { return blocked() })
				c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(first), uint32(1))
			}
			firstResult := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				if removing {
					firstResult <- c.unrealizeEgressIPs("first", first, nil)
				} else {
					_, err := c.realizeEgressIPs(first, make([]*crdv1b2.SubnetInfo, 2))
					firstResult <- err
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("SNAT operation did not start")
			}
			lookup := make(chan string, 1)
			workers.Add(1)
			go func() { defer workers.Done(); ip, _ := c.GetEgressIPByMark(1, true); lookup <- ip }()
			select {
			case ip := <-lookup:
				assert.Equal(t, first[1], ip)
			case <-time.After(time.Second):
				t.Fatal("Traceflow lookup blocked on SNAT restore")
			}
			c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(second), uint32(2))
			c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(second), uint32(2))
			secondResult := make(chan error, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				if err := c.referenceEgressIPs("second", second); err != nil {
					secondResult <- err
					return
				}
				_, err := c.realizeEgressIPs(second, make([]*crdv1b2.SubnetInfo, 2))
				secondResult <- err
			}()
			select {
			case err := <-secondResult:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("another group blocked on SNAT restore")
			}
			unblock()
			require.NoError(t, <-firstResult)
		})
	}
}

func TestPersistentAddressDetectionMismatch(t *testing.T) {
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	egress := &crdv1b2.Egress{ObjectMeta: metav1.ObjectMeta{Name: "egress"}, Spec: crdv1b2.EgressSpec{EgressIPs: ips, ExternalIPPool: fakeExternalIPPool}}
	c := newIPGroupTestController(t, egress, &crdv1b2.ExternalIPPool{ObjectMeta: metav1.ObjectMeta{Name: fakeExternalIPPool}})
	c.egressIPScheduler.schedule()
	// The Pool selected this Node, but the cluster-wide failure reporter is another Node.
	c.cluster = newFakeMemberlistCluster([]string{fakeNode2})
	c.addEgressGroup(&cpv1b2.EgressGroup{ObjectMeta: egress.ObjectMeta,
		GroupMembers: []cpv1b2.GroupMember{{Pod: &cpv1b2.PodReference{Namespace: "ns1", Name: "pod1"}}}})
	parsedIPs := parseEgressTestIPs(ips)
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true)
		c.mockIPAssigner.EXPECT().AssignIP(ip, nil, false).Times(2)
	}
	c.mockRouteClient.EXPECT().AddSNATRules(parsedIPs, uint32(1))
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(parsedIPs, uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), parsedIPs, uint32(1))
	require.NoError(t, c.syncEgress(egress.Name))
	stored, err := c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, c.egressInformer.GetIndexer().Update(stored))

	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(ips[0])}
	require.NoError(t, c.syncEgress(egress.Name), "allow a brief address notification delay")
	state, _ := c.getEgressState(egress.Name)
	require.True(t, state.ofPorts.Has(1))
	group := c.getEgressIPGroup(ips)
	assert.True(t, group.flowsInstalled)
	state.ipDetectionStartTime = time.Now().Add(-egressIPDetectionGracePeriod)
	gomock.InOrder(
		c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1)),
		c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1)),
		c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1)),
	)
	require.ErrorIs(t, c.syncEgress(egress.Name), errEgressIPDetectionTimeout)
	assert.Empty(t, state.ofPorts)
	assert.Zero(t, group.mark)
	assert.False(t, group.flowsInstalled)
	stored, err = c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Empty(t, stored.Status.EgressIPs)
	condition := meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAssigned)
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "AssignmentError", condition.Reason)
	require.NoError(t, c.egressInformer.GetIndexer().Update(stored))
	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(ips...)}
	for _, ip := range ips {
		c.mockIPAssigner.EXPECT().AssignIP(ip, nil, true)
	}
	c.mockRouteClient.EXPECT().AddSNATRules(parsedIPs, uint32(1))
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(parsedIPs, uint32(1))
	c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), parsedIPs, uint32(1))
	require.NoError(t, c.syncEgress(egress.Name))
	assert.True(t, state.ipDetectionStartTime.IsZero())
	stored, err = c.crdClient.CrdV1beta2().Egresses().Get(context.Background(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, metav1.ConditionTrue, meta.FindStatusCondition(stored.Status.Conditions, crdv1b2.IPAssigned).Status)
}

func TestStaleEgressIPGroupCleanupPreservesReplacement(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1}
	key := egressIPGroupKey(ips)
	require.NoError(t, c.referenceEgressIPs("old", ips))
	old := c.getEgressIPGroup(ips)
	c.mockIPAssigner.EXPECT().UnassignIP(ips[0])
	require.NoError(t, c.unrealizeEgressIPs("old", ips, nil))
	require.NoError(t, c.referenceEgressIPs("replacement", ips))
	replacement := c.getEgressIPGroup(ips)
	require.NotSame(t, old, replacement)

	// Resume a cleanup worker that captured the old group before waiting on its mutex.
	require.NoError(t, c.cleanupUnreferencedEgressIPGroup(key, old, ips, nil))
	assert.Same(t, replacement, c.getEgressIPGroup(ips))
	assert.Equal(t, []string{"replacement"}, c.egressIPGroupNames(replacement))
}

func TestNewReferenceRestoresRulesAfterFailedCleanup(t *testing.T) {
	c := newIPGroupTestController(t)
	ips := []string{fakeLocalEgressIP1, fakeLocalEgressIPv6}
	require.NoError(t, c.referenceEgressIPs("first", ips))
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(parseEgressTestIPs(ips), uint32(1))
	_, err := c.realizeEgressIPs(ips, make([]*crdv1b2.SubnetInfo, 2))
	require.NoError(t, err)
	c.mockRouteClient.EXPECT().DeleteSNATRules(uint32(1)).Return(fmt.Errorf("restore failed"))
	require.Error(t, c.unrealizeEgressIPs("first", ips, nil))
	require.NoError(t, c.referenceEgressIPs("second", ips))
	c.mockRouteClient.EXPECT().AddSNATRules(parseEgressTestIPs(ips), uint32(1))
	mark, err := c.realizeEgressIPs(ips, make([]*crdv1b2.SubnetInfo, 2))
	require.NoError(t, err)
	assert.Equal(t, uint32(1), mark)
}

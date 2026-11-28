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
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	crdv1b2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
)

var (
	errEgressIPsPending         = errors.New("waiting for local Egress IP detection")
	errEgressIPDetectionTimeout = errors.New("local Egress IP detection timed out")
)

// egressIPGroupState owns the resources shared by all Egresses with the same IPs.
// A group uses one mark across IP families and one OpenFlow transaction for its mark flows.
// Group rule state and per-IP route state are retained so cleanup can resume after a failure.
type egressIPGroupState struct {
	// mutex serializes this group's I/O without blocking other groups or Traceflow.
	mutex sync.Mutex
	// egressNames uses the registry lock. Mark writes hold both locks for non-blocking lookups.
	// The address values are immutable; subnet and datapath state use this group's mutex.
	rulesConfigured bool
	rulesPending    bool
	ips             []*egressIPState
	egressNames     sets.Set[string]
	mark            uint32
	flowsInstalled  bool
	rateLimitMeter  *rateLimitMeter
}

func egressIPGroupKey(ips []string) string {
	canonicalIPs := make([]string, len(ips))
	for i, ip := range ips {
		canonicalIPs[i] = net.ParseIP(ip).String()
	}
	slices.Sort(canonicalIPs)
	return strings.Join(canonicalIPs, ",")
}

// referenceEgressIPs reserves a whole group under the same lock as mark allocation.
// Admission uses an eventually consistent cache, so it cannot prevent concurrent partially
// overlapping groups from reaching the Agent. Such groups would install conflicting tunnel flows.
func (c *EgressController) referenceEgressIPs(egressName string, ips []string) error {
	c.egressIPGroupsMutex.Lock()
	defer c.egressIPGroupsMutex.Unlock()

	key := egressIPGroupKey(ips)
	if group, exists := c.egressIPGroups[key]; exists {
		group.egressNames.Insert(egressName)
		return nil
	}
	parsedIPs := make([]*egressIPState, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("error reserving Egress IP %s: invalid IP address", ip)
		}
		for _, group := range c.egressIPGroups {
			for _, existing := range group.ips {
				if parsed.Equal(existing.egressIP) {
					return fmt.Errorf("error reserving Egress IP %s: already used by a different IP group", ip)
				}
			}
		}
		parsedIPs = append(parsedIPs, &egressIPState{egressIP: parsed})
	}
	c.egressIPGroups[key] = &egressIPGroupState{ips: parsedIPs, egressNames: sets.New(egressName)}
	return nil
}

// getEgressIPGroup returns a reserved group. Callers hold a reference until their sync finishes.
func (c *EgressController) getEgressIPGroup(ips []string) *egressIPGroupState {
	c.egressIPGroupsMutex.RLock()
	defer c.egressIPGroupsMutex.RUnlock()
	return c.egressIPGroups[egressIPGroupKey(ips)]
}

func (c *EgressController) egressIPGroupNames(group *egressIPGroupState) []string {
	c.egressIPGroupsMutex.RLock()
	defer c.egressIPGroupsMutex.RUnlock()
	return sets.List(group.egressNames)
}

func (c *EgressController) egressSubnetInfos(egress *crdv1b2.Egress, ips []string, enabled bool) ([]*crdv1b2.SubnetInfo, error) {
	subnets := make([]*crdv1b2.SubnetInfo, len(ips))
	if !enabled || egress.Spec.ExternalIPPool == "" {
		return subnets, nil
	}
	pool, err := c.externalIPPoolLister.Get(egress.Spec.ExternalIPPool)
	if err != nil {
		return nil, err
	}
	for i, ip := range ips {
		subnets[i], err = subnetInfoForIP(pool.Spec.Subnets, ip)
		if err != nil {
			return nil, err
		}
	}
	return subnets, nil
}

// assignEgressIPs rolls back newly assigned addresses when a later assignment fails.
// The Egress state already records the complete group so a failed rollback is retried on cleanup.
func (c *EgressController) assignEgressIPs(egress *crdv1b2.Egress, ips []string, subnets []*crdv1b2.SubnetInfo, node string) error {
	group := c.getEgressIPGroup(ips)
	group.mutex.Lock()
	defer group.mutex.Unlock()
	var assignedIPs []string
	var unassignedIPs []string
	defer func() { c.recordIPAssignmentEvent(egress, unassignedIPs, false) }()
	for i, value := range ips {
		ip := net.ParseIP(value).String()
		if node == c.nodeName {
			assigned, err := c.ipAssigner.AssignIP(ip, subnets[i], egress.Status.EgressNode != c.nodeName)
			if err != nil {
				for _, assignedIP := range assignedIPs {
					if _, rollbackErr := c.ipAssigner.UnassignIP(assignedIP); rollbackErr != nil {
						err = errors.Join(err, fmt.Errorf("error rolling back assignment of IP %s: %w", assignedIP, rollbackErr))
					}
				}
				return err
			}
			if assigned {
				assignedIPs = append(assignedIPs, ip)
			}
		} else {
			unassigned, err := c.ipAssigner.UnassignIP(ip)
			if err != nil {
				return err
			}
			if unassigned {
				unassignedIPs = append(unassignedIPs, ip)
			}
		}
	}
	c.recordIPAssignmentEvent(egress, assignedIPs, true)
	return nil
}

// recordIPAssignmentEvent emits one event for the changed addresses: the broadcaster aggregates
// events with the same object, reason and action even when their notes contain different IPs.
func (c *EgressController) recordIPAssignmentEvent(egress *crdv1b2.Egress, ips []string, assigned bool) {
	if egress == nil || len(ips) == 0 {
		return
	}
	reason, verb, preposition := "IPAssigned", "Assigned", "on"
	if !assigned {
		reason, verb, preposition = "IPUnassigned", "Unassigned", "from"
	}
	ipLabel := "IP"
	if len(ips) > 1 {
		ipLabel = "IPs"
	}
	c.record.Eventf(egress, nil, corev1.EventTypeNormal, reason, "NodeAssignment", "%s Egress %s with %s %s %s Node %s", verb, egress.Name, ipLabel, strings.Join(ips, ", "), preposition, c.nodeName)
}

// reconcileEgressIPGroup removes stale Pod flows on failure and rolls back the group if it has
// no other references. Retain the reservation and unfinished cleanup state for the next retry.
func (c *EgressController) reconcileEgressIPGroup(egress *crdv1b2.Egress, state *egressState, subnets []*crdv1b2.SubnetInfo, node string) (mark uint32, err error) {
	defer func() {
		if err == nil || errors.Is(err, errEgressIPsPending) {
			return
		}
		if cleanupErr := c.uninstallPodFlows(egress.Name, state, state.ofPorts, state.pods); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("error removing stale Pod flows: %w", cleanupErr))
			return
		}
		group := c.getEgressIPGroup(state.egressIPs)
		group.mutex.Lock()
		defer group.mutex.Unlock()
		c.egressIPGroupsMutex.RLock()
		shared := group.egressNames.Len() > 1
		c.egressIPGroupsMutex.RUnlock()
		if shared {
			// Preserve the shared datapath. The worker retries the failed Egress with backoff.
			return
		}
		if cleanupErr := c.uninstallEgressIPGroup(group); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("error rolling back Egress IP datapath: %w", cleanupErr))
		}
	}()
	if err := c.assignEgressIPs(egress, state.egressIPs, subnets, node); err != nil {
		return 0, err
	}
	if node != "" {
		for _, ip := range state.egressIPs {
			if c.localIPDetector.IsLocalIP(net.ParseIP(ip).String()) != (node == c.nodeName) {
				if state.ipDetectionStartTime.IsZero() {
					state.ipDetectionStartTime = time.Now()
				}
				if time.Since(state.ipDetectionStartTime) < egressIPDetectionGracePeriod {
					return 0, errEgressIPsPending
				}
				return 0, fmt.Errorf("error detecting Egress IPs %v for scheduled Node %s: %w",
					state.egressIPs, node, errEgressIPDetectionTimeout)
			}
		}
	}
	return c.realizeEgressIPs(state.egressIPs, subnets)
}

func (c *EgressController) realizeEgressIPs(ips []string, subnets []*crdv1b2.SubnetInfo) (uint32, error) {
	group := c.getEgressIPGroup(ips)
	group.mutex.Lock()
	defer group.mutex.Unlock()

	localCount := 0
	for _, ip := range group.ips {
		if c.localIPDetector.IsLocalIP(ip.egressIP.String()) {
			localCount++
		}
	}
	if localCount > 0 && localCount != len(ips) {
		return 0, fmt.Errorf("error realizing Egress IPs %v: they must be assigned together to the same Node", ips)
	}
	if localCount == 0 {
		if err := c.uninstallEgressIPGroup(group); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if group.mark == 0 {
		mark, err := c.markAllocator.allocate()
		if err != nil {
			return 0, fmt.Errorf("error allocating mark for Egress IPs %v: %w", ips, err)
		}
		c.egressIPGroupsMutex.Lock()
		group.mark = mark
		c.egressIPGroupsMutex.Unlock()
	}
	parsedIPs := make([]net.IP, 0, len(group.ips))
	for _, ip := range group.ips {
		parsedIPs = append(parsedIPs, ip.egressIP)
	}
	if !group.rulesConfigured {
		// A failed restore may have applied one family. Retain ownership until batch cleanup succeeds.
		group.rulesPending = true
		if err := c.routeClient.AddSNATRules(parsedIPs, group.mark); err != nil {
			return 0, fmt.Errorf("error installing SNAT rules for IPs %v: %w", ips, err)
		}
		group.rulesConfigured = true
		group.rulesPending = false
	}

	for i, ip := range ips {
		// The group may have been created by an Egress with the opposite IP order.
		for _, ipState := range group.ips {
			if !ipState.egressIP.Equal(net.ParseIP(ip)) {
				continue
			}
			if err := c.installPolicyRoute(ipState, subnets[i], group.mark); err != nil {
				return 0, fmt.Errorf("error installing policy route for IP %s: %w", ip, err)
			}
		}
	}
	if !group.flowsInstalled {
		if err := c.ofClient.InstallSNATMarkFlows(parsedIPs, group.mark); err != nil {
			return 0, fmt.Errorf("error installing SNAT mark flows for IPs %v: %w", ips, err)
		}
		group.flowsInstalled = true
	}
	return group.mark, nil
}

// uninstallEgressIPGroup retains unfinished work until all rules and flows have been removed.
// Callers hold group.mutex. Keep the mark reserved until cleanup succeeds.
func (c *EgressController) uninstallEgressIPGroup(group *egressIPGroupState) error {
	for _, ip := range group.ips {
		if err := c.uninstallPolicyRoute(ip, group.mark); err != nil {
			return err
		}
	}
	if group.rulesConfigured || group.rulesPending {
		// Delete also removes the desired rules. A new reference must restore them if cleanup fails.
		group.rulesConfigured = false
		group.rulesPending = true
		if err := c.routeClient.DeleteSNATRules(group.mark); err != nil {
			return err
		}
		group.rulesPending = false
	}

	if group.flowsInstalled {
		if err := c.ofClient.UninstallSNATMarkFlows(group.mark); err != nil {
			return err
		}
		group.flowsInstalled = false
	}
	if group.rateLimitMeter != nil {
		if err := c.ofClient.UninstallEgressQoS(group.rateLimitMeter.MeterID); err != nil {
			return err
		}
		group.rateLimitMeter = nil
	}
	if group.mark != 0 {
		c.egressIPGroupsMutex.Lock()
		err := c.markAllocator.release(group.mark)
		if err == nil {
			group.mark = 0
		}
		c.egressIPGroupsMutex.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *EgressController) unrealizeEgressIPs(egressName string, ips []string, egress *crdv1b2.Egress) error {
	key := egressIPGroupKey(ips)
	c.egressIPGroupsMutex.Lock()
	group, exists := c.egressIPGroups[key]
	if !exists {
		c.egressIPGroupsMutex.Unlock()
		return nil
	}
	group.egressNames.Delete(egressName)
	names := sets.List(group.egressNames)
	c.egressIPGroupsMutex.Unlock()
	if len(names) > 0 {
		// Reconcile bandwidth after removing a reference that may have supplied it.
		for _, name := range names {
			c.queue.Add(name)
		}
		return nil
	}
	return c.cleanupUnreferencedEgressIPGroup(key, group, ips, egress)
}

func (c *EgressController) cleanupUnreferencedEgressIPGroup(key string, group *egressIPGroupState, ips []string, egress *crdv1b2.Egress) error {
	group.mutex.Lock()
	defer group.mutex.Unlock()
	// A reference may have been added, or the group may have been replaced while we waited.
	c.egressIPGroupsMutex.RLock()
	canCleanup := c.egressIPGroups[key] == group && group.egressNames.Len() == 0
	c.egressIPGroupsMutex.RUnlock()
	if !canCleanup {
		return nil
	}
	if err := c.uninstallEgressIPGroup(group); err != nil {
		return err
	}
	// A new reference can reserve the group now, but it must take this mutex before assigning IPs.
	var unassignedIPs []string
	defer func() { c.recordIPAssignmentEvent(egress, unassignedIPs, false) }()
	for _, value := range ips {
		ip := net.ParseIP(value).String()
		unassigned, err := c.ipAssigner.UnassignIP(ip)
		if err != nil {
			return err
		}
		if unassigned {
			unassignedIPs = append(unassignedIPs, ip)
		}
	}
	c.egressIPGroupsMutex.Lock()
	if c.egressIPGroups[key] == group && group.egressNames.Len() == 0 {
		delete(c.egressIPGroups, key)
	}
	c.egressIPGroupsMutex.Unlock()
	return nil
}

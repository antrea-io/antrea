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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	crdv1b2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
)

var errEgressIPsPending = errors.New("waiting for local Egress IP detection")

// egressIPGroupState owns the resources shared by all Egresses with the same IPs.
// A group uses one mark across IP families and one OpenFlow transaction for its mark flows.
// Per-IP rule and route state is retained so cleanup can resume after a failure.
type egressIPGroupState struct {
	ips            []*egressIPState
	egressNames    sets.Set[string]
	mark           uint32
	flowsInstalled bool
	rateLimitMeter *rateLimitMeter
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
			return fmt.Errorf("invalid Egress IP %s", ip)
		}
		for _, group := range c.egressIPGroups {
			for _, existing := range group.ips {
				if parsed.Equal(existing.egressIP) {
					return fmt.Errorf("Egress IP %s is already used by a different IP group", ip)
				}
			}
		}
		parsedIPs = append(parsedIPs, &egressIPState{egressIP: parsed})
	}
	c.egressIPGroups[key] = &egressIPGroupState{ips: parsedIPs, egressNames: sets.New(egressName)}
	return nil
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
	c.egressIPGroupsMutex.Lock()
	defer c.egressIPGroupsMutex.Unlock()
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
						err = errors.Join(err, fmt.Errorf("rolling back assignment of IP %s: %w", assignedIP, rollbackErr))
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

// reconcileEgressIPGroup removes the old Pod flows and group resources on an assignment or
// realization failure. Retain the reservation and unfinished cleanup state for the next retry.
func (c *EgressController) reconcileEgressIPGroup(egress *crdv1b2.Egress, state *egressState, subnets []*crdv1b2.SubnetInfo, node string) (mark uint32, err error) {
	defer func() {
		if err == nil || errors.Is(err, errEgressIPsPending) {
			return
		}
		if cleanupErr := c.uninstallPodFlows(egress.Name, state, state.ofPorts, state.pods); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("removing stale Pod flows: %w", cleanupErr))
			return
		}
		c.egressIPGroupsMutex.Lock()
		defer c.egressIPGroupsMutex.Unlock()
		group := c.egressIPGroups[egressIPGroupKey(state.egressIPs)]
		if group.egressNames.Len() > 1 {
			// Another Egress may still have Pod flows using this mark. Keep its
			// datapath and reservation intact and let each reference reconcile itself.
			for name := range group.egressNames {
				if name != egress.Name {
					c.queue.Add(name)
				}
			}
			return
		}
		if cleanupErr := c.uninstallEgressIPGroup(group); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("rolling back Egress IP datapath: %w", cleanupErr))
		}
	}()
	if err := c.assignEgressIPs(egress, state.egressIPs, subnets, node); err != nil {
		return 0, err
	}
	if node != "" {
		for _, ip := range state.egressIPs {
			if c.localIPDetector.IsLocalIP(net.ParseIP(ip).String()) != (node == c.nodeName) {
				return 0, errEgressIPsPending
			}
		}
	}
	return c.realizeEgressIPs(state.egressIPs, subnets)
}

func (c *EgressController) realizeEgressIPs(ips []string, subnets []*crdv1b2.SubnetInfo) (uint32, error) {
	c.egressIPGroupsMutex.Lock()
	defer c.egressIPGroupsMutex.Unlock()

	group := c.egressIPGroups[egressIPGroupKey(ips)]
	localCount := 0
	for _, ip := range group.ips {
		if c.localIPDetector.IsLocalIP(ip.egressIP.String()) {
			localCount++
		}
	}
	if localCount > 0 && localCount != len(ips) {
		return 0, fmt.Errorf("Egress IPs %v must be assigned together to the same Node", ips)
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
			return 0, fmt.Errorf("allocating mark for Egress IPs %v: %w", ips, err)
		}
		group.mark = mark
	}

	for i, ip := range ips {
		// The group may have been created by an Egress with the opposite IP order.
		for _, ipState := range group.ips {
			if !ipState.egressIP.Equal(net.ParseIP(ip)) {
				continue
			}
			if !ipState.ruleConfigured {
				// A failed restore can have applied one family already. Record ownership
				// before writing so rollback waits for removal before releasing the mark.
				ipState.rulePending = true
				if err := c.routeClient.AddSNATRule(ipState.egressIP, group.mark); err != nil {
					return 0, fmt.Errorf("installing SNAT rule for IP %s: %w", ip, err)
				}
				ipState.ruleConfigured = true
				ipState.rulePending = false
			}
			if err := c.installPolicyRoute(ipState, subnets[i], group.mark); err != nil {
				return 0, fmt.Errorf("installing policy route for IP %s: %w", ip, err)
			}
		}
	}
	if !group.flowsInstalled {
		parsedIPs := make([]net.IP, 0, len(group.ips))
		for _, ip := range group.ips {
			parsedIPs = append(parsedIPs, ip.egressIP)
		}
		if err := c.ofClient.InstallSNATMarkFlows(parsedIPs, group.mark); err != nil {
			return 0, fmt.Errorf("installing SNAT mark flows for IPs %v: %w", ips, err)
		}
		group.flowsInstalled = true
	}
	return group.mark, nil
}

// uninstallEgressIPGroup retains unfinished work until all rules and flows have been removed.
// Callers hold egressIPGroupsMutex so the mark cannot be reused before cleanup succeeds.
func (c *EgressController) uninstallEgressIPGroup(group *egressIPGroupState) error {
	for _, ip := range group.ips {
		if err := c.uninstallPolicyRoute(ip, group.mark); err != nil {
			return err
		}
		if ip.ruleConfigured || ip.rulePending {
			if err := c.routeClient.DeleteSNATRule(group.mark, ip.egressIP.To4() == nil); err != nil {
				return err
			}
			ip.ruleConfigured = false
			ip.rulePending = false
		}
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
		if err := c.markAllocator.release(group.mark); err != nil {
			return err
		}
		group.mark = 0
	}
	return nil
}

func (c *EgressController) unrealizeEgressIPs(egressName string, ips []string, egress *crdv1b2.Egress) error {
	c.egressIPGroupsMutex.Lock()
	defer c.egressIPGroupsMutex.Unlock()

	key := egressIPGroupKey(ips)
	group, exists := c.egressIPGroups[key]
	if !exists {
		return nil
	}
	group.egressNames.Delete(egressName)
	if group.egressNames.Len() > 0 {
		// A removed reference may have supplied the group's bandwidth. Reconcile the
		// remaining references so their configured bandwidth determines the shared meter.
		for name := range group.egressNames {
			c.queue.Add(name)
		}
		return nil
	}
	if err := c.uninstallEgressIPGroup(group); err != nil {
		return err
	}
	// Keep the group reserved until unassignment succeeds. Another worker must not assign
	// an identical group between deleting its reservation and removing its addresses.
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
	delete(c.egressIPGroups, key)
	return nil
}

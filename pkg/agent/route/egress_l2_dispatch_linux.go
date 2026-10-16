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

package route

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util/ipset"
	"antrea.io/antrea/v2/pkg/agent/util/iptables"
)

// With the Egress l2 dispatch, the Node of a Pod sends the Egress traffic of the Pod unchanged to the MAC address of
// the Egress Node. The Egress Node cannot read the Egress IP from a tunnel destination, so it finds the Egress IP from
// the source Pod IP: an ipset for each local Egress IP holds the IPs of the Pods on other Nodes which use the Egress
// IP, and a mangle rule gives their packets the mark of the Egress IP. The SNAT rule and the policy routing of the
// Egress IP then apply to them, like to the packets that the OVS pipeline marks for local Pods.

const (
	// egressRemotePodIPSetPrefix is the prefix of the ipsets of the local Egress IPs. The mark of the Egress IP follows
	// the prefix, after "6" for IPv6, e.g. ANTREA-EGRESS-POD-IP-3 or ANTREA-EGRESS-POD-IP6-4.
	egressRemotePodIPSetPrefix = "ANTREA-EGRESS-POD-IP"
)

// egressRemotePodIPSet is the ipset of a local Egress IP. It holds the IPs of the Pods on other Nodes which use the
// Egress IP.
type egressRemotePodIPSet struct {
	isIPv6 bool
	podIPs sets.Set[string]
}

func egressRemotePodIPSetName(mark uint32, isIPv6 bool) string {
	if isIPv6 {
		return fmt.Sprintf("%s6-%d", egressRemotePodIPSetPrefix, mark)
	}
	return fmt.Sprintf("%s-%d", egressRemotePodIPSetPrefix, mark)
}

func isEgressRemotePodIPSetName(name string) bool {
	return strings.HasPrefix(name, egressRemotePodIPSetPrefix+"-") ||
		strings.HasPrefix(name, egressRemotePodIPSetPrefix+"6-")
}

// egressRemotePodMarkRuleSpec returns the mangle rule which gives the packets of the Pods on other Nodes which use the
// local Egress IP with the mark, and which arrive from the transport interface, the mark of the Egress IP. The rule
// ignores the packets to Pods, so that they are not routed with the policy routing of the Egress IP. It also ignores
// the packets to the IPs of this Node, for example to a NodePort, so that they are not SNATed with the Egress IP after
// a DNAT. The comment is quoted for iptables-restore.
func (c *Client) egressRemotePodMarkRuleSpec(mark uint32, isIPv6 bool, forRestore bool) []string {
	comment := "Antrea: mark Egress packets from remote Pods"
	if forRestore {
		comment = `"` + comment + `"`
	}
	podIPSet := antreaPodIPSet
	if isIPv6 {
		podIPSet = antreaPodIP6Set
	}
	return []string{
		"-m", "comment", "--comment", comment,
		"-i", c.nodeConfig.NodeTransportInterfaceName,
		"-m", "set", "--match-set", egressRemotePodIPSetName(mark, isIPv6), "src",
		"-m", "set", "!", "--match-set", podIPSet, "dst",
		"-m", "addrtype", "!", "--dst-type", "LOCAL",
		"-j", iptables.MarkTarget, "--set-xmark", fmt.Sprintf("%#08x/%#08x", mark, types.SNATIPMarkMask),
	}
}

// addEgressRemotePodIPSet creates the ipset of the local Egress IP with the mark, and the mangle rule which uses it.
func (c *Client) addEgressRemotePodIPSet(mark uint32, isIPv6 bool) error {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	if _, exists := c.egressRemotePodIPSets[mark]; exists {
		return nil
	}
	name := egressRemotePodIPSetName(mark, isIPv6)
	if err := c.ipset.CreateIPSet(name, ipset.HashIP, isIPv6); err != nil {
		return err
	}
	// A previous agent may have left the ipset, with the Pods of another Egress IP which had the same mark.
	entries, err := c.ipset.ListEntries(name)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := c.ipset.DelEntry(name, entry); err != nil {
			return err
		}
	}
	protocol := iptables.ProtocolIPv4
	if isIPv6 {
		protocol = iptables.ProtocolIPv6
	}
	ruleSpec := c.egressRemotePodMarkRuleSpec(mark, isIPv6, false)
	if err := c.iptables.InsertRule(protocol, iptables.MangleTable, antreaPreRoutingChain, ruleSpec); err != nil {
		return err
	}
	if c.egressRemotePodIPSets == nil {
		c.egressRemotePodIPSets = map[uint32]*egressRemotePodIPSet{}
	}
	c.egressRemotePodIPSets[mark] = &egressRemotePodIPSet{isIPv6: isIPv6, podIPs: sets.New[string]()}
	c.staleEgressRemotePodIPSets.Delete(name)
	return nil
}

// deleteEgressRemotePodIPSet deletes the mangle rule and the ipset of the local Egress IP with the mark. If the ipset
// cannot be destroyed yet, for example because an iptables sync added the rule again, the periodic sync destroys it.
func (c *Client) deleteEgressRemotePodIPSet(mark uint32) error {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	set, exists := c.egressRemotePodIPSets[mark]
	if !exists {
		return nil
	}
	protocol := iptables.ProtocolIPv4
	if set.isIPv6 {
		protocol = iptables.ProtocolIPv6
	}
	ruleSpec := c.egressRemotePodMarkRuleSpec(mark, set.isIPv6, false)
	if err := c.iptables.DeleteRule(protocol, iptables.MangleTable, antreaPreRoutingChain, ruleSpec); err != nil {
		return err
	}
	delete(c.egressRemotePodIPSets, mark)
	name := egressRemotePodIPSetName(mark, set.isIPv6)
	if err := c.ipset.DestroyIPSet(name); err != nil {
		klog.ErrorS(err, "Failed to destroy the ipset of an Egress IP, will retry", "ipset", name)
		c.addStaleEgressRemotePodIPSet(name)
	}
	return nil
}

// addStaleEgressRemotePodIPSet records an ipset to destroy. The caller holds egressRemotePodIPSetsMutex.
func (c *Client) addStaleEgressRemotePodIPSet(name string) {
	if c.staleEgressRemotePodIPSets == nil {
		c.staleEgressRemotePodIPSets = sets.New[string]()
	}
	c.staleEgressRemotePodIPSets.Insert(name)
}

func (c *Client) SetEgressRemotePodIPs(mark uint32, podIPs sets.Set[string]) error {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	set, exists := c.egressRemotePodIPSets[mark]
	if !exists {
		return fmt.Errorf("the Egress IP with mark %#x has no ipset for remote Pods", mark)
	}
	name := egressRemotePodIPSetName(mark, set.isIPv6)
	for podIP := range podIPs.Difference(set.podIPs) {
		if err := c.ipset.AddEntry(name, podIP); err != nil {
			return err
		}
		set.podIPs.Insert(podIP)
	}
	for podIP := range set.podIPs.Difference(podIPs) {
		if err := c.ipset.DelEntry(name, podIP); err != nil {
			return err
		}
		set.podIPs.Delete(podIP)
	}
	return nil
}

// syncEgressRemotePodIPSets restores the ipsets of the local Egress IPs and their entries.
func (c *Client) syncEgressRemotePodIPSets() error {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	for mark, set := range c.egressRemotePodIPSets {
		name := egressRemotePodIPSetName(mark, set.isIPv6)
		if err := c.ipset.CreateIPSet(name, ipset.HashIP, set.isIPv6); err != nil {
			return err
		}
		for podIP := range set.podIPs {
			if err := c.ipset.AddEntry(name, podIP); err != nil {
				return err
			}
		}
	}
	return nil
}

// findStaleEgressRemotePodIPSets records the ipsets of Egress IPs which a previous agent left on the Node, so that
// the periodic sync destroys them once the iptables rules which used them are gone. It also finds them when the
// Egress l2 dispatch is off.
func (c *Client) findStaleEgressRemotePodIPSets() error {
	data, err := c.ipset.Save()
	if err != nil {
		return err
	}
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	inUse := sets.New[string]()
	for mark, set := range c.egressRemotePodIPSets {
		inUse.Insert(egressRemotePodIPSetName(mark, set.isIPv6))
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) < 2 || fields[0] != "create" || !isEgressRemotePodIPSetName(fields[1]) || inUse.Has(fields[1]) {
			continue
		}
		c.addStaleEgressRemotePodIPSet(fields[1])
	}
	return nil
}

// destroyStaleEgressRemotePodIPSets destroys the ipsets of Egress IPs which are no longer used. It must run after an
// iptables sync, which removes the rules that used them.
func (c *Client) destroyStaleEgressRemotePodIPSets() {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	for name := range c.staleEgressRemotePodIPSets {
		if err := c.ipset.DestroyIPSet(name); err != nil {
			klog.ErrorS(err, "Failed to destroy the stale ipset of an Egress IP", "ipset", name)
			continue
		}
		klog.InfoS("Destroyed the stale ipset of an Egress IP", "ipset", name)
		c.staleEgressRemotePodIPSets.Delete(name)
	}
}

// egressRemotePodIPSetMarks returns the marks of the local Egress IPs of the IP family which have an ipset, in order.
func (c *Client) egressRemotePodIPSetMarks(isIPv6 bool) []uint32 {
	c.egressRemotePodIPSetsMutex.Lock()
	defer c.egressRemotePodIPSetsMutex.Unlock()
	var marks []uint32
	for _, mark := range slices.Sorted(maps.Keys(c.egressRemotePodIPSets)) {
		if c.egressRemotePodIPSets[mark].isIPv6 == isIPv6 {
			marks = append(marks, mark)
		}
	}
	return marks
}

// writeEgressRemotePodMangleRules writes the mangle rules of the local Egress IPs of the IP family.
func (c *Client) writeEgressRemotePodMangleRules(iptablesData *bytes.Buffer, isIPv6 bool) {
	for _, mark := range c.egressRemotePodIPSetMarks(isIPv6) {
		rule := append([]string{"-A", antreaPreRoutingChain}, c.egressRemotePodMarkRuleSpec(mark, isIPv6, true)...)
		writeLine(iptablesData, rule...)
	}
}

// writeEgressRemotePodForwardRules writes the filter rules which accept the forwarded Egress traffic of the Pods on
// other Nodes, and its replies. The other rules of ANTREA-FORWARD only accept the traffic to or from the Antrea
// gateway, and the Egress traffic of the Pods on other Nodes passes between the transport interface and the interface
// of the Egress IP. Without these rules, a host whose forwarding policy drops packets by default, for example because
// Docker is installed, drops it.
func (c *Client) writeEgressRemotePodForwardRules(iptablesData *bytes.Buffer) {
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept Egress packets from remote Pods"`,
		"-i", c.nodeConfig.NodeTransportInterfaceName,
		// Match the packets with the mark of a local Egress IP, which the mangle rules of the Egress IPs set.
		"-m", "mark", "!", "--mark", fmt.Sprintf("%#08x/%#08x", 0, types.SNATIPMarkMask),
		"-j", iptables.AcceptTarget,
	}...)
	writeLine(iptablesData, []string{
		"-A", antreaForwardChain,
		"-m", "comment", "--comment", `"Antrea: accept reply packets of Egress connections from remote Pods"`,
		"-o", c.nodeConfig.NodeTransportInterfaceName,
		// Match the reply packets of the connections which this Node SNATed, which the reverse NAT sends back to the
		// remote Pods through the transport interface.
		"-m", "conntrack", "--ctstate", "SNAT",
		"-m", "conntrack", "--ctdir", "REPLY",
		"-j", iptables.AcceptTarget,
	}...)
}

// writeEgressRemotePodMasqueradeRule writes the nat rule which masquerades the Egress traffic of the Pods on other
// Nodes whose IPs are not in the ipset of the Egress IP yet. Such traffic gets the default SNAT, with the IP of this
// Node, like the traffic of a Pod whose Egress flows are not installed yet. Without the rule, it would leave the
// cluster with the Pod IP. In noEncap mode, the traffic from the Pods on other Nodes which this Node forwards to a
// destination outside the Pod network is the traffic which they send to an Egress IP of this Node.
func (c *Client) writeEgressRemotePodMasqueradeRule(iptablesData *bytes.Buffer, podIPSet string) {
	rule := []string{
		"-A", antreaPostRoutingChain,
		"-m", "comment", "--comment", `"Antrea: masquerade Egress packets from remote Pods without an Egress IP"`,
		"-m", "set", "--match-set", podIPSet, "src",
		"-m", "set", "!", "--match-set", podIPSet, "dst",
		"!", "-o", c.nodeConfig.GatewayConfig.Name,
		"-j", iptables.MasqueradeTarget,
	}
	if c.nodeSNATRandomFully {
		rule = append(rule, "--random-fully")
	}
	writeLine(iptablesData, rule...)
}

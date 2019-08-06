package iptables

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

const (
	NATTable    = "nat"
	FilterTable = "filter"

	ForwardRuleComment            = "okn:okn forwarding rules"
	ForwardPodInternalComment     = "okn:inter pod communication"
	ForwardPodExternalNATComment  = "okn:pod to external traffic requiring SNAT"
	ForwardPodExternalComment     = "okn:pod to external communication"
	PostRoutingRuleComment        = "okn:okn postrouting rules"
	PostRoutingPodExternalComment = "okn:pod to external traffic requiring SNAT"
)

// Use the 10th bit as masquerade mark
var (
	masqueradeBits  = uint(10)
	masqueradeValue = 1 << masqueradeBits
	masqueradeMark  = fmt.Sprintf("%#08x/%#08x", masqueradeValue, masqueradeValue)
)

var ipt *iptables.IPTables

type chain struct {
	table string
	chain string
}

// Add jump action from target to current chain
func (c *chain) appendJumpFrom(fromChain string, oriRuleSpec ...string) error {
	oriRuleSpec = append(oriRuleSpec, "-j", c.chain)
	return appendRule(c.table, fromChain, oriRuleSpec)
}

// Add jump action from current chain to target
func (c *chain) appendJumpTo(target string, oriRuleSpec ...string) error {
	oriRuleSpec = append(oriRuleSpec, "-j", target)
	return appendRule(c.table, c.chain, oriRuleSpec)
}

// Add specified mark on packets
func (c *chain) appendMarkRule(oriRuleSpec []string, mark string) error {
	oriRuleSpec = append(oriRuleSpec, "-j", "MARK", "--set-xmark", mark)
	return appendRule(c.table, c.chain, oriRuleSpec)
}

// Create OKN-FORWARD chain which is for forwarding packets from/to host
// gateway interface. Packets would jump to OKN-FORWARD from FORWARD, and
//   1) traffic among local pods and host would be accepted,
//   2) traffic from pod to external addresses would add mark as 0x10/0x10 which
// is used in nat table before accepted
func setupGwForwarding(gwIface string) error {
	// Create OKN-FORWARD Chain
	hostFwdChain, err := createFilterChain("OKN-FORWARD")
	if err != nil {
		return err
	}

	// Add iptables rule to ensure packets jump from FORWARD to OKN-FORWARD
	err = hostFwdChain.appendJumpFrom("FORWARD", addMatchComment(ForwardRuleComment)...)
	if err != nil {
		return err
	}

	// Add iptables rule to accept inter pod communication
	ruleSpec := []string{"-i", gwIface, "-o", gwIface}
	ruleSpec = append(ruleSpec, addMatchComment(ForwardPodInternalComment)...)
	if err := hostFwdChain.appendJumpTo("ACCEPT", ruleSpec...); err != nil {
		return err
	}

	// Add iptables rule to add Mark on packets that from local pods to external
	ruleSpec = []string{"-i", gwIface, "!", "-o", gwIface}
	ruleSpec = append(ruleSpec, addMatchComment(ForwardPodExternalNATComment)...)
	if err := hostFwdChain.appendMarkRule(ruleSpec, masqueradeMark); err != nil {
		return err
	}

	// Add iptables rule to accept traffic from pod to external
	ruleSpec = []string{"-i", gwIface, "!", "-o", gwIface}
	ruleSpec = append(ruleSpec, addMatchComment(ForwardPodExternalComment)...)
	if err := hostFwdChain.appendJumpTo("ACCEPT", ruleSpec...); err != nil {
		return err
	}

	return nil
}

// Create OKN-POSTROUTING chain which is for executing SNAT on packets from
// local pods. Packets would jump to OKN-POSTROUTING from POSTROUTING, and execute
// SNAT only if it has masquerade mark set
func setupHostPostRouting() error {
	// Create OKN-POSTROUTING Chain in nat table
	hostPostRoutingChain, err := createNATChain("OKN-POSTROUTING")
	if err != nil {
		return err
	}

	// Add iptables rule to ensure packets jump from POSTROUTING to OKN-POSTROUTING
	if err := hostPostRoutingChain.appendJumpFrom("POSTROUTING", addMatchComment(PostRoutingRuleComment)...); err != nil {
		return err
	}

	ruleSpec := []string{"-m", "mark", "--mark", masqueradeMark}
	ruleSpec = append(ruleSpec, addMatchComment(PostRoutingPodExternalComment)...)
	// Add iptables rule to masquerade packets that has been marked in OKN-FORWARD chain
	if err := hostPostRoutingChain.appendJumpTo("MASQUERADE", ruleSpec...); err != nil {
		return err
	}
	return nil
}

// Create chain on filter table
func createFilterChain(chainName string) (*chain, error) {
	return newChain(FilterTable, chainName)
}

// Create chain on nat table
func createNATChain(chainName string) (*chain, error) {
	return newChain(NATTable, chainName)
}

// Add comments on iptables rule
func addMatchComment(comment string) []string {
	return []string{"-m", "comment", "--comment", comment}
}

// Check if target chain already exists, create only if not exist
func newChain(table string, chainName string) (*chain, error) {
	oriChains, err := ipt.ListChains(table)
	if err != nil {
		klog.Errorf("Failed to list existing iptables chains: %v", err)
		return nil, err
	}
	if !contains(oriChains, chainName) {
		if err := ipt.NewChain(table, chainName); err != nil {
			klog.Errorf("Failed to create chain %s in table %s: %v", chainName, table, err)
			return nil, err
		}
	}
	klog.Infof("Success to create target chain %s in table %s", chainName, table)
	return &chain{table: table, chain: chainName}, nil
}

// Check if iptables rule already exists firstly, add only if not exist
func appendRule(table string, chain string, ruleSpec []string) error {
	exist, err := ipt.Exists(table, chain, ruleSpec...)
	if err != nil {
		klog.Errorf("Failed to check existence in table %s chain %s for %v: %v", table, chain, ruleSpec, err)
		return err
	}
	if !exist {
		if err := ipt.Append(table, chain, ruleSpec...); err != nil {
			klog.Errorf("Failed to append on table %s chain %s with rule %v: %v", table, chain, ruleSpec, err)
		}
	}
	return nil
}

func contains(chains []string, targetChain string) bool {
	for _, val := range chains {
		if val == targetChain {
			return true
		}
	}
	return false
}

// Create OKN-FORWARD in filter table, and create OKN-POSTROUTING in nat table. Add
// forwarding and snat rules to ensure connectivity from local pods to external address.
func SetupHostIPTablesRules(hostGw string) error {
	if err := setupGwForwarding(hostGw); err != nil {
		return err
	}
	return setupHostPostRouting()
}

func init() {
	ipt, _ = iptables.New()
}

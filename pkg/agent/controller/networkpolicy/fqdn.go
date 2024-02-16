// Copyright 2021 Antrea Authors
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

package networkpolicy

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"github.com/miekg/dns"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	utilsets "antrea.io/antrea/pkg/util/sets"
	dnsutil "antrea.io/antrea/third_party/dns"
)

const (
	kubeDNSServiceHost = "KUBE_DNS_SERVICE_HOST"
	kubeDNSServicePort = "KUBE_DNS_SERVICE_PORT"

	ruleRealizationTimeout = 2 * time.Second
	dnsRequestTimeout      = 10 * time.Second
)

// fqdnSelectorItem is a selector that selects FQDNs,
// either by exact name match or by regex pattern.
type fqdnSelectorItem struct {
	matchName  string
	matchRegex string
}

func (fs *fqdnSelectorItem) String() string {
	if fs.matchRegex != "" {
		return "matchRegex:" + fs.matchRegex
	}
	return "matchName:" + fs.matchName
}

// matches knows if a FQDN is selected by the fqdnSelectorItem.
func (fs *fqdnSelectorItem) matches(fqdn string) bool {
	if fs.matchRegex != "" {
		matched, _ := regexp.MatchString(fs.matchRegex, fqdn)
		return matched
	}
	return fs.matchName == fqdn
}

// dnsMeta stores the name resolution results of a FQDN,
// including the IP addresses resolved, as well as the
// expirationTime of the records, which is the DNS response
// receiving time plus lowest applicable TTL.
type dnsMeta struct {
	expirationTime time.Time
	// Key for responseIPs is the string representation of the IP.
	// It helps to quickly identify IP address updates when a
	// new DNS response is received.
	responseIPs map[string]net.IP
}

// subscriber is a entity that subsribes for datapath rule realization
// results of a specific FQDN. It is needed in case of DNS query interception:
// the fqdnController needs to make sure that all fqdn rules that DNS
// query affects is realized, before sending the DNS query back to the
// original requesting client.
type subscriber struct {
	waitCh           chan error
	rulesToSyncCount int
}

// ruleRealizationUpdate is a rule realization result reported by policy
// rule reconciler.
type ruleRealizationUpdate struct {
	ruleId string
	err    error
}

// ruleSyncTracker tracks the realization status of FQDN rules that are
// applied to workloads on this Node.
type ruleSyncTracker struct {
	mutex sync.RWMutex
	// updateCh is the channel used by the rule reconciler to report rule realization status.
	updateCh chan ruleRealizationUpdate
	// ruleToSubscribers keeps track of the subscribers that are currently subscribed
	// to each dirty rule. Once an update of the rule realization status is received,
	// all subscribers for that rule are notified (either an error or success), after
	// which the rule entry is deleted from ruleToSubscribers.
	ruleToSubscribers map[string][]*subscriber
	// dirtyRules is collection of dirty rule IDs to be synced. Once the rule sync is
	// successful, its ID is removed from this set. Otherwise it will stay in the
	// dirtyRules set. This is to ensure that the fqdnController does not send
	// DNS response which has a fqdn rule that previously failed to realize.
	dirtyRules sets.Set[string]
}

type fqdnController struct {
	// ofClient is the Openflow interface.
	ofClient openflow.Client
	// dnsServerAddr stores the coreDNS server address, or the user provided DNS server address.
	dnsServerAddr string

	// dirtyRuleHandler is a callback that is run upon finding a rule out-of-sync.
	dirtyRuleHandler func(string)
	// A single instance of ruleSyncTracker.
	ruleSyncTracker *ruleSyncTracker
	// FQDN names this controller is tracking, with their corresponding dnsMeta.
	dnsEntryCache map[string]dnsMeta
	// FQDN names that needs to be re-queried after their respective TTLs.
	dnsQueryQueue workqueue.RateLimitingInterface
	// idAllocator provides interfaces to allocateForRule and release uint32 id.
	idAllocator *idAllocator

	fqdnRuleToPodsMutex sync.Mutex
	// The mapping between FQDN rule IDs and the Pod's ofPort IDs that the rule selects.
	fqdnRuleToSelectedPods map[string]sets.Set[int32]

	// Mutex for fqdnToSelectorItem, selectorItemToFQDN and selectorItemToRuleIDs.
	fqdnSelectorMutex sync.Mutex
	// fqdnToSelectorItem stores known FQDNSelectorItems that selects the FQDN, for each
	// FQDN tracked by this controller.
	fqdnToSelectorItem map[string]map[fqdnSelectorItem]struct{}
	// selectorItemToFQDN is a reversed map of fqdnToSelectorItem. It stores all known
	// FQDNs that match the fqdnSelectorItem.
	selectorItemToFQDN map[fqdnSelectorItem]sets.Set[string]
	// selectorItemToRuleIDs maps fqdnToSelectorItem to the rules that contains the selector.
	selectorItemToRuleIDs map[fqdnSelectorItem]sets.Set[string]
	ipv4Enabled           bool
	ipv6Enabled           bool
	gwPort                uint32
}

func newFQDNController(client openflow.Client, allocator *idAllocator, dnsServerOverride string, dirtyRuleHandler func(string), v4Enabled, v6Enabled bool, gwPort uint32) (*fqdnController, error) {
	controller := &fqdnController{
		ofClient:               client,
		dirtyRuleHandler:       dirtyRuleHandler,
		ruleSyncTracker:        &ruleSyncTracker{updateCh: make(chan ruleRealizationUpdate, 1), ruleToSubscribers: map[string][]*subscriber{}, dirtyRules: sets.New[string]()},
		idAllocator:            allocator,
		dnsQueryQueue:          workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "fqdn"),
		dnsEntryCache:          map[string]dnsMeta{},
		fqdnRuleToSelectedPods: map[string]sets.Set[int32]{},
		fqdnToSelectorItem:     map[string]map[fqdnSelectorItem]struct{}{},
		selectorItemToFQDN:     map[fqdnSelectorItem]sets.Set[string]{},
		selectorItemToRuleIDs:  map[fqdnSelectorItem]sets.Set[string]{},
		ipv4Enabled:            v4Enabled,
		ipv6Enabled:            v6Enabled,
		gwPort:                 gwPort,
	}
	if controller.ofClient != nil {
		if err := controller.ofClient.NewDNSPacketInConjunction(dnsInterceptRuleID); err != nil {
			return nil, fmt.Errorf("failed to install flow for DNS response interception: %w", err)
		}
	}
	if dnsServerOverride != "" {
		klog.InfoS("DNS server override provided by user", "dnsServer", dnsServerOverride)
		controller.dnsServerAddr = dnsServerOverride
	} else {
		host, port := os.Getenv(kubeDNSServiceHost), os.Getenv(kubeDNSServicePort)
		if host == "" || port == "" {
			klog.InfoS("Unable to derive DNS server from the kube-dns Service, will fall back to local resolver and DNS names matching the configured cluster domain suffix are not supported")
			controller.dnsServerAddr = ""
		} else {
			controller.dnsServerAddr = net.JoinHostPort(host, port)
			klog.InfoS("Using kube-dns Service for DNS requests", "dnsServer", controller.dnsServerAddr)
		}
	}
	return controller, nil
}

// fqdnToSelectorItem converts a FQDN expression to a fqdnSelectorItem.
func fqdnToSelectorItem(fqdn string) fqdnSelectorItem {
	fqdn = strings.ToLower(fqdn)
	if strings.Contains(fqdn, "*") {
		return fqdnSelectorItem{
			matchRegex: toRegex(fqdn),
		}
	}
	return fqdnSelectorItem{matchName: fqdn}
}

// toRegex converts a FQDN wildcard expression to the regex pattern used to
// match FQDNs against.
func toRegex(pattern string) string {
	pattern = strings.TrimSpace(pattern)

	// Replace "." as a regex literal, since it's recogized as a separator in FQDN.
	pattern = strings.Replace(pattern, ".", "[.]", -1)
	// Replace "*" with ".*".
	pattern = strings.Replace(pattern, "*", ".*", -1)

	// Anchor the regex match expression.
	return "^" + pattern + "$"
}

// setFQDNMatchSelector records a FQDN and a selectorItem matches.
// fqdnSelectorMutex must have been acquired by the caller.
func (f *fqdnController) setFQDNMatchSelector(fqdn string, selectorItem fqdnSelectorItem) {
	matchedSelectorItems, ok := f.fqdnToSelectorItem[fqdn]
	if !ok {
		f.fqdnToSelectorItem[fqdn] = map[fqdnSelectorItem]struct{}{
			selectorItem: {},
		}
	} else {
		matchedSelectorItems[selectorItem] = struct{}{}
	}
	matchedFQDNs, ok := f.selectorItemToFQDN[selectorItem]
	if !ok {
		f.selectorItemToFQDN[selectorItem] = sets.New[string](fqdn)
	} else {
		matchedFQDNs.Insert(fqdn)
	}
}

// getIPsForFQDNSelectors retrieves the current IP addresses cached for FQDNs that
// matches the selection criteria of a v1beta2.FQDN selector.
func (f *fqdnController) getIPsForFQDNSelectors(fqdns []string) []net.IP {
	f.fqdnSelectorMutex.Lock()
	defer f.fqdnSelectorMutex.Unlock()
	var matchedIPs []net.IP
	for _, fqdn := range fqdns {
		fqdnSelectorItem := fqdnToSelectorItem(fqdn)
		fqdnsMatched, ok := f.selectorItemToFQDN[fqdnSelectorItem]
		if !ok {
			klog.ErrorS(nil, "FQDN selector is not known to the controller, cannot get IPs", "fqdnSelector", fqdnSelectorItem)
			return matchedIPs
		}
		for fqdn := range fqdnsMatched {
			if dnsMeta, ok := f.dnsEntryCache[fqdn]; ok {
				for _, ip := range dnsMeta.responseIPs {
					matchedIPs = append(matchedIPs, ip)
				}
			}
		}
	}
	return matchedIPs
}

// addFQDNRule adds a new FQDN rule to fqdnSelectorItem mapping, as well as the OFAddresses of
// Pods selected by the FQDN rule.
func (f *fqdnController) addFQDNRule(ruleID string, fqdns []string, podOFAddrs sets.Set[int32]) error {
	f.addFQDNSelector(ruleID, fqdns)
	return f.updateRuleSelectedPods(ruleID, podOFAddrs)
}

func (f *fqdnController) addFQDNSelector(ruleID string, fqdns []string) {
	f.fqdnSelectorMutex.Lock()
	defer f.fqdnSelectorMutex.Unlock()
	for _, fqdn := range fqdns {
		fqdnSelectorItem := fqdnToSelectorItem(fqdn)
		ruleIDs, exists := f.selectorItemToRuleIDs[fqdnSelectorItem]
		if !exists {
			// This is a new fqdnSelectorItem. All existing FQDNs in the cache needs to be matched
			// against this fqdnSelectorItem to update the mapping.
			f.selectorItemToRuleIDs[fqdnSelectorItem] = sets.New[string](ruleID)
			for fqdn := range f.dnsEntryCache {
				if fqdnSelectorItem.matches(fqdn) {
					f.setFQDNMatchSelector(fqdn, fqdnSelectorItem)
				}
			}
		} else {
			f.selectorItemToRuleIDs[fqdnSelectorItem] = ruleIDs.Insert(ruleID)
		}
		if fqdnSelectorItem.matchName != "" {
			// Start a DNS query immediately for matchName selectors.
			f.setFQDNMatchSelector(fqdnSelectorItem.matchName, fqdnSelectorItem)
			f.dnsQueryQueue.Add(fqdnSelectorItem.matchName)
		}
	}
}

// updateRuleSelectedPods updates the Pod OFAddresses selected by a FQDN rule. Those addresses
// are used to create DNS response interception rules.
func (f *fqdnController) updateRuleSelectedPods(ruleID string, podOFAddrs sets.Set[int32]) error {
	f.fqdnRuleToPodsMutex.Lock()
	defer f.fqdnRuleToPodsMutex.Unlock()
	originalPodSet, newPodSet := sets.Set[int32]{}, sets.Set[int32]{}
	for _, pods := range f.fqdnRuleToSelectedPods {
		utilsets.MergeInt32(originalPodSet, pods)
	}
	f.fqdnRuleToSelectedPods[ruleID] = podOFAddrs
	for _, pods := range f.fqdnRuleToSelectedPods {
		utilsets.MergeInt32(newPodSet, pods)
	}
	addedPods, removedPods := newPodSet.Difference(originalPodSet), originalPodSet.Difference(newPodSet)
	if len(addedPods) > 0 {
		var addedOFAddrs []types.Address
		for port := range addedPods {
			addedOFAddrs = append(addedOFAddrs, openflow.NewOFPortAddress(port))
		}
		if err := f.ofClient.AddAddressToDNSConjunction(dnsInterceptRuleID, addedOFAddrs); err != nil {
			return err
		}
	}
	if len(removedPods) > 0 {
		var removedOFAddrs []types.Address
		for port := range removedPods {
			removedOFAddrs = append(removedOFAddrs, openflow.NewOFPortAddress(port))
		}
		if err := f.ofClient.DeleteAddressFromDNSConjunction(dnsInterceptRuleID, removedOFAddrs); err != nil {
			return err
		}
	}
	return nil
}

// deleteFQDNRule handles a FQDN policy rule delete event.
func (f *fqdnController) deleteFQDNRule(ruleID string, fqdns []string) error {
	f.deleteFQDNSelector(ruleID, fqdns)
	return f.deleteRuleSelectedPods(ruleID)
}

func (f *fqdnController) deleteFQDNSelector(ruleID string, fqdns []string) {
	f.fqdnSelectorMutex.Lock()
	defer f.fqdnSelectorMutex.Unlock()
	for _, fqdn := range fqdns {
		fqdnSelectorItem := fqdnToSelectorItem(fqdn)
		ruleIDs, exists := f.selectorItemToRuleIDs[fqdnSelectorItem]
		if exists && ruleIDs.Has(ruleID) {
			remainingRules := ruleIDs.Delete(ruleID)
			if len(remainingRules) > 0 {
				f.selectorItemToRuleIDs[fqdnSelectorItem] = remainingRules
			} else {
				f.cleanupFQDNSelectorItem(fqdnSelectorItem)
			}
		}
	}
}

// cleanupFQDNSelectorItem handles a fqdnSelectorItem delete event.
func (f *fqdnController) cleanupFQDNSelectorItem(fs fqdnSelectorItem) {
	for fqdn := range f.selectorItemToFQDN[fs] {
		selectors := f.fqdnToSelectorItem[fqdn]
		if _, ok := selectors[fs]; ok {
			if len(selectors) == 1 {
				// the fqdnSelectorItem being deleted is the last fqdnSelectorItem
				// that selects this FQDN. Hence this FQDN no longer needs to be
				// tracked by the fqdnController.
				delete(f.fqdnToSelectorItem, fqdn)
				delete(f.dnsEntryCache, fqdn)
			}
			delete(selectors, fs)
		}
	}
	delete(f.selectorItemToFQDN, fs)
	delete(f.selectorItemToRuleIDs, fs)
}

// deleteRuleSelectedPods removes the Pod OFAddresses selected by a FQDN rule.
func (f *fqdnController) deleteRuleSelectedPods(ruleID string) error {
	f.fqdnRuleToPodsMutex.Lock()
	defer f.fqdnRuleToPodsMutex.Unlock()
	if _, exists := f.fqdnRuleToSelectedPods[ruleID]; !exists {
		return nil
	}
	originalPodSet, newPodSet := sets.Set[int32]{}, sets.Set[int32]{}
	for _, pods := range f.fqdnRuleToSelectedPods {
		utilsets.MergeInt32(originalPodSet, pods)
	}
	delete(f.fqdnRuleToSelectedPods, ruleID)
	for _, pods := range f.fqdnRuleToSelectedPods {
		utilsets.MergeInt32(newPodSet, pods)
	}
	removedPods := originalPodSet.Difference(newPodSet)
	if len(removedPods) > 0 {
		var removedOFAddrs []types.Address
		for port := range removedPods {
			removedOFAddrs = append(removedOFAddrs, openflow.NewOFPortAddress(port))
		}
		if err := f.ofClient.DeleteAddressFromDNSConjunction(dnsInterceptRuleID, removedOFAddrs); err != nil {
			return err
		}
	}
	return nil
}

func (f *fqdnController) onDNSResponse(
	fqdn string,
	responseIPs map[string]net.IP,
	lowestTTL uint32,
	lookupTime time.Time,
	waitCh chan error,
) {
	if len(responseIPs) == 0 {
		klog.V(4).InfoS("FQDN was not resolved to any addresses, skip updating DNS cache", "fqdn", fqdn)
		if waitCh != nil {
			waitCh <- nil
		}
		return
	}
	// mustCacheResponse is only true if the FQDN is already tracked by this
	// controller, or it matches at least one fqdnSelectorItem from the policy rules.
	// addressUpdate is only true if there has been an update in IP addresses
	// corresponded with the FQDN.
	mustCacheResponse, addressUpdate := false, false
	recordTTL := lookupTime.Add(time.Duration(lowestTTL) * time.Second)

	f.fqdnSelectorMutex.Lock()
	defer f.fqdnSelectorMutex.Unlock()
	oldDNSMeta, exist := f.dnsEntryCache[fqdn]
	if exist {
		mustCacheResponse = true
		for ipStr := range responseIPs {
			if _, ok := oldDNSMeta.responseIPs[ipStr]; !ok {
				addressUpdate = true
				break
			}
		}
		for oldIPStr, oldIP := range oldDNSMeta.responseIPs {
			if _, ok := responseIPs[oldIPStr]; !ok {
				if oldDNSMeta.expirationTime.Before(time.Now()) {
					// This IP entry has already expired and not seen in the latest DNS response.
					// It should be removed from the cache.
					addressUpdate = true
				} else {
					// Add the unexpired IP entry to responseIP and update the lowest applicable TTL if needed.
					responseIPs[oldIPStr] = oldIP
					if oldDNSMeta.expirationTime.Before(recordTTL) {
						recordTTL = oldDNSMeta.expirationTime
					}
				}
			}
		}
	} else {
		for selectorItem := range f.selectorItemToRuleIDs {
			// Only track the FQDN if there is at least one fqdnSelectorItem matching it.
			if selectorItem.matches(fqdn) {
				mustCacheResponse, addressUpdate = true, true
				f.setFQDNMatchSelector(fqdn, selectorItem)
			}
		}
	}
	if mustCacheResponse {
		f.dnsEntryCache[fqdn] = dnsMeta{
			expirationTime: recordTTL,
			responseIPs:    responseIPs,
		}
		f.dnsQueryQueue.AddAfter(fqdn, recordTTL.Sub(time.Now()))
	}
	f.syncDirtyRules(fqdn, waitCh, addressUpdate)
}

// onDNSResponseMsg handles a DNS response message intercepted.
func (f *fqdnController) onDNSResponseMsg(dnsMsg *dns.Msg, lookupTime time.Time, waitCh chan error) {
	fqdn, responseIPs, lowestTTL, err := f.parseDNSResponse(dnsMsg)
	if err != nil {
		klog.V(2).InfoS("Failed to parse DNS response")
		if waitCh != nil {
			waitCh <- fmt.Errorf("failed to parse DNS response: %v", err)
		}
		return
	}
	f.onDNSResponse(fqdn, responseIPs, lowestTTL, lookupTime, waitCh)
}

// syncDirtyRules triggers rule syncs for rules that are affected by the FQDN of DNS response
// event. Note that if the query is initiated by the client Pod (not by the fqdnController, in
// which case waitCh will not be nil), even when addressUpdate is false, the function will still
// verify if there was any previous rule realization error for the dirty rules. If so, it will
// wait for another attempt of realization of these rules, before forwarding the response to the
// original client.
func (f *fqdnController) syncDirtyRules(fqdn string, waitCh chan error, addressUpdate bool) {
	if waitCh == nil && !addressUpdate {
		// No dirty rules to sync
		return
	}
	dirtyRules := sets.New[string]()
	for selectorItem := range f.fqdnToSelectorItem[fqdn] {
		utilsets.MergeString(dirtyRules, f.selectorItemToRuleIDs[selectorItem])
	}
	if waitCh == nil {
		if addressUpdate {
			for ruleID := range dirtyRules {
				klog.V(4).InfoS("Reconciling dirty rule for FQDN address updates", "ruleID", ruleID)
				f.dirtyRuleHandler(ruleID)
			}
		}
	} else {
		if !addressUpdate {
			// If there is no address update for this FQDN, and rules selecting this FQDN
			// were all previously realized successfully, then there will be no dirty rules
			// left to be synced. On the contrary, if some rules that select this FQDN are
			// still in the dirtyRules set of the ruleSyncTracker, then only those rules
			// should be retried for reconciliation, and packetOut shall be blocked.
			dirtyRules = f.ruleSyncTracker.getDirtyRules().Intersection(dirtyRules)
		}
		if len(dirtyRules) > 0 {
			klog.V(4).InfoS("Dirty rules blocking packetOut", "dirtyRules", dirtyRules)
			f.ruleSyncTracker.subscribe(waitCh, dirtyRules)
			for r := range dirtyRules {
				f.dirtyRuleHandler(r)
			}
		} else {
			klog.V(4).InfoS("Rules are already synced for this FQDN")
			waitCh <- nil
		}
	}
}

// subscribe registers a subscriber with its dirty rules update events. When the
// ruleSyncTracker receives a rule realization update, it will decrease the
// dirty rule count of each subscriber of that rule by one, if the rule is
// successfully reconciled.
func (rst *ruleSyncTracker) subscribe(waitCh chan error, dirtyRules sets.Set[string]) {
	subscriber := &subscriber{waitCh, len(dirtyRules)}
	rst.mutex.Lock()
	defer rst.mutex.Unlock()
	rst.dirtyRules = rst.dirtyRules.Union(dirtyRules)
	for r := range dirtyRules {
		rst.ruleToSubscribers[r] = append(rst.ruleToSubscribers[r], subscriber)
	}
}

// getDirtyRules retrieves the current dirty rule set of ruleSyncTracker.
func (rst *ruleSyncTracker) getDirtyRules() sets.Set[string] {
	rst.mutex.RLock()
	defer rst.mutex.RUnlock()
	// Must return a copy as the set can be updated in-place by Run func.
	return rst.dirtyRules.Clone()
}

func (rst *ruleSyncTracker) Run(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case update := <-rst.updateCh:
			rst.mutex.Lock()
			if subscribers, ok := rst.ruleToSubscribers[update.ruleId]; ok {
				for _, s := range subscribers {
					if update.err != nil {
						s.waitCh <- fmt.Errorf("failed to realize rule %s in OVS", update.ruleId)
						s.rulesToSyncCount = 0
						continue
					}
					if s.rulesToSyncCount == 0 {
						// This may happen when some other rules in the same subscriber failed to realize.
						// An error should already been pushed to the waitCh of this subscriber.
						continue
					}
					s.rulesToSyncCount--
					if s.rulesToSyncCount == 0 {
						// All dirty rules for that subscriber have been processed successfully.
						s.waitCh <- nil
					}
				}
				delete(rst.ruleToSubscribers, update.ruleId)
			}
			// Only delete the ruleId from dirtyRules if rule realization is successful.
			if update.err == nil {
				rst.dirtyRules.Delete(update.ruleId)
			}
			rst.mutex.Unlock()
		}
	}
}

// notifyRuleUpdate is an interface for the reconciler to notify the ruleSyncTracker of a
// rule realization status.
func (f *fqdnController) notifyRuleUpdate(ruleID string, err error) {
	f.ruleSyncTracker.updateCh <- ruleRealizationUpdate{ruleID, err}
}

func (f *fqdnController) runRuleSyncTracker(stopCh <-chan struct{}) {
	f.ruleSyncTracker.Run(stopCh)
}

// parseDNSResponse returns the FQDN, IP query result and lowest applicable TTL of a DNS response.
func (f *fqdnController) parseDNSResponse(msg *dns.Msg) (string, map[string]net.IP, uint32, error) {
	if len(msg.Question) == 0 {
		return "", nil, 0, fmt.Errorf("invalid DNS message")
	}
	fqdn := strings.ToLower(msg.Question[0].Name)
	lowestTTL := uint32(math.MaxUint32) // a TTL must exist in the RRs
	responseIPs := map[string]net.IP{}
	for _, ans := range msg.Answer {
		switch r := ans.(type) {
		case *dns.A:
			if f.ipv4Enabled {
				responseIPs[r.A.String()] = r.A
				if r.Header().Ttl < lowestTTL {
					lowestTTL = r.Header().Ttl
				}
			}
		case *dns.AAAA:
			if f.ipv6Enabled {
				responseIPs[r.AAAA.String()] = r.AAAA
				if r.Header().Ttl < lowestTTL {
					lowestTTL = r.Header().Ttl
				}
			}
		}
	}
	if len(responseIPs) > 0 {
		klog.V(4).InfoS("Received DNS Packet with valid Answer", "IPs", responseIPs, "TTL", lowestTTL)
	}
	if strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return fqdn, responseIPs, lowestTTL, nil
}

func (f *fqdnController) worker() {
	for f.processNextWorkItem() {
	}
}

func (f *fqdnController) processNextWorkItem() bool {
	key, quit := f.dnsQueryQueue.Get()
	if quit {
		return false
	}
	defer f.dnsQueryQueue.Done(key)

	ctx, cancel := context.WithTimeout(context.Background(), dnsRequestTimeout)
	defer cancel()
	err := f.makeDNSRequest(ctx, key.(string))
	f.handleErr(err, key)
	return true
}

func (f *fqdnController) handleErr(err error, key interface{}) {
	if err == nil {
		f.dnsQueryQueue.Forget(key)
		return
	}
	klog.ErrorS(err, "Error syncing FQDN, retrying", "fqdn", key)
	f.dnsQueryQueue.AddRateLimited(key)
}

func (f *fqdnController) lookupIP(ctx context.Context, fqdn string) error {
	const defaultTTL = 600 // 600 seconds, 10 minutes
	resolver := net.DefaultResolver

	v4ok, v6ok := true, true

	makeResponseIPs := func(ips []net.IP) map[string]net.IP {
		responseIPs := make(map[string]net.IP)
		for _, ip := range ips {
			responseIPs[ip.String()] = ip
		}
		return responseIPs
	}

	if f.ipv4Enabled {
		lookupTime := time.Now()
		if ips, err := resolver.LookupIP(ctx, "ip4", fqdn); err == nil {
			f.onDNSResponse(fqdn, makeResponseIPs(ips), defaultTTL, lookupTime, nil)
		} else {
			v4ok = false
		}
	}
	if f.ipv6Enabled {
		lookupTime := time.Now()
		if ips, err := resolver.LookupIP(ctx, "ip6", fqdn); err == nil {
			f.onDNSResponse(fqdn, makeResponseIPs(ips), defaultTTL, lookupTime, nil)
		} else {
			v6ok = false
		}
	}

	if !v4ok || !v6ok {
		return fmt.Errorf("DNS request failed for at least one network (v4 and/or v6)")
	}
	return nil
}

// makeDNSRequest makes a proactive query for a FQDN to the coreDNS service.
func (f *fqdnController) makeDNSRequest(ctx context.Context, fqdn string) error {
	if f.dnsServerAddr == "" {
		klog.V(2).InfoS("No DNS server configured, falling back to local resolver")
		return f.lookupIP(ctx, fqdn)
	}
	klog.V(2).InfoS("Making DNS request", "fqdn", fqdn, "dnsServer", f.dnsServerAddr)
	dnsClient := dns.Client{SingleInflight: true}
	fqdnToQuery := fqdn
	// The FQDN in the DNS request needs to end by a dot
	if fqdn[len(fqdn)-1] != '.' {
		fqdnToQuery = fqdn + "."
	}
	query := func(m *dns.Msg) (*dns.Msg, error) {
		r, _, err := dnsClient.ExchangeContext(ctx, m, f.dnsServerAddr)
		if err != nil {
			klog.ErrorS(err, "DNS exchange failed")
			return nil, err
		}
		return r, nil
	}
	v4ok, v6ok := true, true
	if f.ipv4Enabled {
		m := dns.Msg{}
		m.SetQuestion(fqdnToQuery, dns.TypeA)
		lookupTime := time.Now()
		if res, err := query(&m); err == nil {
			f.onDNSResponseMsg(res, lookupTime, nil)
		} else {
			v4ok = false
		}
	}
	if f.ipv6Enabled {
		m := dns.Msg{}
		m.SetQuestion(fqdnToQuery, dns.TypeAAAA)
		lookupTime := time.Now()
		if res, err := query(&m); err == nil {
			f.onDNSResponseMsg(res, lookupTime, nil)
		} else {
			v6ok = false
		}
	}
	if !v4ok || !v6ok {
		return fmt.Errorf("DNS request failed for at least one of type A or AAAA queries")
	}
	return nil
}

// HandlePacketIn implements openflow.PacketInHandler
func (f *fqdnController) HandlePacketIn(pktIn *ofctrl.PacketIn) error {
	klog.V(4).InfoS("Received a packetIn for DNS response")
	waitCh := make(chan error, 1)
	handleUDP := func(udp *protocol.UDP) {
		dnsMsg := dns.Msg{}
		if err := dnsMsg.Unpack(udp.Data); err != nil {
			// A non-DNS response packet or a fragmented DNS response is received. Forward it to the Pod.
			waitCh <- nil
			return
		}
		f.onDNSResponseMsg(&dnsMsg, time.Now(), waitCh)
	}
	handleTCP := func(tcpPkt *protocol.TCP) {
		dnsData, dataLength, err := binding.GetTCPDNSData(tcpPkt)
		if err != nil {
			// The packet doesn't contain a valid DNS length field and data. Forward it to the Pod.
			klog.V(4).InfoS("Unable to get DNS data from the packet, skipping it", "err", err)
			waitCh <- nil
			return
		}
		dnsMsg := dns.Msg{}
		if dataLength > len(dnsData) {
			// This is likely the first fragment containing the length field and partial message of a DNS response.
			// Usually the first fragment contains the question and answer sections, from which we can get FQDN <-> IP
			// mapping. So we try to partially unpack it.
			klog.InfoS("Received a fragmented DNS response, partially unpacking it", "lengthField", dataLength, "actualLength", len(dnsData))
			if err := dnsutil.UnpackDNSMsgPartially(dnsData, &dnsMsg); err != nil {
				klog.InfoS("Unable to unpack the DNS response partially, skipping it", "err", err)
				waitCh <- nil
				return
			}
		} else if err := dnsMsg.Unpack(dnsData); err != nil {
			// This is likely a non-DNS response packet or a non-first-DNS response packet containing partial message.
			// Set verbose level to 2 as normally we are not interested in it.
			klog.V(2).InfoS("Unable to unpack the DNS response, skipping it", "err", err)
			waitCh <- nil
			return
		}
		f.onDNSResponseMsg(&dnsMsg, time.Now(), waitCh)
	}
	go func() {
		ethernetPkt, err := openflow.GetEthernetPacket(pktIn)
		if err != nil {
			// Can't parse the packet. Forward it to the Pod.
			waitCh <- nil
			return
		}
		switch ipPkt := ethernetPkt.Data.(type) {
		case *protocol.IPv4:
			proto := ipPkt.Protocol
			switch proto {
			case protocol.Type_UDP:
				handleUDP(ipPkt.Data.(*protocol.UDP))
			case protocol.Type_TCP:
				tcpPkt, err := binding.GetTCPPacketFromIPMessage(ipPkt)
				if err != nil {
					// Can't parse the packet. Forward it to the Pod.
					waitCh <- nil
					return
				}
				handleTCP(tcpPkt)
			}
		case *protocol.IPv6:
			proto := ipPkt.NextHeader
			switch proto {
			case protocol.Type_UDP:
				handleUDP(ipPkt.Data.(*protocol.UDP))
			case protocol.Type_TCP:
				tcpPkt, err := binding.GetTCPPacketFromIPMessage(ipPkt)
				if err != nil {
					// Can't parse the packet. Forward it to the Pod.
					waitCh <- nil
					return
				}
				handleTCP(tcpPkt)
			}
		}
	}()
	select {
	case <-time.After(ruleRealizationTimeout):
		return fmt.Errorf("rules not synced within %v for DNS reply, dropping packet", ruleRealizationTimeout)
	case err := <-waitCh:
		if err != nil {
			return fmt.Errorf("error when syncing up rules for DNS reply, dropping packet: %v", err)
		}
		klog.V(2).InfoS("Rule sync is successful or not needed or a non-DNS response packet was received, forwarding the packet to Pod")
		return f.ofClient.ResumePausePacket(pktIn)
	}
}

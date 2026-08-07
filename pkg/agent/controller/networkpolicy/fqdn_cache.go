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

package networkpolicy

import (
	"container/heap"
	"container/list"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"antrea.io/antrea/v2/pkg/agent/metrics"
)

const (
	// maxTrackedFQDNs caps the number of FQDNs tracked by the fqdnCache which no
	// fqdnSelectorItem selects by exact name. It bounds the memory which the
	// fqdnController uses for FQDN tracking, regardless of how many FQDN selectors
	// the policies of the cluster define, which maxFQDNsPerSelector alone does not.
	// The FQDNs which a policy names explicitly are exempt, as their number is
	// bounded by the number of selectors, and evicting one would stop a rule from
	// matching a name which it lists.
	maxTrackedFQDNs = 10000

	// maxFQDNsPerSelector caps the number of FQDNs tracked for a single
	// fqdnSelectorItem. Without it, a single wildcard selector could fill the whole
	// cache and evict the FQDNs tracked for every other selector, so that a Pod
	// resolving many distinct names under one wildcard expression would stop the
	// rules using unrelated expressions from matching the names they select. In
	// practice only a wildcard selector can reach this cap, as a selector matching
	// an exact name never tracks more than that one name.
	maxFQDNsPerSelector = 1024

	// idleRequeryWait bounds how long a worker blocks in nextDue while no DNS query
	// is due. It is only a safety net: a worker is woken as soon as a query is
	// scheduled, so this does not determine the delay of a re-query.
	idleRequeryWait = time.Minute

	// notScheduled is the heapIndex of a fqdnCacheEntry which has no DNS query
	// scheduled, which is the case while a worker is making one for it.
	notScheduled = -1

	// evictionLogInterval bounds how often the eviction of a FQDN is logged, for each
	// of the two limits. Once the cache is at one of them, an eviction happens for
	// every new domain name which is resolved, hence logging each one would flood the
	// log; the antrea_agent_fqdn_cache_eviction_count metric counts them all.
	evictionLogInterval = 10 * time.Minute
)

// fqdnCacheEntry is the state which the fqdnCache tracks for a single FQDN.
type fqdnCacheEntry struct {
	// fqdn is the domain name which this entry tracks. It is set when the entry is
	// created, before the entry is published in the entries map, and never modified
	// afterwards, hence it can be read without holding the mutex. The workers rely on
	// this to make their DNS query from the entry which nextDue handed them.
	fqdn string
	// meta holds the IPs which the FQDN currently resolves to.
	meta dnsMeta
	// resolved records whether meta was ever set. A FQDN can be tracked before it is
	// resolved for the first time: the exact name of a newly added fqdnSelectorItem
	// starts being tracked when the selector is added, before the fqdnController
	// makes its first DNS query for it.
	resolved bool

	// selectorElems is the position of this entry in the recency order of each
	// fqdnSelectorItem which selects the FQDN. Its key set is therefore the set of
	// selectors selecting the FQDN.
	selectorElems map[fqdnSelectorItem]*list.Element
	// exactSelectors counts the fqdnSelectorItems in selectorElems which select the
	// FQDN by exact name. An entry with at least one of them is never evicted to
	// honor maxTrackedFQDNs: the exact names used by the policies are chosen by the
	// cluster admin and are bounded by the number of selectors, while evicting one
	// would stop a rule from matching a name which it explicitly lists.
	exactSelectors int
	// globalElem is the position of this entry in the global recency order, or nil
	// while the entry is exempt from it because exactSelectors is not zero.
	globalElem *list.Element

	// requeryAt is the time at which the next DNS query for this FQDN is due. It is
	// only meaningful while the entry is scheduled.
	requeryAt time.Time
	// heapIndex is the position of this entry in the requery heap of the fqdnCache,
	// or notScheduled.
	heapIndex int
	// querying is set while a worker is making the DNS query which nextDue handed out
	// for this entry. The entry is not scheduled while it is set: a query scheduled in
	// the meantime is recorded in pendingRequeryAt and only applied by doneQuerying,
	// so that two workers never query the same FQDN at the same time.
	querying bool
	// pendingRequeryAt is the earliest time at which a DNS query was scheduled for
	// this entry while querying was set, or the zero time if none was.
	pendingRequeryAt time.Time
	// failures counts the consecutive failed DNS queries for this FQDN, and drives
	// the retry backoff.
	failures int
}

// requeryHeap orders the scheduled entries of a fqdnCache by requeryAt, earliest
// first. fqdnCache.mutex guards it.
type requeryHeap []*fqdnCacheEntry

func (h requeryHeap) Len() int           { return len(h) }
func (h requeryHeap) Less(i, j int) bool { return h[i].requeryAt.Before(h[j].requeryAt) }

func (h requeryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex, h[j].heapIndex = i, j
}

func (h *requeryHeap) Push(x any) {
	entry := x.(*fqdnCacheEntry)
	entry.heapIndex = len(*h)
	*h = append(*h, entry)
}

func (h *requeryHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	entry.heapIndex = notScheduled
	return entry
}

// fqdnCache is the single structure tracking the FQDNs which the fqdnController
// resolves for FQDN policy rules. It combines the responsibilities which would
// otherwise be spread over several structures keyed by FQDN:
//   - it stores the IPs which each FQDN resolves to, along with the
//     fqdnSelectorItems which select it;
//   - it orders the FQDNs by recency of use, both globally and for each selector,
//     and bounds their number with maxTrackedFQDNs and maxFQDNsPerSelector,
//     evicting the least-recently-used FQDN past either cap;
//   - it schedules the DNS query which refreshes each FQDN once its records
//     expire, and hands the due FQDNs out to the fqdnController workers.
//
// Holding the schedule in the same structure as the entries is what makes the cap
// hold: evicting an entry also cancels its scheduled query, so the schedule can
// never cover more FQDNs than the cache itself contains. Scheduling the queries in
// a delaying workqueue instead cannot offer this, as an item which has already
// been scheduled in a workqueue cannot be removed from it; the queue would then
// keep growing with the FQDNs which the cache has already evicted.
//
// Recency is only refreshed by the resolutions which client Pods initiate, which
// is the only signal that a FQDN is in use. It is deliberately not refreshed by
// the re-queries which the fqdnController makes itself: every tracked FQDN is
// re-queried whether any Pod still uses it or not, so doing so would order the
// caches by the TTL length of the records instead of by usage, and would let a
// FQDN which no Pod resolves anymore keep itself tracked, and re-queried, forever.
type fqdnCache struct {
	clock                 clock.Clock
	maxEntries            int
	maxEntriesPerSelector int

	mutex sync.Mutex
	// entries holds every tracked FQDN.
	entries map[string]*fqdnCacheEntry
	// globalOrder holds the entries which may be evicted to honor maxEntries, most
	// recently used first. The entries selected by exact name are left out of it, as
	// they are exempt: this also keeps the choice of a victim O(1), which walking
	// past them would not, since their recency is never refreshed and they therefore
	// accumulate at the back.
	globalOrder *list.List
	// selectorOrder holds, for each fqdnSelectorItem selecting at least one tracked
	// FQDN, the entries which it selects, most recently used first. It bounds each
	// selector at maxEntriesPerSelector.
	selectorOrder map[fqdnSelectorItem]*list.List
	// scheduled orders the entries whose DNS query is scheduled by requeryAt.
	scheduled requeryHeap
	// wakeCh is closed and replaced whenever a DNS query is scheduled, so that the
	// workers waiting in nextDue reconsider which query is due next.
	wakeCh chan struct{}
	// selectorLimitEvictions and totalLimitEvictions rate-limit the logging of the
	// evictions made to honor, respectively, maxEntriesPerSelector and maxEntries.
	selectorLimitEvictions, totalLimitEvictions evictionLogState
}

// evictionLogState rate-limits the logging of the evictions made to honor one of the
// two limits of a fqdnCache.
type evictionLogState struct {
	// sinceLastLog counts the evictions which were not logged since lastLog.
	sinceLastLog int
	// lastLog is the time at which an eviction was last logged, or the zero time if
	// none was.
	lastLog time.Time
}

func newFQDNCache(clock clock.Clock, maxEntries, maxEntriesPerSelector int) *fqdnCache {
	return &fqdnCache{
		clock:                 clock,
		maxEntries:            maxEntries,
		maxEntriesPerSelector: maxEntriesPerSelector,
		entries:               map[string]*fqdnCacheEntry{},
		globalOrder:           list.New(),
		selectorOrder:         map[fqdnSelectorItem]*list.List{},
		wakeCh:                make(chan struct{}),
	}
}

// track records that selectorItem selects fqdn, and refreshes the recency of the
// FQDN both globally and for selectorItem. The FQDN starts being tracked if it was
// not already, and tracking it may evict others to honor the two caps.
//
// The returned set holds every fqdnSelectorItem whose FQDNs changed, including
// selectorItem itself when it just started selecting fqdn. The rules using these
// selectors must be realized again, so that the addresses of the FQDNs which were
// evicted stop matching them and the addresses of fqdn start matching the rules of
// a selector which had evicted it.
func (c *fqdnCache) track(fqdn string, selectorItem fqdnSelectorItem) sets.Set[fqdnSelectorItem] {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	affected := sets.New[fqdnSelectorItem]()
	c.trackLocked(fqdn, selectorItem, true, affected)
	return affected
}

// trackExisting records that selectorItem, which has just been added to the
// fqdnController, selects the given FQDNs, which the cache already tracks for other
// fqdnSelectorItems. At most maxEntriesPerSelector of them are tracked for it; the
// others start being tracked for it as the client Pods resolve them again (see
// onDNSResponse). The whole batch is handled under a single acquisition of the lock,
// as a new wildcard expression can match every tracked FQDN, and its caller holds
// fqdnSelectorMutex, which the interception of DNS responses needs.
//
// Unlike track, this does not refresh the recency of the FQDNs: adding a policy is
// not a use of the names it selects, and treating it as one would let a new
// expression displace, from the global order, the FQDNs which the Pods are actually
// resolving.
//
// The returned set holds every fqdnSelectorItem whose FQDNs changed, which is
// selectorItem alone: no FQDN is evicted, as the cap is honored before tracking one
// more and the FQDNs are all tracked already.
func (c *fqdnCache) trackExisting(fqdns []string, selectorItem fqdnSelectorItem) sets.Set[fqdnSelectorItem] {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	affected := sets.New[fqdnSelectorItem]()
	for _, fqdn := range fqdns {
		if order, ok := c.selectorOrder[selectorItem]; ok && order.Len() >= c.maxEntriesPerSelector {
			klog.V(4).InfoS("FQDN selector is at its limit, the FQDNs it matches which it does not track yet will be tracked as they are resolved again",
				"fqdnSelector", &selectorItem, "limit", c.maxEntriesPerSelector)
			break
		}
		c.trackLocked(fqdn, selectorItem, false, affected)
	}
	return affected
}

// trackLocked implements track for a single FQDN. refresh reports whether the caller
// is recording a use of the FQDN, in which case it becomes the most recently used one
// for selectorItem and globally; a FQDN tracked without being used is tracked as the
// least recently used one, and is therefore the first to be evicted.
// mutex must have been acquired by the caller.
func (c *fqdnCache) trackLocked(fqdn string, selectorItem fqdnSelectorItem, refresh bool, affected sets.Set[fqdnSelectorItem]) {
	entry, ok := c.entries[fqdn]
	if !ok {
		entry = &fqdnCacheEntry{
			fqdn:          fqdn,
			selectorElems: map[fqdnSelectorItem]*list.Element{},
			heapIndex:     notScheduled,
		}
		c.entries[fqdn] = entry
	}

	order, ok := c.selectorOrder[selectorItem]
	if !ok {
		order = list.New()
		c.selectorOrder[selectorItem] = order
	}
	if elem, ok := entry.selectorElems[selectorItem]; ok {
		if refresh {
			order.MoveToFront(elem)
		}
	} else {
		if refresh {
			entry.selectorElems[selectorItem] = order.PushFront(entry)
		} else {
			entry.selectorElems[selectorItem] = order.PushBack(entry)
		}
		if selectorItem.matchRegex == "" {
			entry.exactSelectors++
		}
		affected.Insert(selectorItem)
	}
	c.syncGlobalOrderLocked(entry, refresh)

	// Enforce the per-selector cap before the global one: dropping a FQDN from
	// selectorItem may drop the entry altogether and so free a global slot.
	for order.Len() > c.maxEntriesPerSelector {
		victim := order.Back().Value.(*fqdnCacheEntry)
		metrics.FQDNCacheEvictionCount.WithLabelValues(metrics.LabelFQDNCacheSelectorLimit).Inc()
		if evictions, shouldLog := c.recordEvictionLocked(&c.selectorLimitEvictions); shouldLog {
			klog.InfoS("Evicting the least-recently-used FQDN of a FQDN selector which is at its limit. The rules using this selector stop matching this FQDN until a Pod which they select resolves it again",
				"fqdn", victim.fqdn, "fqdnSelector", &selectorItem, "limit", c.maxEntriesPerSelector, "evictionsSinceLastLog", evictions)
		}
		c.untrackLocked(victim, selectorItem, affected)
	}
	for c.globalOrder.Len() > c.maxEntries {
		victim := c.globalOrder.Back().Value.(*fqdnCacheEntry)
		metrics.FQDNCacheEvictionCount.WithLabelValues(metrics.LabelFQDNCacheTotalLimit).Inc()
		if evictions, shouldLog := c.recordEvictionLocked(&c.totalLimitEvictions); shouldLog {
			klog.InfoS("Evicting the least-recently-used FQDN, the FQDN cache is at its limit. The rules using the FQDN selectors which select this FQDN stop matching it until a Pod which they select resolves it again",
				"fqdn", victim.fqdn, "limit", c.maxEntries, "evictionsSinceLastLog", evictions)
		}
		c.removeLocked(victim, affected)
	}
	metrics.FQDNCacheSize.Set(float64(len(c.entries)))
}

// recordEvictionLocked records an eviction made to honor the limit which state
// tracks, and reports whether it should be logged, along with the number of
// evictions the log stands for, which is the one being recorded plus the ones which
// were not logged since the last one was.
// mutex must have been acquired by the caller.
func (c *fqdnCache) recordEvictionLocked(state *evictionLogState) (evictions int, shouldLog bool) {
	state.sinceLastLog++
	now := c.clock.Now()
	if !state.lastLog.IsZero() && now.Sub(state.lastLog) < evictionLogInterval {
		return 0, false
	}
	state.lastLog = now
	evictions = state.sinceLastLog
	state.sinceLastLog = 0
	return evictions, true
}

// syncGlobalOrderLocked keeps entry in the global recency order only while no
// fqdnSelectorItem selects it by exact name. It must be called after any change to
// the selectors of entry. refresh reports whether the change was a use of the FQDN,
// in which case it becomes the most recently used entry.
//
// An entry which enters the order without having been used enters it as the least
// recently used one: this happens when a policy naming the FQDN explicitly is
// deleted while a wildcard expression still selects it, and no recency was recorded
// for it while it was exempt. It is then the first to be evicted, and starts being
// tracked again the next time a selected Pod resolves it.
// mutex must have been acquired by the caller.
func (c *fqdnCache) syncGlobalOrderLocked(entry *fqdnCacheEntry, refresh bool) {
	if entry.exactSelectors > 0 {
		if entry.globalElem != nil {
			c.globalOrder.Remove(entry.globalElem)
			entry.globalElem = nil
		}
		return
	}
	switch {
	case entry.globalElem == nil && refresh:
		entry.globalElem = c.globalOrder.PushFront(entry)
	case entry.globalElem == nil:
		entry.globalElem = c.globalOrder.PushBack(entry)
	case refresh:
		c.globalOrder.MoveToFront(entry.globalElem)
	}
}

// untrackSelector stops tracking selectorItem. The FQDNs which no other
// fqdnSelectorItem selects stop being tracked, and their scheduled DNS queries are
// cancelled with them. No other selector can be affected, as an entry is only
// removed when selectorItem was the last selector selecting it.
func (c *fqdnCache) untrackSelector(selectorItem fqdnSelectorItem) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	order, ok := c.selectorOrder[selectorItem]
	if !ok {
		return
	}
	for elem := order.Front(); elem != nil; {
		entry := elem.Value.(*fqdnCacheEntry)
		// untrackLocked removes elem from order, so advance before calling it.
		elem = elem.Next()
		c.untrackLocked(entry, selectorItem, nil)
	}
	delete(c.selectorOrder, selectorItem)
	metrics.FQDNCacheSize.Set(float64(len(c.entries)))
}

// untrackLocked stops tracking entry for selectorItem, and stops tracking it
// entirely if selectorItem was the last fqdnSelectorItem selecting it. Every
// selector which stops selecting entry is added to affected, which may be nil.
// mutex must have been acquired by the caller.
func (c *fqdnCache) untrackLocked(entry *fqdnCacheEntry, selectorItem fqdnSelectorItem, affected sets.Set[fqdnSelectorItem]) {
	elem, ok := entry.selectorElems[selectorItem]
	if !ok {
		return
	}
	order := c.selectorOrder[selectorItem]
	order.Remove(elem)
	if order.Len() == 0 {
		delete(c.selectorOrder, selectorItem)
	}
	delete(entry.selectorElems, selectorItem)
	if selectorItem.matchRegex == "" {
		entry.exactSelectors--
	}
	if affected != nil {
		affected.Insert(selectorItem)
	}
	if len(entry.selectorElems) == 0 {
		c.removeLocked(entry, affected)
		return
	}
	// The entry may have lost its last exact name selector, in which case it becomes
	// evictable. Its recency is not refreshed: it was not used, it was untracked.
	c.syncGlobalOrderLocked(entry, false)
}

// removeLocked stops tracking entry entirely, cancelling its scheduled DNS query.
// Every fqdnSelectorItem which still selected it is added to affected, which may
// be nil.
// mutex must have been acquired by the caller.
func (c *fqdnCache) removeLocked(entry *fqdnCacheEntry, affected sets.Set[fqdnSelectorItem]) {
	for selectorItem, elem := range entry.selectorElems {
		order := c.selectorOrder[selectorItem]
		order.Remove(elem)
		if order.Len() == 0 {
			delete(c.selectorOrder, selectorItem)
		}
		if affected != nil {
			affected.Insert(selectorItem)
		}
	}
	entry.selectorElems = nil
	entry.exactSelectors = 0
	if entry.globalElem != nil {
		c.globalOrder.Remove(entry.globalElem)
		entry.globalElem = nil
	}
	if entry.heapIndex != notScheduled {
		heap.Remove(&c.scheduled, entry.heapIndex)
	}
	delete(c.entries, entry.fqdn)
}

// setResolved records the IPs which fqdn resolves to and schedules the DNS query
// which will refresh them at requeryAt. It is a no-op if the FQDN is not tracked,
// which is how the result of a DNS query for a FQDN evicted while it was in flight
// is discarded.
func (c *fqdnCache) setResolved(fqdn string, meta dnsMeta, requeryAt time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries[fqdn]
	if !ok {
		return
	}
	entry.meta = meta
	entry.resolved = true
	c.scheduleLocked(entry, requeryAt)
}

// scheduleNow makes the DNS query for fqdn due immediately. It is a no-op if the
// FQDN is not tracked.
func (c *fqdnCache) scheduleNow(fqdn string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if entry, ok := c.entries[fqdn]; ok {
		c.scheduleLocked(entry, c.clock.Now())
	}
}

// scheduleLocked makes the DNS query for entry due at requeryAt.
// mutex must have been acquired by the caller.
func (c *fqdnCache) scheduleLocked(entry *fqdnCacheEntry, requeryAt time.Time) {
	if entry.querying {
		// A worker is querying this FQDN. Record the schedule instead of applying it, so
		// that the worker is the only one making a query for the FQDN; doneQuerying
		// applies the earliest schedule recorded in the meantime.
		if entry.pendingRequeryAt.IsZero() || requeryAt.Before(entry.pendingRequeryAt) {
			entry.pendingRequeryAt = requeryAt
		}
		return
	}
	entry.requeryAt = requeryAt
	if entry.heapIndex == notScheduled {
		heap.Push(&c.scheduled, entry)
	} else {
		heap.Fix(&c.scheduled, entry.heapIndex)
	}
	// Only the entry which is due first determines how long the workers wait in
	// nextDue, hence waking them for any other one would be pointless. This matters
	// because every DNS response schedules a query, and every wake-up has each worker
	// contend for the mutex.
	if entry.heapIndex == 0 {
		close(c.wakeCh)
		c.wakeCh = make(chan struct{})
	}
}

// nextDue blocks until the DNS query for a tracked FQDN is due and returns the
// entry of that FQDN, or until stopCh is closed, in which case it returns false.
// The entry is left unscheduled, and marked as being queried, until doneQuerying is
// called for it, so that concurrent workers never query the same FQDN at the same
// time. doneQuerying must therefore be called with the entry once the query has
// completed.
func (c *fqdnCache) nextDue(stopCh <-chan struct{}) (*fqdnCacheEntry, bool) {
	for {
		c.mutex.Lock()
		now := c.clock.Now()
		wait := idleRequeryWait
		if len(c.scheduled) > 0 {
			if next := c.scheduled[0]; !next.requeryAt.After(now) {
				heap.Pop(&c.scheduled)
				next.querying = true
				next.pendingRequeryAt = time.Time{}
				c.mutex.Unlock()
				return next, true
			} else if remaining := next.requeryAt.Sub(now); remaining < wait {
				wait = remaining
			}
		}
		wakeCh := c.wakeCh
		c.mutex.Unlock()

		timer := c.clock.NewTimer(wait)
		select {
		case <-stopCh:
			timer.Stop()
			return nil, false
		case <-timer.C():
		case <-wakeCh:
			timer.Stop()
		}
	}
}

// doneQuerying reports the outcome of the DNS query which nextDue handed out for
// entry, and applies the schedule which the processing of the response asked for
// while the query was in flight. A failed query is retried with an exponential
// backoff. If neither happened, which is the case when a successful query resolved
// no address, no new query is scheduled for the FQDN, and the entry is eventually
// evicted as the least-recently-used one.
func (c *fqdnCache) doneQuerying(entry *fqdnCacheEntry, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.entries[entry.fqdn] != entry {
		// The FQDN stopped being tracked while the query was in flight. It may even be
		// tracked again already, by a different entry created after this one was evicted:
		// that entry has its own schedule, its own retry backoff, and possibly a worker
		// of its own querying it, hence the outcome reported here must not be applied to
		// it.
		return
	}
	entry.querying = false
	requeryAt := entry.pendingRequeryAt
	entry.pendingRequeryAt = time.Time{}
	if err == nil {
		entry.failures = 0
	} else {
		// Shifting by more than a few positions is pointless, and would overflow.
		backoff := minRetryDelay << min(entry.failures, 8)
		if backoff > maxRetryDelay {
			backoff = maxRetryDelay
		}
		entry.failures++
		// A query can fail for one IP family after succeeding for the other, in which
		// case the response which was processed already scheduled the refresh of the
		// records it carried. Retrying must not push that refresh back, as these records
		// would then be used in the datapath past their TTL, for the whole backoff.
		retryAt := c.clock.Now().Add(backoff)
		if requeryAt.IsZero() || retryAt.Before(requeryAt) {
			requeryAt = retryAt
		}
	}
	if !requeryAt.IsZero() {
		c.scheduleLocked(entry, requeryAt)
	}
}

// meta returns the IPs which fqdn resolves to, along with the two states which the
// absence of IPs can stand for:
//   - tracked reports whether the fqdnCache holds an entry for the FQDN, which means
//     that at least one fqdnSelectorItem selects it and that its DNS queries are
//     scheduled. A FQDN which was never resolved, or which was evicted to honor one
//     of the limits of the cache, is not tracked.
//   - resolved reports whether a DNS query for the FQDN ever completed, which is what
//     makes the returned dnsMeta meaningful. A FQDN is tracked without being resolved
//     only if a fqdnSelectorItem selects it by exact name: such a selector starts
//     tracking the name it holds as soon as it is added, and the FQDN stays unresolved
//     until the first DNS query which the fqdnController makes for it completes, or
//     indefinitely if the name never resolves. A FQDN selected by a wildcard
//     expression alone cannot be in this state: it only starts being tracked as it is
//     resolved.
//
// resolved therefore implies tracked, and the returned dnsMeta is only valid when
// resolved is true. Both being false means that the FQDN is either unknown or was
// evicted to honor one of the limits of the cache.
func (c *fqdnCache) meta(fqdn string) (meta dnsMeta, tracked bool, resolved bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries[fqdn]
	if !ok {
		return dnsMeta{}, false, false
	}
	if !entry.resolved {
		return dnsMeta{}, true, false
	}
	return entry.meta, true, true
}

// selectorsFor returns the fqdnSelectorItems which currently track fqdn.
func (c *fqdnCache) selectorsFor(fqdn string) []fqdnSelectorItem {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries[fqdn]
	if !ok {
		return nil
	}
	selectorItems := make([]fqdnSelectorItem, 0, len(entry.selectorElems))
	for selectorItem := range entry.selectorElems {
		selectorItems = append(selectorItems, selectorItem)
	}
	return selectorItems
}

// fqdnsFor returns the FQDNs which selectorItem currently tracks.
func (c *fqdnCache) fqdnsFor(selectorItem fqdnSelectorItem) []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	order, ok := c.selectorOrder[selectorItem]
	if !ok {
		return nil
	}
	fqdns := make([]string, 0, order.Len())
	for elem := order.Front(); elem != nil; elem = elem.Next() {
		fqdns = append(fqdns, elem.Value.(*fqdnCacheEntry).fqdn)
	}
	return fqdns
}

// resolvedFQDNs returns a snapshot of the FQDNs which were resolved at least once,
// so that the caller can match them against a selector without holding the lock.
func (c *fqdnCache) resolvedFQDNs() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	fqdns := make([]string, 0, len(c.entries))
	for fqdn, entry := range c.entries {
		if entry.resolved {
			fqdns = append(fqdns, fqdn)
		}
	}
	return fqdns
}

// forEachResolved calls fn for every FQDN which was resolved at least once. fn must
// not call back into the fqdnCache.
func (c *fqdnCache) forEachResolved(fn func(fqdn string, meta dnsMeta)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for fqdn, entry := range c.entries {
		if entry.resolved {
			fn(fqdn, entry.meta)
		}
	}
}

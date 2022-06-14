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

package labelidentity

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/controller/types"
)

const (
	// Cluster scoped selectors are stored under empty Namespace in indice.
	emptyNamespace = ""
	policyIndex    = "policyIndex"
)

var (
	// eventChanSize is declared as a variable to allow overriding for testing.
	eventChanSize = 1000
	// labelRegex knows how to decompose a normalized label identity.
	labelRegex = regexp.MustCompile(`ns:(?P<nslabels>(.)*)&pod:(?P<podlabels>(.)*)`)
	nsIndex    = labelRegex.SubexpIndex("nslabels")
	podIndex   = labelRegex.SubexpIndex("podlabels")
)

// eventHandler is the registered callback for policy re-sync
type eventHandler func(policyKey string)

type Interface interface {
	// AddSelector adds or updates a selectorItem when a new selector is added to a policy.
	AddSelector(selector *types.GroupSelector, policyKey string) []uint32
	// DeleteSelector deletes or updates a selectorItem when a selector is deleted from a policy.
	DeleteSelector(selectorKey string, policyKey string)
	// GetLabelIdentityIDs retrieves the label identity IDs selected by the provided selectorItem keys.
	GetLabelIdentityIDs(selectorKey string) []uint32
	// SetPolicySelectors registers a policy's selectors with the index.
	SetPolicySelectors(selectors []*types.GroupSelector, policyKey string) []uint32
	// DeletePolicySelectors removes any selectors from referring to the policy being deleted.
	DeletePolicySelectors(policyKey string)
	// AddLabelIdentity adds LabelIdentity-ID mapping to the index.
	AddLabelIdentity(labelKey string, id uint32)
	// DeleteLabelIdentity deletes a LabelIdentity from the index.
	DeleteLabelIdentity(labelKey string)
	// AddEventHandler registers an eventHandler with the index.
	AddEventHandler(handler eventHandler)
	// Run starts the index.
	Run(stopCh <-chan struct{})
	// HasSynced returns true if the interface has been initialized with the full lists of LabelIdentities.
	HasSynced() bool
}

type selectorItemUpdateEvent string

const (
	selectorMatchedLabelAdd     selectorItemUpdateEvent = "labelAdd"
	selectorMatchedLabelDelete  selectorItemUpdateEvent = "labelDelete"
	selectorMatchedPolicyAdd    selectorItemUpdateEvent = "policyAdd"
	selectorMatchedPolicyDelete selectorItemUpdateEvent = "policyDelete"
)

// selectorItem represents a ClusterSet-scope selector from Antrea-native policies.
// It also stores the LabelIdentity keys that this selector currently selects, as well
// as the keys of Antrea-native policies that have this selector.
type selectorItem struct {
	selector *types.GroupSelector
	// Keys are the normalized labels of matching LabelIdentities
	labelIdentityKeys sets.String
	// Keys are the UIDs of the policies that have the selector in their specs.
	policyKeys sets.String
}

func (s *selectorItem) getKey() string {
	return s.selector.NormalizedName
}

// labelIdentityMatch is constructed from a LabelIdentity and used for matching
// between LabelIdentity and selectorItems. It also stores the current selectorItems
// that matches this LabelIdentity.
type labelIdentityMatch struct {
	id               uint32
	namespace        string
	namespaceLabels  map[string]string
	podLabels        map[string]string
	selectorItemKeys sets.String
}

// matches knows if a LabelIdentity matches a selectorItem.
func (l *labelIdentityMatch) matches(s *selectorItem) bool {
	selectorItemNamespace := s.selector.Namespace
	if selectorItemNamespace != emptyNamespace && selectorItemNamespace != l.namespace {
		return false
	}
	if s.selector.NamespaceSelector != nil && !s.selector.NamespaceSelector.Matches(labels.Set(l.namespaceLabels)) {
		return false
	}
	// At this stage Namespace has matched
	if s.selector.PodSelector != nil {
		return s.selector.PodSelector.Matches(labels.Set(l.podLabels))
	}
	// SelectorItem selects all when all selectors are missing.
	return true
}

// constructMapFromLabelString parses label string of format "app=client,env=dev" into a map.
func constructMapFromLabelString(s string) map[string]string {
	m := map[string]string{}
	kvs := strings.Split(s, ",")
	for _, kv := range kvs {
		kvpair := strings.Split(kv, "=")
		m[kvpair[0]] = kvpair[1]
	}
	return m
}

// newLabelIdentityMatch constructs a labelIdentityMatch from a normalized LabelIdentity string.
func newLabelIdentityMatch(labelIdentity string, id uint32) *labelIdentityMatch {
	labelMatches := labelRegex.FindStringSubmatch(labelIdentity)
	nsLabels := constructMapFromLabelString(labelMatches[nsIndex])
	podLabels := constructMapFromLabelString(labelMatches[podIndex])

	namespace := nsLabels[apiv1.LabelMetadataName]
	return &labelIdentityMatch{
		id:               id,
		namespace:        namespace,
		namespaceLabels:  nsLabels,
		podLabels:        podLabels,
		selectorItemKeys: sets.NewString(),
	}
}

// selectorItemKeyFunc knows how to get the key of a selectorItem.
func selectorItemKeyFunc(obj interface{}) (string, error) {
	sItem, ok := obj.(*selectorItem)
	if !ok {
		return "", fmt.Errorf("object is not of type *selectorItem: %v", obj)
	}
	return sItem.getKey(), nil
}

func newSelectorItemStore() cache.Indexer {
	indexers := cache.Indexers{
		cache.NamespaceIndex: func(obj interface{}) ([]string, error) {
			sItem, ok := obj.(*selectorItem)
			if !ok {
				return []string{}, nil
			}
			// sItem.Selector.Namespace == "" means it's a cluster scoped selector, we index it as it is.
			return []string{sItem.selector.Namespace}, nil
		},
		policyIndex: func(obj interface{}) ([]string, error) {
			sItem, ok := obj.(*selectorItem)
			if !ok {
				return []string{}, nil
			}
			return sItem.policyKeys.UnsortedList(), nil
		},
	}
	return cache.NewIndexer(selectorItemKeyFunc, indexers)
}

// LabelIdentityIndex implements Interface.
type LabelIdentityIndex struct {
	lock sync.RWMutex
	// labelIdentities stores all labelIdentityMatches, with the normalized labels of LabelIdentity as map key.
	labelIdentities map[string]*labelIdentityMatch
	// labelIdentityNamespaceIndex is an index from Namespace to LabelIdentity keys in that Namespace.
	labelIdentityNamespaceIndex map[string]sets.String
	// selectorItems stores all selectorItems, indexed by Namespace and policy keys.
	selectorItems cache.Indexer

	eventChan chan string
	// eventHandlers is a list of callbacks registered for policies to be re-processed due to
	// LabelIdentity events.
	eventHandlers []eventHandler

	// synced stores a boolean value, which tracks if the LabelIdentityIndex has been initialized with
	// the full lists of LabelIdentities.
	synced *atomic.Value
}

func NewLabelIdentityIndex() *LabelIdentityIndex {
	synced := &atomic.Value{}
	synced.Store(false)
	index := &LabelIdentityIndex{
		labelIdentities:             map[string]*labelIdentityMatch{},
		labelIdentityNamespaceIndex: map[string]sets.String{},
		selectorItems:               newSelectorItemStore(),
		eventChan:                   make(chan string, eventChanSize),
		eventHandlers:               []eventHandler{},
		synced:                      synced,
	}
	return index
}

func (i *LabelIdentityIndex) updateSelectorItem(sItem *selectorItem, updateType selectorItemUpdateEvent, updateKey string) {
	// Make a copy of selectorItem's fields as modifying the original object affects indexing.
	labelIdentities, policies := sItem.labelIdentityKeys.Union(nil), sItem.policyKeys.Union(nil)
	switch updateType {
	case selectorMatchedLabelAdd:
		labelIdentities.Insert(updateKey)
	case selectorMatchedLabelDelete:
		labelIdentities.Delete(updateKey)
	case selectorMatchedPolicyAdd:
		policies.Insert(updateKey)
	case selectorMatchedPolicyDelete:
		policies.Delete(updateKey)
	}
	// Construct a new selectorItem since objects got from ThreadSafeStore should be
	// read-only. Indexers will break otherwise.
	newSelectorItem := &selectorItem{
		selector:          sItem.selector,
		labelIdentityKeys: labelIdentities,
		policyKeys:        policies,
	}
	i.selectorItems.Update(newSelectorItem)
}

// AddSelector registers a selectorItem to policy mapping with the LabelIdentityIndex,
// and returns the list of LabelIdentity IDs that the selector selects.
func (i *LabelIdentityIndex) AddSelector(selector *types.GroupSelector, policyKey string) []uint32 {
	i.lock.Lock()
	defer i.lock.Unlock()

	selectorKey, selectorNS := selector.NormalizedName, selector.Namespace
	if s, exists, _ := i.selectorItems.GetByKey(selectorKey); exists {
		sItem := s.(*selectorItem)
		i.updateSelectorItem(sItem, selectorMatchedPolicyAdd, policyKey)
		return i.getMatchedLabelIdentityIDs(sItem)
	}
	sItem := &selectorItem{
		selector:          selector,
		labelIdentityKeys: sets.NewString(),
		policyKeys:        sets.NewString(policyKey),
	}
	i.selectorItems.Add(sItem)
	if selectorNS != emptyNamespace {
		// Scan for LabelIdentity matches in a specific Namespace.
		// Note that in multicluster context, the "Namespace sameness" concept applies, which means that
		// Namespaces with the same name are considered to be the same Namespace across the ClusterSet.
		// For more information, refer to
		// https://github.com/kubernetes/community/blob/master/sig-multicluster/namespace-sameness-position-statement.md
		labelIdentityKeys := i.labelIdentityNamespaceIndex[selectorNS]
		i.scanLabelIdentityMatches(labelIdentityKeys, sItem)
	} else {
		// Scan for LabelIdentity matches globally.
		for _, labelIdentityKeys := range i.labelIdentityNamespaceIndex {
			i.scanLabelIdentityMatches(labelIdentityKeys, sItem)
		}
	}
	return i.getMatchedLabelIdentityIDs(sItem)
}

// DeleteSelector removes a selectorItem from referring to the policy being deleted.
func (i *LabelIdentityIndex) DeleteSelector(selectorKey string, policyKey string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.deleteSelector(selectorKey, policyKey)
}

func (i *LabelIdentityIndex) deleteSelector(selectorKey string, policyKey string) {
	s, exists, _ := i.selectorItems.GetByKey(selectorKey)
	if !exists {
		return
	}
	sItem := s.(*selectorItem)
	if sItem.policyKeys.Equal(sets.NewString(policyKey)) {
		// delete the selectorItem and any LabelIdentity mappings if there's no
		// policy left that has the selector anymore.
		for lkey := range sItem.labelIdentityKeys {
			labelIdentity := i.labelIdentities[lkey]
			labelIdentity.selectorItemKeys.Delete(selectorKey)
		}
		i.selectorItems.Delete(sItem)
	} else {
		i.updateSelectorItem(sItem, selectorMatchedPolicyDelete, policyKey)
	}
}

// SetPolicySelectors registers ClusterSet-scope policy selectors with the labelIdentityIndex,
// and then retrieves all the LabelIdentity IDs that currently match these selectors.
func (i *LabelIdentityIndex) SetPolicySelectors(selectors []*types.GroupSelector, policyKey string) []uint32 {
	var labelIdentityIDs []uint32
	newSelectors := map[string]*types.GroupSelector{}
	for _, s := range selectors {
		klog.V(4).InfoS("Getting matched LabelIdentity for policy selector", "selector", s.NormalizedName, "policy", policyKey)
		newSelectors[s.NormalizedName] = s
	}
	originalSelectors := i.getPolicySelectors(policyKey)
	for selKey, sel := range newSelectors {
		if _, exists := originalSelectors[selKey]; exists {
			// These clusterset-scoped selectors are already bound to the policy in labelIdentityIndex.
			// We can simply read matched label identity IDs from the index.
			selectedLabelIDs := i.GetLabelIdentityIDs(selKey)
			labelIdentityIDs = append(labelIdentityIDs, selectedLabelIDs...)
			// Remove matched clusterset-scoped selectors of the policy before and after the update.
			// The selectors remaining in originalSelectors will need to be removed from the policy.
			delete(originalSelectors, selKey)
		} else {
			selectedLabelIDs := i.AddSelector(sel, policyKey)
			labelIdentityIDs = append(labelIdentityIDs, selectedLabelIDs...)
		}
	}
	// The policy no longer has these selectors.
	for selectorKey := range originalSelectors {
		i.DeleteSelector(selectorKey, policyKey)
	}
	// Dedup label identity IDs in-place.
	seen := map[uint32]struct{}{}
	idx := 0
	for _, id := range labelIdentityIDs {
		if _, exists := seen[id]; !exists {
			seen[id] = struct{}{}
			labelIdentityIDs[idx] = id
			idx++
		}
	}
	return labelIdentityIDs[:idx]
}

func (i *LabelIdentityIndex) getPolicySelectors(policyKey string) map[string]*types.GroupSelector {
	i.lock.RLock()
	defer i.lock.RUnlock()

	res := map[string]*types.GroupSelector{}
	selectors, _ := i.selectorItems.ByIndex(policyIndex, policyKey)
	for _, s := range selectors {
		sel := s.(*selectorItem)
		res[sel.getKey()] = sel.selector
	}
	return res
}

func (i *LabelIdentityIndex) DeletePolicySelectors(policyKey string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	selectors, _ := i.selectorItems.ByIndex(policyIndex, policyKey)
	for _, s := range selectors {
		sel := s.(*selectorItem)
		i.deleteSelector(sel.getKey(), policyKey)
	}
}

func (i *LabelIdentityIndex) GetLabelIdentityIDs(selectorKey string) []uint32 {
	i.lock.RLock()
	defer i.lock.RUnlock()

	if s, exists, _ := i.selectorItems.GetByKey(selectorKey); exists {
		sel := s.(*selectorItem)
		return i.getMatchedLabelIdentityIDs(sel)
	}
	return []uint32{}
}

func (i *LabelIdentityIndex) getMatchedLabelIdentityIDs(sItem *selectorItem) []uint32 {
	var ids []uint32
	for lKey := range sItem.labelIdentityKeys {
		labelIdentity := i.labelIdentities[lKey]
		ids = append(ids, labelIdentity.id)
	}
	return ids
}

func (i *LabelIdentityIndex) scanLabelIdentityMatches(labelIdentityKeys sets.String, sItem *selectorItem) {
	for lkey := range labelIdentityKeys {
		labelIdentity := i.labelIdentities[lkey]
		if labelIdentity.matches(sItem) {
			sItem.labelIdentityKeys.Insert(lkey)
			labelIdentity.selectorItemKeys.Insert(sItem.getKey())
		}
	}
}

func (i *LabelIdentityIndex) AddLabelIdentity(labelKey string, id uint32) {
	i.lock.Lock()
	defer i.lock.Unlock()

	existingLabelMatch, exists := i.labelIdentities[labelKey]
	if exists {
		if existingLabelMatch.id != id {
			existingLabelMatch.id = id
			i.notifyPoliciesForLabelIdentityUpdate(existingLabelMatch)
		}
		return
	}
	klog.V(2).InfoS("Adding new LabelIdentity", "label", labelKey)
	labelIdentityMatch := newLabelIdentityMatch(labelKey, id)
	i.labelIdentities[labelKey] = labelIdentityMatch
	if keys, ok := i.labelIdentityNamespaceIndex[labelIdentityMatch.namespace]; ok {
		keys.Insert(labelKey)
	} else {
		i.labelIdentityNamespaceIndex[labelIdentityMatch.namespace] = sets.NewString(labelKey)
	}
	i.scanSelectorItemMatches(labelIdentityMatch, labelKey)
}

func (i *LabelIdentityIndex) DeleteLabelIdentity(labelKey string) {
	i.lock.Lock()
	defer i.lock.Unlock()

	l, exists := i.labelIdentities[labelKey]
	if !exists {
		klog.V(2).InfoS("LabelIdentity is already deleted from the index", "label", labelKey)
		return
	}
	klog.V(2).InfoS("Deleting LabelIdentity", "label", labelKey)
	labelIdentityNamespace := l.namespace
	policyKeysToNotify := sets.NewString()
	for sKey := range l.selectorItemKeys {
		if s, exists, _ := i.selectorItems.GetByKey(sKey); exists {
			sItem := s.(*selectorItem)
			policyKeysToNotify = policyKeysToNotify.Union(sItem.policyKeys)
			i.updateSelectorItem(sItem, selectorMatchedLabelDelete, labelKey)
		}
	}
	delete(i.labelIdentities, labelKey)
	if labelKeys, ok := i.labelIdentityNamespaceIndex[labelIdentityNamespace]; ok {
		labelKeys.Delete(labelKey)
		if len(labelKeys) == 0 {
			// There are no more labelIdentities in that Namespace
			delete(i.labelIdentityNamespaceIndex, labelIdentityNamespace)
		}
	}
	i.notify(policyKeysToNotify)
}

func (i *LabelIdentityIndex) notify(policyKeys sets.String) {
	for k := range policyKeys {
		klog.V(2).InfoS("Adding policy to the resync chan", "policyKey", k)
		i.eventChan <- k
	}
}

func (i *LabelIdentityIndex) notifyPoliciesForLabelIdentityUpdate(l *labelIdentityMatch) {
	for sKey := range l.selectorItemKeys {
		if s, exists, _ := i.selectorItems.GetByKey(sKey); exists {
			sItem := s.(*selectorItem)
			i.notify(sItem.policyKeys)
		}
	}
}

// scanSelectorItemMatches scans all selectorItems that can possibly match the LabelIdentity.
// If there are new matches, all policies that possess the selectorItem will be notified as
// a new LabelIdentity ID will be matched for that policy.
func (i *LabelIdentityIndex) scanSelectorItemMatches(l *labelIdentityMatch, normalizedLabel string) {
	nsSelectors, _ := i.selectorItems.ByIndex(cache.NamespaceIndex, l.namespace)
	clusterSelectors, _ := i.selectorItems.ByIndex(cache.NamespaceIndex, emptyNamespace)
	allSelectors := append(nsSelectors, clusterSelectors...)
	for _, n := range allSelectors {
		sItem := n.(*selectorItem)
		if l.matches(sItem) {
			l.selectorItemKeys.Insert(sItem.getKey())
			i.updateSelectorItem(sItem, selectorMatchedLabelAdd, normalizedLabel)
			i.notify(sItem.policyKeys)
		}
	}
}

func (i *LabelIdentityIndex) AddEventHandler(handler eventHandler) {
	i.eventHandlers = append(i.eventHandlers, handler)
}

func (i *LabelIdentityIndex) HasSynced() bool {
	return i.synced.Load().(bool)
}

func (i *LabelIdentityIndex) setSynced(synced bool) {
	i.synced.Store(synced)
}

func (i *LabelIdentityIndex) Run(stopCh <-chan struct{}) {
	klog.Info("Starting LabelIdentityIndex")
	for {
		select {
		case <-stopCh:
			klog.Info("Stopping LabelIdentityIndex")
			return
		case policyKey := <-i.eventChan:
			for _, handler := range i.eventHandlers {
				handler(policyKey)
			}
		}
	}
}

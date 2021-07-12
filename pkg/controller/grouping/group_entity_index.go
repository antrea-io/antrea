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

package grouping

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
	utilsets "github.com/vmware-tanzu/antrea/pkg/util/sets"
)

const (
	// Cluster scoped selectors are stored under empty Namespace in the selectorItemIndex.
	emptyNamespace = ""
)

var (
	// eventChanSize is declared as a variable to allow overriding for testing.
	eventChanSize = 1000
)

type eventHandler func(group string)

// GroupType is a public type used to differentiate Groups.
type GroupType string

// Interface provides methods to query entities that a given group selects and groups that select a given entity.
// It maintains indexes between groups and entities to make the query efficient. It supports callers to register
// callbacks that will be called when a specific type of groups' entities are updated.
type Interface interface {
	// AddGroup adds or updates a group to the index. The caller can then get entities selected by this group.
	AddGroup(groupType GroupType, name string, selector *types.GroupSelector)
	// DeleteGroup deletes a group from the index.
	DeleteGroup(groupType GroupType, name string)
	// AddEventHandler registers an eventHandler for the given type of groups. When any Pod/ExternelEntity/Namespace
	// update affects the given kind of groups, the eventHandler will be called with the affected groups.
	// The eventHandler is supposed to execute quickly and not perform blocking operation. Blocking operation should be
	// deferred to a routine that is triggered by the eventHandler, like the eventHandler + workqueue pattern.
	AddEventHandler(groupType GroupType, handler eventHandler)
	// GetEntities returns the selected Pods or ExternalEntities for the given group.
	GetEntities(groupType GroupType, name string) ([]*v1.Pod, []*v1alpha2.ExternalEntity)
	// GetGroupsForPod returns the groups that select the given Pod.
	GetGroupsForPod(namespace, name string) (map[GroupType][]string, bool)
	// GetGroupsForExternalEntity returns the groups that select the given ExternalEntity.
	GetGroupsForExternalEntity(namespace, name string) (map[GroupType][]string, bool)
	// AddPod adds or updates a Pod to the index. If any existing groups are affected, eventHandlers will be called with
	// the affected groups.
	AddPod(pod *v1.Pod)
	// DeletePod deletes a Pod from the index. If any existing groups are affected, eventHandlers will be called with
	// the affected groups.
	DeletePod(pod *v1.Pod)
	// AddExternalEntity adds or updates an ExternalEntity to the index. If any existing groups are affected,
	// eventHandlers will be called with the affected groups.
	AddExternalEntity(ee *v1alpha2.ExternalEntity)
	// DeleteExternalEntity deletes an ExternalEntity from the index. If any existing groups are affected, eventHandlers
	// will be called with the affected groups.
	DeleteExternalEntity(ee *v1alpha2.ExternalEntity)
	// AddNamespace adds or updates a Namespace to the index. If any existing groups are affected, eventHandlers will be
	// called with the affected groups.
	AddNamespace(namespace *v1.Namespace)
	// DeleteNamespace deletes a Namespace to the index. If any existing groups are affected, eventHandlers will be
	// called with the affected groups.
	DeleteNamespace(namespace *v1.Namespace)
	// Run starts the index.
	Run(stopCh <-chan struct{})
	// HasSynced returns true if the interface has been initialized with the full lists of Pods, Namespaces, and
	// ExternalEntities.
	HasSynced() bool
}

// entityType is an internal type used to differentiate Pod from ExternalEntity.
type entityType int

const (
	podEntityType entityType = iota
	externalEntityType
)

// entityItem contains an entity (either Pod or ExternalEntity) and some relevant information.
type entityItem struct {
	// entity is either a Pod or an ExternalEntity.
	entity metav1.Object
	// labelItemKey is the key of the labelItem that the entityItem is associated with.
	// entityItems will be associated with the same labelItem if they have same Namespace, entityType, and labels.
	labelItemKey string
}

// labelItem represents an individual label set. It's the actual object that will be matched with label selectors.
// Entities of same type in same Namespace having same labels will share a labelItem.
type labelItem struct {
	// The label set that will be used for matching.
	labels labels.Set
	// The Namespace of the entities that share the labelItem.
	namespace string
	// The type of the entities that share the labelItem.
	entityType entityType
	// The keys of the entityItems that share the labelItem.
	entityItemKeys sets.String
	// The keys of the selectorItems that match the labelItem.
	selectorItemKeys sets.String
}

// groupItem contains a group's metadata and its selector.
type groupItem struct {
	// The type of the group.
	groupType GroupType
	// The name of the group. It must be unique within its own type.
	name string
	// The selector of the group.
	selector *types.GroupSelector
	// selectorItemKey is the key of the selectorItem that the groupItem is associated with.
	// groupItems will be associated with the same selectorItem if they have same selector.
	selectorItemKey string
}

// selectorItem represents an individual label selector. It's the actual object that will be matched with label sets.
// Groups having same label selector will share a selectorItem.
type selectorItem struct {
	// The label selector that will be used for matching.
	selector *types.GroupSelector
	// The keys of the groupItems that share the selectorItem.
	groupItemKeys sets.String
	// The keys of the labelItems that match the selectorItem.
	labelItemKeys sets.String
}

var _ Interface = &GroupEntityIndex{}

// GroupEntityIndex implements Interface.
//
// It abstracts label set and label selector from entities and groups and does actual matching against the formers to
// avoid redundant calculation given that most entities (Pod or ExternalEntity) actually share labels. For example, Pods
// that managed by a deployment controller have same labels.
//
// It maintains indexes between label set and label selector so that querying label sets that match a label selector and
// reversed queries can be performed with a constant time complexity. Indirectly, querying entities that match a group
// and reversed queries can be performed with same complexity.
//
// The relationship of the four items are like below:
// entityItem <===> labelItem <===> selectorItem <===> groupItem
type GroupEntityIndex struct {
	lock sync.RWMutex

	// entityItems stores all entityItems.
	entityItems map[string]*entityItem

	// labelItems stores all labelItems.
	labelItems map[string]*labelItem
	// labelItemIndex is nested map from entityType to Namespace to keys of labelItems.
	// It's used to filter potential labelItems when matching a Namespace scoped selectorItem.
	labelItemIndex map[entityType]map[string]sets.String

	// groupItems stores all groupItems.
	groupItems map[string]*groupItem

	// selectorItems stores all selectorItems.
	selectorItems map[string]*selectorItem
	// selectorItemIndex is nested map from entityType to Namespace to keys of selectorItems.
	// It's used to filter potential selectorItems when matching an labelItem.
	// Cluster scoped selectorItems are stored under empty Namespace "".
	selectorItemIndex map[entityType]map[string]sets.String

	// namespaceLabels stores label sets of all Namespaces.
	namespaceLabels map[string]labels.Set

	// eventHandlers is a map from group type to a list of handlers. When a type of group's updated, the corresponding
	// event handlers will be called with the group name provided.
	eventHandlers map[GroupType][]eventHandler

	// eventChan is channel used for calling eventHandlers asynchronously.
	eventChan chan string

	// synced stores a boolean value, which tracks if the GroupEntityIndex has been initialized with the full lists of
	// Pods, Namespaces, and ExternalEntities.
	synced *atomic.Value
}

// NewGroupEntityIndex creates a GroupEntityIndex.
func NewGroupEntityIndex() *GroupEntityIndex {
	synced := &atomic.Value{}
	synced.Store(false)
	index := &GroupEntityIndex{
		entityItems:       map[string]*entityItem{},
		groupItems:        map[string]*groupItem{},
		labelItems:        map[string]*labelItem{},
		labelItemIndex:    map[entityType]map[string]sets.String{podEntityType: {}, externalEntityType: {}},
		selectorItems:     map[string]*selectorItem{},
		selectorItemIndex: map[entityType]map[string]sets.String{podEntityType: {}, externalEntityType: {}},
		namespaceLabels:   map[string]labels.Set{},
		eventHandlers:     map[GroupType][]eventHandler{},
		eventChan:         make(chan string, eventChanSize),
		synced:            synced,
	}
	return index
}

func (i *GroupEntityIndex) GetEntities(groupType GroupType, name string) ([]*v1.Pod, []*v1alpha2.ExternalEntity) {
	gKey := getGroupItemKey(groupType, name)

	i.lock.RLock()
	defer i.lock.RUnlock()

	gItem, exists := i.groupItems[gKey]
	if !exists {
		return nil, nil
	}

	// Get the selectorItem the group is associated with.
	sItem, _ := i.selectorItems[gItem.selectorItemKey]
	var pods []*v1.Pod
	var externalEntities []*v1alpha2.ExternalEntity
	// Get the keys of the labelItems the selectorItem matches.
	for lKey := range sItem.labelItemKeys {
		lItem, _ := i.labelItems[lKey]
		// Collect the entityItems that share the labelItem.
		for entityItemKey := range lItem.entityItemKeys {
			eItem, _ := i.entityItems[entityItemKey]
			switch entity := eItem.entity.(type) {
			case *v1.Pod:
				pods = append(pods, entity)
			case *v1alpha2.ExternalEntity:
				externalEntities = append(externalEntities, entity)
			}
		}
	}
	return pods, externalEntities
}

func (i *GroupEntityIndex) GetGroupsForPod(namespace, name string) (map[GroupType][]string, bool) {
	return i.getGroups(podEntityType, namespace, name)
}

func (i *GroupEntityIndex) GetGroupsForExternalEntity(namespace, name string) (map[GroupType][]string, bool) {
	return i.getGroups(externalEntityType, namespace, name)
}

func (i *GroupEntityIndex) getGroups(entityType entityType, namespace, name string) (map[GroupType][]string, bool) {
	eKey := getEntityItemKeyByName(entityType, namespace, name)

	i.lock.RLock()
	defer i.lock.RUnlock()

	// Get the selectorItem the group is associated with.
	eItem, exists := i.entityItems[eKey]
	if !exists {
		return nil, false
	}

	groups := map[GroupType][]string{}
	lItem, _ := i.labelItems[eItem.labelItemKey]
	// Get the keys of the selectorItems the labelItem matches.
	for sKey := range lItem.selectorItemKeys {
		sItem, _ := i.selectorItems[sKey]
		// Collect the groupItems that share the selectorItem.
		for gKey := range sItem.groupItemKeys {
			gItem, _ := i.groupItems[gKey]
			groups[gItem.groupType] = append(groups[gItem.groupType], gItem.name)
		}
	}
	return groups, true
}

func (i *GroupEntityIndex) AddNamespace(namespace *v1.Namespace) {
	i.lock.Lock()
	defer i.lock.Unlock()

	namespaceLabels, exists := i.namespaceLabels[namespace.Name]
	// Do nothing if labels are not updated.
	if exists && labels.Equals(namespaceLabels, namespace.Labels) {
		return
	}

	i.namespaceLabels[namespace.Name] = namespace.Labels

	// Resync cluster scoped selectors as they may start or stop matching the Namespace because of the label update.
	for _, namespaceToSelector := range i.selectorItemIndex {
		// Cluster scoped selectors are stored under empty Namespace in the selectorItemIndex.
		selectorKeys, exists := namespaceToSelector[emptyNamespace]
		if !exists {
			continue
		}
		for sKey := range selectorKeys {
			sItem := i.selectorItems[sKey]
			// If the selector selects all Namespaces, it won't be affected.
			if sItem.selector.NamespaceSelector == nil || sItem.selector.NamespaceSelector.Empty() {
				continue
			}
			// By default, the selector selects Pods. It selects ExternalEntities only if ExternalEntitySelector is set
			// explicitly.
			entityType := podEntityType
			if sItem.selector.ExternalEntitySelector != nil {
				entityType = externalEntityType
			}
			// Only labelItems in this Namespace may be affected.
			if i.scanLabelItems(i.labelItemIndex[entityType][namespace.Name], sItem) {
				// Notify watchers if the selectorItem is updated.
				i.notify(sKey)
			}
		}
	}
}

func (i *GroupEntityIndex) DeleteNamespace(namespace *v1.Namespace) {
	i.lock.Lock()
	defer i.lock.Unlock()

	delete(i.namespaceLabels, namespace.Name)
}

// deleteEntityFromLabelItem disconnects an entityItem from a labelItem.
// The labelItem will be deleted if it's no longer used by any entityItem.
func (i *GroupEntityIndex) deleteEntityFromLabelItem(label, entity string) *labelItem {
	lItem, _ := i.labelItems[label]
	lItem.entityItemKeys.Delete(entity)
	// If the labelItem is still used by any entities, keep it. Otherwise delete it.
	if len(lItem.entityItemKeys) > 0 {
		return lItem
	}
	// Delete the labelItem itself.
	delete(i.labelItems, label)

	// Delete it from the labelItemIndex.
	i.labelItemIndex[lItem.entityType][lItem.namespace].Delete(label)
	if len(i.labelItemIndex[lItem.entityType][lItem.namespace]) == 0 {
		delete(i.labelItemIndex[lItem.entityType], lItem.namespace)
	}

	// Delete the labelItem from matched selectorItems.
	for selector := range lItem.selectorItemKeys {
		sItem := i.selectorItems[selector]
		sItem.labelItemKeys.Delete(label)
	}
	return lItem
}

// createLabelItem creates a labelItem based on the provided entityItem.
// It's called when there is no existing labelItem for a label set.
func (i *GroupEntityIndex) createLabelItem(entityType entityType, eItem *entityItem) *labelItem {
	lItem := &labelItem{
		labels:           eItem.entity.GetLabels(),
		namespace:        eItem.entity.GetNamespace(),
		entityType:       entityType,
		entityItemKeys:   sets.NewString(),
		selectorItemKeys: sets.NewString(),
	}
	// Create the labelItem.
	i.labelItems[eItem.labelItemKey] = lItem
	// Add it to the labelItemIndex.
	labelItemKeys, exists := i.labelItemIndex[entityType][lItem.namespace]
	if !exists {
		labelItemKeys = sets.NewString()
		i.labelItemIndex[entityType][lItem.namespace] = labelItemKeys
	}
	labelItemKeys.Insert(eItem.labelItemKey)

	// Scan potential selectorItems and associate the new labelItem with the matched ones.
	scanSelectorItems := func(selectorItemKeys sets.String) {
		for sKey := range selectorItemKeys {
			sItem := i.selectorItems[sKey]
			matched := i.match(lItem.entityType, lItem.labels, lItem.namespace, sItem.selector)
			if matched {
				sItem.labelItemKeys.Insert(eItem.labelItemKey)
				lItem.selectorItemKeys.Insert(sKey)
			}
		}
	}
	// SelectorItems in the same Namespace may match the labelItem.
	localSelectorItemKeys, _ := i.selectorItemIndex[entityType][eItem.entity.GetNamespace()]
	scanSelectorItems(localSelectorItemKeys)
	// Cluster scoped selectorItems may match the labelItem.
	clusterSelectorItemKeys, _ := i.selectorItemIndex[entityType][emptyNamespace]
	scanSelectorItems(clusterSelectorItemKeys)
	return lItem
}

func (i *GroupEntityIndex) AddPod(pod *v1.Pod) {
	i.addEntity(podEntityType, pod)
}

func (i *GroupEntityIndex) AddExternalEntity(ee *v1alpha2.ExternalEntity) {
	i.addEntity(externalEntityType, ee)
}

func (i *GroupEntityIndex) addEntity(entityType entityType, entity metav1.Object) {
	eKey := getEntityItemKey(entityType, entity)
	lKey := getLabelItemKey(entityType, entity)
	var oldLabelItem *labelItem
	var entityUpdated bool

	i.lock.Lock()
	defer i.lock.Unlock()

	eItem, exists := i.entityItems[eKey]
	if exists {
		entityUpdated = entityAttrsUpdated(eItem.entity, entity)
		eItem.entity = entity
		// If its label doesn't change, its labelItem won't change. We still need to dispatch the updates of the groups
		// that select the entity if the entity's attributes that we care about are updated.
		if eItem.labelItemKey == lKey {
			if entityUpdated {
				lItem := i.labelItems[eItem.labelItemKey]
				for sKey := range lItem.selectorItemKeys {
					i.notify(sKey)
				}
			}
			return
		}
		// Delete the Pod from the previous labelItem as its label is updated.
		oldLabelItem = i.deleteEntityFromLabelItem(eItem.labelItemKey, eKey)
		eItem.labelItemKey = lKey
	} else {
		entityUpdated = true
		eItem = &entityItem{
			entity:       entity,
			labelItemKey: lKey,
		}
		i.entityItems[eKey] = eItem
	}

	// Create a labelItem if it doesn't exist.
	lItem, exists := i.labelItems[lKey]
	if !exists {
		lItem = i.createLabelItem(entityType, eItem)
	}
	lItem.entityItemKeys.Insert(eKey)

	// Notify group updates.
	var affectedSelectorItemKeys sets.String
	if oldLabelItem != nil {
		// If entity is updated, all previously and currently matched selectors are affected. Otherwise only the
		// difference portion are affected.
		if entityUpdated {
			affectedSelectorItemKeys = lItem.selectorItemKeys.Union(oldLabelItem.selectorItemKeys)
		} else {
			affectedSelectorItemKeys = utilsets.SymmetricDifference(lItem.selectorItemKeys, oldLabelItem.selectorItemKeys)
		}
	} else {
		affectedSelectorItemKeys = lItem.selectorItemKeys
	}
	for sKey := range affectedSelectorItemKeys {
		i.notify(sKey)
	}
}

func (i *GroupEntityIndex) DeletePod(pod *v1.Pod) {
	i.deleteEntity(podEntityType, pod)
}

func (i *GroupEntityIndex) DeleteExternalEntity(ee *v1alpha2.ExternalEntity) {
	i.deleteEntity(externalEntityType, ee)
}

func (i *GroupEntityIndex) deleteEntity(entityType entityType, entity metav1.Object) {
	eKey := getEntityItemKey(entityType, entity)

	i.lock.Lock()
	defer i.lock.Unlock()

	eItem, exists := i.entityItems[eKey]
	if !exists {
		return
	}

	// Delete the entity from its associated labelItem and entityItems.
	lItem := i.deleteEntityFromLabelItem(eItem.labelItemKey, eKey)
	delete(i.entityItems, eKey)

	// All selectorItems that match the labelItem are affected.
	for sKey := range lItem.selectorItemKeys {
		i.notify(sKey)
	}
}

// deleteGroupFromSelectorItem disconnects a groupItem from a selectorItem.
// The selectorItem will be deleted if it's no longer used by any groupItem.
func (i *GroupEntityIndex) deleteGroupFromSelectorItem(sKey, gKey string) *selectorItem {
	sItem, _ := i.selectorItems[sKey]
	sItem.groupItemKeys.Delete(gKey)
	// If the selectorItem is still used by any groups, keep it. Otherwise delete it.
	if len(sItem.groupItemKeys) > 0 {
		return sItem
	}
	// Delete the selectorItem itself.
	delete(i.selectorItems, sKey)

	// Delete it from the selectorItemIndex.
	entityType := podEntityType
	if sItem.selector.ExternalEntitySelector != nil {
		entityType = externalEntityType
	}
	i.selectorItemIndex[entityType][sItem.selector.Namespace].Delete(sKey)
	if len(i.selectorItemIndex[entityType][sItem.selector.Namespace]) == 0 {
		delete(i.selectorItemIndex[entityType], sItem.selector.Namespace)
	}

	// Delete the selectorItem from matched labelItems.
	for lKey := range sItem.labelItemKeys {
		lItem := i.labelItems[lKey]
		lItem.selectorItemKeys.Delete(sKey)
	}
	return sItem
}

// createSelectorItem creates a selectorItem based on the provided groupItem.
// It's called when there is no existing selectorItem for a group selector.
func (i *GroupEntityIndex) createSelectorItem(gItem *groupItem) *selectorItem {
	sItem := &selectorItem{
		selector:      gItem.selector,
		groupItemKeys: sets.NewString(),
		labelItemKeys: sets.NewString(),
	}
	// Create the selectorItem.
	i.selectorItems[gItem.selectorItemKey] = sItem
	// Add it to the selectorItemIndex.
	entityType := podEntityType
	if gItem.selector.ExternalEntitySelector != nil {
		entityType = externalEntityType
	}
	selectorItemKeys, exists := i.selectorItemIndex[entityType][sItem.selector.Namespace]
	if !exists {
		selectorItemKeys = sets.NewString()
		i.selectorItemIndex[entityType][sItem.selector.Namespace] = selectorItemKeys
	}
	selectorItemKeys.Insert(gItem.selectorItemKey)

	// Scan potential labelItems and associates the new selectorItem with the matched ones.
	if sItem.selector.Namespace != "" {
		// The selector is Namespace scoped, it can only match labelItems in this Namespace.
		labelItemKeys, _ := i.labelItemIndex[entityType][sItem.selector.Namespace]
		i.scanLabelItems(labelItemKeys, sItem)
	} else if sItem.selector.NamespaceSelector != nil && !sItem.selector.NamespaceSelector.Empty() {
		// The selector is Cluster scoped and has non-empty NamespaceSelector, scan labelItems in a Namespace only if
		// the Namespace's labels match.
		for namespace, namespaceLabel := range i.namespaceLabels {
			if sItem.selector.NamespaceSelector.Matches(namespaceLabel) {
				i.scanLabelItems(i.labelItemIndex[entityType][namespace], sItem)
			}
		}
	} else {
		// The selector is Cluster scoped and match all Namespaces.
		for _, labelItemKeys := range i.labelItemIndex[entityType] {
			i.scanLabelItems(labelItemKeys, sItem)
		}
	}
	return sItem
}

// scanLabelItems scans potential labelItems and updates their association.
func (i *GroupEntityIndex) scanLabelItems(labelItemKeys sets.String, sItem *selectorItem) bool {
	updated := false
	for lKey := range labelItemKeys {
		lItem := i.labelItems[lKey]
		if i.match(lItem.entityType, lItem.labels, lItem.namespace, sItem.selector) {
			// Connect the selector and the label if they didn't match before, otherwise do nothing.
			if !sItem.labelItemKeys.Has(lKey) {
				sItem.labelItemKeys.Insert(lKey)
				lItem.selectorItemKeys.Insert(sItem.selector.NormalizedName)
				updated = true
			}
		} else {
			// Disconnect the selector and the label if they matched before, otherwise do nothing.
			if sItem.labelItemKeys.Has(lKey) {
				sItem.labelItemKeys.Delete(lKey)
				lItem.selectorItemKeys.Delete(sItem.selector.NormalizedName)
				updated = true
			}
		}
	}
	return updated
}

func (i *GroupEntityIndex) AddGroup(groupType GroupType, name string, selector *types.GroupSelector) {
	gKey := getGroupItemKey(groupType, name)
	sKey := getSelectorItemKey(selector)

	i.lock.Lock()
	defer i.lock.Unlock()

	gItem, exists := i.groupItems[gKey]
	if exists {
		// Its selector doesn't change, do nothing.
		if gItem.selectorItemKey == sKey {
			return
		}
		i.deleteGroupFromSelectorItem(gItem.selectorItemKey, gKey)
		gItem.selectorItemKey = sKey
		gItem.selector = selector
	} else {
		gItem = &groupItem{
			groupType:       groupType,
			name:            name,
			selector:        selector,
			selectorItemKey: sKey,
		}
		i.groupItems[gKey] = gItem
	}

	// Create a selectorItem if it doesn't exist.
	sItem, exists := i.selectorItems[sKey]
	if !exists {
		sItem = i.createSelectorItem(gItem)
	}
	sItem.groupItemKeys.Insert(gKey)
}

func (i *GroupEntityIndex) DeleteGroup(groupType GroupType, name string) {
	gKey := getGroupItemKey(groupType, name)

	i.lock.Lock()
	defer i.lock.Unlock()

	gItem, exists := i.groupItems[gKey]
	if !exists {
		return
	}

	// Delete the group from its associated selectorItem and groupItems.
	i.deleteGroupFromSelectorItem(gItem.selectorItemKey, gKey)
	delete(i.groupItems, gKey)
}

// notify notifies the affected groups to eventHandlers.
// It's supposed to be called with the lock held as it accesses the selectorItems. Normally the method shouldn't block
// as the event channel is buffered and the consumer Run should execute quickly. If it blocks in practice, we should
// review whether there are unexpected blocking eventHandlers, or consider moving the routine out of locking.
func (i *GroupEntityIndex) notify(selector string) {
	sItem := i.selectorItems[selector]
	for group := range sItem.groupItemKeys {
		i.eventChan <- group
	}
}

func (i *GroupEntityIndex) Run(stopCh <-chan struct{}) {
	klog.Info("Starting GroupEntityIndex")
	for {
		select {
		case <-stopCh:
			klog.Info("Stopping GroupEntityIndex")
			return
		case group := <-i.eventChan:
			parts := strings.Split(group, "/")
			groupType, name := GroupType(parts[0]), parts[1]
			for _, handler := range i.eventHandlers[groupType] {
				handler(name)
			}
		}
	}
}

func (i *GroupEntityIndex) AddEventHandler(groupType GroupType, handler eventHandler) {
	i.eventHandlers[groupType] = append(i.eventHandlers[groupType], handler)
}

func (i *GroupEntityIndex) HasSynced() bool {
	return i.synced.Load().(bool)
}

func (i *GroupEntityIndex) setSynced(synced bool) {
	i.synced.Store(synced)
}

func (i *GroupEntityIndex) match(entityType entityType, label labels.Set, namespace string, sel *types.GroupSelector) bool {
	objSelector := sel.PodSelector
	if entityType == externalEntityType {
		objSelector = sel.ExternalEntitySelector
	}
	if sel.Namespace != "" {
		if sel.Namespace != namespace {
			// Pods or ExternalEntities must be matched within the same Namespace.
			return false
		}
		if objSelector != nil && !objSelector.Matches(label) {
			// podSelector or externalEntitySelector exists but doesn't match the ExternalEntity or Pod's labels.
			return false
		}
		return true
	}
	if sel.NamespaceSelector != nil {
		if !sel.NamespaceSelector.Empty() {
			namespaceLabels, exists := i.namespaceLabels[namespace]
			if !exists {
				return false
			}
			if !sel.NamespaceSelector.Matches(namespaceLabels) {
				// Pod's Namespace does not match namespaceSelector.
				return false
			}
		}
		if objSelector != nil && !objSelector.Matches(label) {
			// ExternalEntity or Pod's Namespace matches namespaceSelector but
			// labels do not match the podSelector or externalEntitySelector.
			return false
		}
		return true
	}
	if objSelector != nil {
		// Selector only has a PodSelector/ExternalEntitySelector and no sel.Namespace.
		// Pods/ExternalEntities must be matched from all Namespaces.
		if !objSelector.Matches(label) {
			// pod/ee labels do not match PodSelector/ExternalEntitySelector.
			return false
		}
		return true
	}
	// The group selects nothing when all selectors are missing.
	return false
}

func entityAttrsUpdated(oldEntity, newEntity metav1.Object) bool {
	switch oldValue := oldEntity.(type) {
	case *v1.Pod:
		// For Pod, we only care about PodIP and NodeName update.
		// Some other attributes we care about are immutable, e.g. the named ContainerPort.
		newValue := newEntity.(*v1.Pod)
		if oldValue.Status.PodIP != newValue.Status.PodIP {
			return true
		}
		if oldValue.Spec.NodeName != newValue.Spec.NodeName {
			return true
		}
		return false
	case *v1alpha2.ExternalEntity:
		newValue := newEntity.(*v1alpha2.ExternalEntity)
		if !reflect.DeepEqual(oldValue.Spec, newValue.Spec) {
			return true
		}
		return false
	}
	return false
}

// getEntityItemKey returns the entity key used in entityItems.
func getEntityItemKey(entityType entityType, entity metav1.Object) string {
	return fmt.Sprint(entityType) + "/" + entity.GetNamespace() + "/" + entity.GetName()
}

// getEntityItemKeyByName returns the entity key used in entityItems.
func getEntityItemKeyByName(entityType entityType, namespace, name string) string {
	return fmt.Sprint(entityType) + "/" + namespace + "/" + name
}

// getLabelItemKey returns the label key used in labelItems.
func getLabelItemKey(entityType entityType, obj metav1.Object) string {
	return fmt.Sprint(entityType) + "/" + obj.GetNamespace() + "/" + labels.Set(obj.GetLabels()).String()
}

// getGroupItemKey returns the group key used in groupItems.
func getGroupItemKey(groupType GroupType, name string) string {
	return string(groupType) + "/" + name
}

// getSelectorItemKey returns the selector key used in selectorItems.
func getSelectorItemKey(selector *types.GroupSelector) string {
	return selector.NormalizedName
}

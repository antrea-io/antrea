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

package store

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/apiserver/storage/ram"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	ServiceIndex      = "service"
	ChildGroupIndex   = "childGroup"
	IPBlockGroupIndex = "hasIPBlocks"
	HasIPBlocks       = "true"
)

// GroupKeyFunc knows how to get the key of a Group.
func GroupKeyFunc(obj interface{}) (string, error) {
	group, ok := obj.(*antreatypes.Group)
	if !ok {
		return "", fmt.Errorf("object is not *types.Group: %v", obj)
	}
	return k8s.NamespacedName(group.SourceReference.Namespace, group.SourceReference.Name), nil
}

// NewGroupStore creates a store of Group.
func NewGroupStore() storage.Interface {
	indexers := cache.Indexers{
		cache.NamespaceIndex: func(obj interface{}) ([]string, error) {
			g, ok := obj.(*antreatypes.Group)
			if !ok || g.Selector == nil {
				return []string{}, nil
			}
			return []string{g.Selector.Namespace}, nil
		},
		ServiceIndex: func(obj interface{}) ([]string, error) {
			g, ok := obj.(*antreatypes.Group)
			if !ok || g.ServiceReference == nil {
				return []string{}, nil
			}
			return []string{k8s.NamespacedName(g.ServiceReference.Namespace, g.ServiceReference.Name)}, nil
		},
		ChildGroupIndex: func(obj interface{}) ([]string, error) {
			g, ok := obj.(*antreatypes.Group)
			if !ok {
				return []string{}, nil
			}
			if g.SourceReference.Namespace != "" {
				namespacedCG := make([]string, len(g.ChildGroups))
				for _, childGroup := range g.ChildGroups {
					namespacedCG = append(namespacedCG, g.SourceReference.Namespace+"/"+childGroup)
				}
				return namespacedCG, nil
			}
			return g.ChildGroups, nil
		},
		IPBlockGroupIndex: func(obj interface{}) ([]string, error) {
			g, ok := obj.(*antreatypes.Group)
			if !ok || len(g.IPBlocks) == 0 {
				return []string{}, nil
			}
			return []string{HasIPBlocks}, nil
		},
	}
	// genEventFunc is set to nil, thus watchers of this store will not be created.
	return ram.NewStore(GroupKeyFunc, indexers, nil, keyAndSpanSelectFunc, func() runtime.Object { return nil })
}

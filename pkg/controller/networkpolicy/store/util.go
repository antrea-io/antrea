// Copyright 2019 Antrea Authors
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
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
)

// filter returns whether the provided selectors matches the key and/or the nodeNames.
func filter(selectors *storage.Selectors, key string, nodeNames sets.String) bool {
	// If Key is present in selectors, the provided key must match it.
	if selectors.Key != "" && key != selectors.Key {
		return false
	}
	// If nodeName is present in selectors's Field selector, the provided nodeNames must contain it.
	if nodeName, found := selectors.Field.RequiresExactMatch("nodeName"); found {
		if !nodeNames.Has(nodeName) {
			return false
		}
	}
	return true
}

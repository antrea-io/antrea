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

package k8s

// NamespacedName generates the conventional K8s resource name,
// which connects namespace and name with "/".
func NamespacedName(namespace, name string) string {
	if namespace == "" {
		// Cluster scoped resources will contain empty namespace.
		return name
	}
	return namespace + "/" + name
}

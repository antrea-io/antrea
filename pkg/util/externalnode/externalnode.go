// Copyright 2022 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package externalnode

import "antrea.io/antrea/pkg/apis/crd/v1alpha1"

func GenExternalEntityName(externalNode *v1alpha1.ExternalNode) string {
	if len(externalNode.Spec.Interfaces) == 0 {
		return ""
	}
	// Only one network interface is supported now.
	// Other interfaces except interfaces[0] will be ignored if there are more than one interfaces.
	ifName := externalNode.Spec.Interfaces[0].Name
	if ifName == "" {
		return externalNode.Name
	} else {
		return externalNode.Name + "-" + ifName
	}
}

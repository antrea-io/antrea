// Copyright 2020 Antrea Authors
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

package v1beta1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type BundleStatus string

const (
	SupportBundleStatusNone       BundleStatus = "None"
	SupportBundleStatusCollecting BundleStatus = "Collecting"
	SupportBundleStatusCollected  BundleStatus = "Collected"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get,create,delete
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SupportBundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status   BundleStatus `json:"status,omitempty"`
	Sum      string       `json:"sum,omitempty"`
	Days     uint32       `json:"days,omitempty"`
	Size     uint32       `json:"size,omitempty"`
	Filepath string       `json:"-"`
}

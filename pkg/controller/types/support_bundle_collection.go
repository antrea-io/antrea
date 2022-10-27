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

package types

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

type SupportBundleCollection struct {
	SpanMeta
	// UID of the internal SupportBundleCollection.
	UID types.UID
	// Name of the internal SupportBundleCollection, must be unique across all Support Bundle types
	Name           string
	ExpiredAt      metav1.Time
	SinceTime      string
	FileServer     v1alpha1.BundleFileServer
	Authentication controlplane.BundleServerAuthConfiguration
}

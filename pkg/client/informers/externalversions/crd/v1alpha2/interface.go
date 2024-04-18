// Copyright 2024 Antrea Authors
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

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha2

import (
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// Egresses returns a EgressInformer.
	Egresses() EgressInformer
	// ExternalEntities returns a ExternalEntityInformer.
	ExternalEntities() ExternalEntityInformer
	// IPPools returns a IPPoolInformer.
	IPPools() IPPoolInformer
	// TrafficControls returns a TrafficControlInformer.
	TrafficControls() TrafficControlInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// Egresses returns a EgressInformer.
func (v *version) Egresses() EgressInformer {
	return &egressInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ExternalEntities returns a ExternalEntityInformer.
func (v *version) ExternalEntities() ExternalEntityInformer {
	return &externalEntityInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// IPPools returns a IPPoolInformer.
func (v *version) IPPools() IPPoolInformer {
	return &iPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// TrafficControls returns a TrafficControlInformer.
func (v *version) TrafficControls() TrafficControlInformer {
	return &trafficControlInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

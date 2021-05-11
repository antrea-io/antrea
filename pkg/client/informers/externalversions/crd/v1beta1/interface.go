// Copyright 2021 Antrea Authors
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

package v1beta1

import (
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// AntreaAgentInfos returns a AntreaAgentInfoInformer.
	AntreaAgentInfos() AntreaAgentInfoInformer
	// AntreaControllerInfos returns a AntreaControllerInfoInformer.
	AntreaControllerInfos() AntreaControllerInfoInformer
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

// AntreaAgentInfos returns a AntreaAgentInfoInformer.
func (v *version) AntreaAgentInfos() AntreaAgentInfoInformer {
	return &antreaAgentInfoInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// AntreaControllerInfos returns a AntreaControllerInfoInformer.
func (v *version) AntreaControllerInfos() AntreaControllerInfoInformer {
	return &antreaControllerInfoInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

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

package externalversions

import (
	"fmt"

	v1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	v1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=crd.antrea.io, Version=v1alpha1
	case v1alpha1.SchemeGroupVersion.WithResource("bgppolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha1().BGPPolicies().Informer()}, nil
	case v1alpha1.SchemeGroupVersion.WithResource("externalnodes"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha1().ExternalNodes().Informer()}, nil
	case v1alpha1.SchemeGroupVersion.WithResource("nodelatencymonitors"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha1().NodeLatencyMonitors().Informer()}, nil
	case v1alpha1.SchemeGroupVersion.WithResource("packetcaptures"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha1().PacketCaptures().Informer()}, nil
	case v1alpha1.SchemeGroupVersion.WithResource("supportbundlecollections"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha1().SupportBundleCollections().Informer()}, nil

		// Group=crd.antrea.io, Version=v1alpha2
	case v1alpha2.SchemeGroupVersion.WithResource("externalentities"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha2().ExternalEntities().Informer()}, nil
	case v1alpha2.SchemeGroupVersion.WithResource("ippools"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha2().IPPools().Informer()}, nil
	case v1alpha2.SchemeGroupVersion.WithResource("trafficcontrols"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1alpha2().TrafficControls().Informer()}, nil

		// Group=crd.antrea.io, Version=v1beta1
	case v1beta1.SchemeGroupVersion.WithResource("antreaagentinfos"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().AntreaAgentInfos().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("antreacontrollerinfos"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().AntreaControllerInfos().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("clustergroups"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().ClusterGroups().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("clusternetworkpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().ClusterNetworkPolicies().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("egresses"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().Egresses().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("externalippools"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().ExternalIPPools().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("groups"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().Groups().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("ippools"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().IPPools().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("networkpolicies"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().NetworkPolicies().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("tiers"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().Tiers().Informer()}, nil
	case v1beta1.SchemeGroupVersion.WithResource("traceflows"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Crd().V1beta1().Traceflows().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}

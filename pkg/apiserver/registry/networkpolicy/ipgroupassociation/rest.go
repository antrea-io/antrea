// Copyright 2023 Antrea Authors
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

package ipgroupassociation

import (
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"
	coreinformers "k8s.io/client-go/informers/core/v1"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	ga "antrea.io/antrea/pkg/apiserver/registry/networkpolicy/groupassociation"
	crdv1a2informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/features"
)

type REST struct {
	podInformer  coreinformers.PodInformer
	eeInformer   crdv1a2informers.ExternalEntityInformer
	ipbQuerier   ipBlockGroupAssociationQuerier
	groupQuerier ga.GroupAssociationQuerier
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.Getter               = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

// NewREST returns a REST object that will work against API services.
func NewREST(podQuerier coreinformers.PodInformer,
	eeQuerier crdv1a2informers.ExternalEntityInformer,
	ipbQuerier ipBlockGroupAssociationQuerier,
	groupQuerier ga.GroupAssociationQuerier) *REST {
	return &REST{podQuerier, eeQuerier, ipbQuerier, groupQuerier}
}

type ipBlockGroupAssociationQuerier interface {
	GetAssociatedIPBlockGroups(ip net.IP) []types.Group
}

func (r *REST) New() runtime.Object {
	return &controlplane.IPGroupAssociation{}
}

func (r *REST) Destroy() {
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	parsedIP := net.ParseIP(name)
	if parsedIP == nil {
		return nil, errors.NewBadRequest("not a valid IP address")
	}
	matchedGroups := map[controlplane.GroupReference]struct{}{}
	addToGroupList := func(groups []types.Group) {
		for _, g := range groups {
			item := controlplane.GroupReference{
				Namespace: g.SourceReference.Namespace,
				Name:      g.SourceReference.Name,
				UID:       g.UID,
			}
			matchedGroups[item] = struct{}{}
		}
	}
	addAssociatedGroups := func(obj metav1.Object) {
		groups := r.groupQuerier.GetAssociatedGroups(obj.GetName(), obj.GetNamespace())
		addToGroupList(groups)
	}
	matchedPod := r.getAssociatedPod(parsedIP.String())
	if matchedPod != nil {
		addAssociatedGroups(matchedPod)
	} else {
		// The namespace/name might correspond to an ExternalEntity rather than a Pod
		matchedExternalEntities := r.getAssociatedExternalEntities(parsedIP.String())
		for i := range matchedExternalEntities {
			addAssociatedGroups(matchedExternalEntities[i])
		}
	}
	// Check for ipBlock group association no matter the Pod/EE query result is
	ipBlockGroups := r.ipbQuerier.GetAssociatedIPBlockGroups(parsedIP)
	addToGroupList(ipBlockGroups)
	groupList := make([]controlplane.GroupReference, len(matchedGroups))
	i := 0
	for g := range matchedGroups {
		groupList[i] = g
		i++
	}
	members := &controlplane.IPGroupAssociation{AssociatedGroups: groupList}
	return members, nil
}

func (r *REST) getAssociatedPod(ip string) *v1.Pod {
	pods, _ := r.podInformer.Informer().GetIndexer().ByIndex(grouping.PodIPsIndex, ip)
	if len(pods) > 0 {
		pod, _ := pods[0].(*v1.Pod)
		return pod
	}
	return nil
}

func (r *REST) getAssociatedExternalEntities(ip string) []*v1alpha2.ExternalEntity {
	if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return nil
	}
	eeObjs, _ := r.eeInformer.Informer().GetIndexer().ByIndex(grouping.ExternalEntityIPsIndex, ip)
	if len(eeObjs) == 0 {
		return nil
	}
	ees := make([]*v1alpha2.ExternalEntity, len(eeObjs))
	for i := 0; i < len(eeObjs); i++ {
		ee, _ := eeObjs[i].(*v1alpha2.ExternalEntity)
		ees[i] = ee
	}
	return ees
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "ipgroupassociation"
}

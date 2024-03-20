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

package multicastgroup

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metatable "k8s.io/apimachinery/pkg/api/meta/table"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/rest"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	tableColumnDefinitions = []metav1.TableColumnDefinition{
		{Name: "Group", Type: "string", Format: "name", Description: "IP of multicast group."},
		{Name: "Pods", Type: "string", Description: "List of Pods the has joined the multicast group."},
	}
)

type REST struct {
	statsProvider statsProvider
}

// NewREST returns a REST object that will work against API services.
func NewREST(p statsProvider) *REST {
	return &REST{p}
}

var (
	_ rest.Storage              = &REST{}
	_ rest.Scoper               = &REST{}
	_ rest.Getter               = &REST{}
	_ rest.Lister               = &REST{}
	_ rest.SingularNameProvider = &REST{}
)

type statsProvider interface {
	ListMulticastGroups() []statsv1alpha1.MulticastGroup
	GetMulticastGroup(name string) (*statsv1alpha1.MulticastGroup, bool)
}

func (r *REST) New() runtime.Object {
	return &statsv1alpha1.MulticastGroup{}
}

func (r *REST) Destroy() {
}

func (r *REST) NewList() runtime.Object {
	return &statsv1alpha1.MulticastGroupList{}
}

func (r *REST) List(ctx context.Context, options *internalversion.ListOptions) (runtime.Object, error) {
	if !features.DefaultFeatureGate.Enabled(features.Multicast) {
		return &statsv1alpha1.MulticastGroupList{}, nil
	}
	multicastGroups := &statsv1alpha1.MulticastGroupList{
		Items: r.statsProvider.ListMulticastGroups(),
	}
	return multicastGroups, nil
}

func (r *REST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	if !features.DefaultFeatureGate.Enabled(features.Multicast) {
		return &statsv1alpha1.MulticastGroup{}, nil
	}
	multicastGroup, exists := r.statsProvider.GetMulticastGroup(name)
	if !exists {
		return nil, errors.NewNotFound(statsv1alpha1.Resource("multicastgroup"), name)
	}
	return multicastGroup, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	table := &metav1.Table{
		ColumnDefinitions: tableColumnDefinitions,
	}
	if m, err := meta.ListAccessor(obj); err == nil {
		table.ResourceVersion = m.GetResourceVersion()
		table.Continue = m.GetContinue()
		table.RemainingItemCount = m.GetRemainingItemCount()
	} else {
		if m, err := meta.CommonAccessor(obj); err == nil {
			table.ResourceVersion = m.GetResourceVersion()
		}
	}

	var err error
	table.Rows, err = metatable.MetaToTableRow(obj, func(obj runtime.Object, m metav1.Object, name, age string) ([]interface{}, error) {
		stats := obj.(*statsv1alpha1.MulticastGroup)
		return []interface{}{stats.Group, formatPodReferenceList(stats.Pods, 3)}, nil
	})
	return table, err
}

// formatPodReferenceList formats a list of PodReference and cut it if it encodes more than 3 pods.
// Example: formatPodReferenceList(pods with len 13)
// apodNamespace/apodName,bpodNamespace/bpodName,bpodNamespace/bpodName + 10 more...
func formatPodReferenceList(pods []statsv1alpha1.PodReference, max int) string {
	count := len(pods)
	if count > max {
		pods = pods[:max]
	}
	list := make([]string, 0, len(pods))
	for _, pod := range pods {
		list = append(list, k8s.NamespacedName(pod.Namespace, pod.Name))
	}
	ret := strings.Join(list, ",")
	if count > max {
		return fmt.Sprintf("%s + %d more...", ret, count-max)
	}
	if ret == "" {
		ret = "<none>"
	}
	return ret
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) GetSingularName() string {
	return "multicastgroup"
}

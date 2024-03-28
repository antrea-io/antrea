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

package addressgroup

import (
	"io"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/kubectl/pkg/cmd/get"
	"k8s.io/kubectl/pkg/scheme"

	"antrea.io/antrea/pkg/antctl/transform"
	"antrea.io/antrea/pkg/antctl/transform/common"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/util/printers"
)

type Response struct {
	Name  string               `json:"name" yaml:"name"`
	Pods  []common.GroupMember `json:"pods,omitempty"`
	Nodes []common.GroupMember `json:"nodes,omitempty"`
}

func listTransform(l interface{}, opts map[string]string) (interface{}, error) {
	groupsList := l.(*cpv1beta.AddressGroupList)
	if len(groupsList.Items) == 0 {
		return "", nil
	}
	sortField := opts["sort-by"]
	if sortField == "" {
		sortField = ".metadata.name"
	}

	addressGroupRuntimeObjectList, _ := meta.ExtractList(groupsList)
	if _, err := get.SortObjects(scheme.Codecs.UniversalDecoder(), addressGroupRuntimeObjectList, sortField); err != nil {
		return "", err
	}

	result := make([]Response, 0, len(groupsList.Items))
	for i := range addressGroupRuntimeObjectList {
		o, _ := objectTransform(addressGroupRuntimeObjectList[i], opts)
		result = append(result, o.(Response))
	}
	return result, nil
}

func objectTransform(o interface{}, _ map[string]string) (interface{}, error) {
	group := o.(*cpv1beta.AddressGroup)
	var pods, nodes []common.GroupMember
	for _, member := range group.GroupMembers {
		gm := common.GroupMemberTransform(member)
		if member.Node != nil {
			nodes = append(nodes, gm)
			continue
		}
		pods = append(pods, gm)
	}
	return Response{Name: group.Name, Pods: pods, Nodes: nodes}, nil
}

func Transform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.AddressGroup{}),
		reflect.TypeOf(cpv1beta.AddressGroupList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAME", "POD-IPS", "NODE-IPS"}
}

func (r Response) GetPodIPs(maxColumnLength int) string {
	list := make([]string, len(r.Pods))
	for i, pod := range r.Pods {
		list[i] = pod.IP
	}
	return printers.GenerateTableElementWithSummary(list, maxColumnLength)
}

func (r Response) GetNodeIPs(maxColumnLength int) string {
	list := make([]string, len(r.Nodes))
	for i, node := range r.Nodes {
		list[i] = node.IP
	}
	return printers.GenerateTableElementWithSummary(list, maxColumnLength)
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Name, r.GetPodIPs(maxColumnLength), r.GetNodeIPs(maxColumnLength)}
}

func (r Response) SortRows() bool {
	return true
}

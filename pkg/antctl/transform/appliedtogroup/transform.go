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

package appliedtogroup

import (
	"io"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/kubectl/pkg/cmd/get"
	"k8s.io/kubectl/pkg/scheme"

	"antrea.io/antrea/pkg/antctl/transform"
	"antrea.io/antrea/pkg/antctl/transform/common"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type Response struct {
	Name    string               `json:"name" yaml:"name"`
	Members []common.GroupMember `json:"members,omitempty"`
}

func listTransform(l interface{}, opts map[string]string) (interface{}, error) {
	groupsList := l.(*cpv1beta.AppliedToGroupList)
	if len(groupsList.Items) == 0 {
		return "", nil
	}
	sortField := opts["sort-by"]
	if sortField == "" {
		sortField = ".metadata.name"
	}

	appliedToGroupRuntimeObjectList, _ := meta.ExtractList(groupsList)
	if _, err := get.SortObjects(scheme.Codecs.UniversalDecoder(), appliedToGroupRuntimeObjectList, sortField); err != nil {
		return "", err
	}

	result := make([]Response, 0, len(groupsList.Items))
	for i := range appliedToGroupRuntimeObjectList {
		o, _ := objectTransform(appliedToGroupRuntimeObjectList[i], opts)
		result = append(result, o.(Response))
	}
	return result, nil
}

func objectTransform(o interface{}, _ map[string]string) (interface{}, error) {
	group := o.(*cpv1beta.AppliedToGroup)
	var members []common.GroupMember
	for _, member := range group.GroupMembers {
		members = append(members, common.GroupMemberTransform(member))
	}
	return Response{Name: group.GetName(), Members: members}, nil
}

func Transform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.AppliedToGroup{}),
		reflect.TypeOf(cpv1beta.AppliedToGroupList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader(_ string) []string {
	return []string{"NAME", "PODS", "EXTERNAL-ENTITIES"}
}

func (r Response) getNames(maxColumnLength int, memberType string) string {
	list := make([]string, len(r.Members))
	for i, member := range r.Members {
		if member.Pod != nil && memberType == "PODS" {
			list[i] = member.Pod.Namespace + "/" + member.Pod.Name
		} else if member.ExternalEntity != nil && memberType == "EXTERNAL-ENTITIES" {
			list[i] = member.ExternalEntity.Namespace + "/" + member.ExternalEntity.Name
		}
	}
	return common.GenerateTableElementWithSummary(list, maxColumnLength)
}

func (r Response) GetTableRow(maxColumnLength int, _ string) []string {
	return []string{r.Name, r.getNames(maxColumnLength, "PODS"), r.getNames(maxColumnLength, "EXTERNAL-ENTITIES")}
}

func (r Response) SortRows() bool {
	return true
}

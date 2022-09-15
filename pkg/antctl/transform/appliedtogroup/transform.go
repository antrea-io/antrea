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

import ( //"io"
	//"reflect"
	//"sort"
	//"antrea.io/antrea/pkg/antctl/transform"
	"antrea.io/antrea/pkg/antctl/transform/common"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type Response struct {
	Name string               `json:"name" yaml:"name"`
	Pods []common.GroupMember `json:"pods,omitempty"`
}

/*func listTransform(l interface{}, opts map[string]string) (interface{}, error) {
	groups := l.(*cpv1beta.AppliedToGroupList)
	sortBy := ""
	if sb, ok := opts["sort-by"]; ok {
		sortBy = sb
	}
	apsorter := &Apsorter{
		appliedtogroups: groups.Items,
		sortBy:          sortBy,
	}
	sort.Sort(apsorter)

	result := make([]Response, 0, len(groups.Items))
	for i := range apsorter.appliedtogroups {
		o, _ := objectTransform(&apsorter.appliedtogroups[i], opts)
		result = append(result, o.(Response))
	}
	return result, nil
}

func objectTransform(o interface{}, _ map[string]string) (interface{}, error) {
	group := o.(*cpv1beta.AppliedToGroup)
	var pods []common.GroupMember
	for _, pod := range group.GroupMembers {
		pods = append(pods, common.GroupMemberTransform(pod))
	}
	return Response{Name: group.GetName(), Pods: pods}, nil
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
*/
/*const sortBycreationtime = "CreationTimestamp"

type TimeSlice []time.Time
*/
type Apsorter struct {
	Appliedtogroups []cpv1beta.AppliedToGroup
	SortBy          string
}

/*
func (aps *Apsorter) Len() int { return len(aps.Appliedtogroups) }
func (aps *Apsorter) Swap(i, j int) {
	aps.Appliedtogroups[i], aps.Appliedtogroups[j] = aps.Appliedtogroups[j], aps.Appliedtogroups[i]
}

func (aps *Apsorter) Less(i, j int) bool {
	switch aps.SortBy {
	case sortBycreationtime:
		return aps.Appliedtogroups[i].CreationTimestamp.Before(&aps.Appliedtogroups[j].CreationTimestamp)
	default:
		return aps.Appliedtogroups[i].Name < aps.Appliedtogroups[j].Name
	}
}
*/
var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAME", "PODS"}
}

func (r Response) GetPodNames(maxColumnLength int) string {
	list := make([]string, len(r.Pods))
	for i, pod := range r.Pods {
		list[i] = pod.Pod.Namespace + "/" + pod.Pod.Name
	}
	return common.GenerateTableElementWithSummary(list, maxColumnLength)
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Name, r.GetPodNames(maxColumnLength)}
}

func (r Response) SortRows() bool {
	return true
}

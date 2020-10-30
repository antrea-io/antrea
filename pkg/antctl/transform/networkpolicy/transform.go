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

package networkpolicy

import (
	"io"
	"reflect"
	"strconv"

	"github.com/vmware-tanzu/antrea/pkg/antctl/transform"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

type Response struct {
	*cpv1beta.NetworkPolicy
}

func objectTransform(o interface{}) (interface{}, error) {
	return Response{o.(*cpv1beta.NetworkPolicy)}, nil
}

func listTransform(l interface{}) (interface{}, error) {
	policyList := l.(*cpv1beta.NetworkPolicyList)
	result := make([]Response, 0, len(policyList.Items))
	for i := range policyList.Items {
		o, _ := objectTransform(&policyList.Items[i])
		result = append(result, o.(Response))
	}
	return result, nil
}

func Transform(reader io.Reader, single bool) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.NetworkPolicy{}),
		reflect.TypeOf(cpv1beta.NetworkPolicyList{}),
		objectTransform,
		listTransform,
	)(reader, single)
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAME", "APPLIED-TO", "RULES", "SOURCE"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Name, common.GenerateTableElementWithSummary(r.AppliedToGroups, maxColumnLength), strconv.Itoa(len(r.Rules)), r.SourceRef.ToString()}
}

func (r Response) SortRows() bool {
	return true
}

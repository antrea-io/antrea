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
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/rule"
	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

type Response struct {
	Name            string          `json:"name" yaml:"name"`
	Rules           []rule.Response `json:"rules" yaml:"rules"`
	AppliedToGroups []string        `json:"appliedToGroups" yaml:"appliedToGroups"`
}

func objectTransform(o interface{}) (interface{}, error) {
	policy := o.(*networkingv1beta1.NetworkPolicy)
	rules, _ := rule.ObjectTransform(&policy.Rules)
	if policy.AppliedToGroups == nil {
		policy.AppliedToGroups = []string{}
	}
	return Response{
		Name:            policy.Name,
		Rules:           rules.([]rule.Response),
		AppliedToGroups: policy.AppliedToGroups,
	}, nil
}

func listTransform(l interface{}) (interface{}, error) {
	policyList := l.(*networkingv1beta1.NetworkPolicyList)
	result := []Response{}
	for _, item := range policyList.Items {
		o, _ := objectTransform(&item)
		result = append(result, o.(Response))
	}
	return result, nil
}

func Transform(reader io.Reader, single bool) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(networkingv1beta1.NetworkPolicy{}),
		reflect.TypeOf(networkingv1beta1.NetworkPolicyList{}),
		objectTransform,
		listTransform,
	)(reader, single)
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAME", "APPLIED-TO", "RULES"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Name, common.GenerateTableElementWithSummary(r.AppliedToGroups, maxColumnLength), strconv.Itoa(len(r.Rules))}
}

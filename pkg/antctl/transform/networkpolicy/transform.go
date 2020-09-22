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
	cpv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
)

type Response struct {
	NameSpace       string                      `json:"namespace" yaml:"namespace"`
	Name            string                      `json:"name" yaml:"name"`
	TierPriority    int32                       `json:"tierPriority" yaml:"tierPriority"`
	Priority        float64                     `json:"priority" yaml:"priority"`
	Rules           []rule.Response             `json:"rules" yaml:"rules"`
	AppliedToGroups []string                    `json:"appliedToGroups" yaml:"appliedToGroups"`
	SourceType      cpv1beta1.NetworkPolicyType `json:"sourceNetworkPolicyType" yaml:"sourceNetworkPolicyType"`
}

func objectTransform(o interface{}) (interface{}, error) {
	policy := o.(*cpv1beta1.NetworkPolicy)
	rules, _ := rule.ObjectTransform(&policy.Rules)
	if policy.AppliedToGroups == nil {
		policy.AppliedToGroups = []string{}
	}

	if policy.SourceRef.Type == cpv1beta1.K8sNetworkPolicy {
		return Response{
			NameSpace:       policy.Namespace,
			Name:            policy.Name,
			TierPriority:    0,
			Priority:        0,
			Rules:           rules.([]rule.Response),
			AppliedToGroups: policy.AppliedToGroups,
			SourceType:      policy.SourceRef.Type,
		}, nil
	}

	return Response{
		NameSpace:       policy.Namespace,
		Name:            policy.Name,
		TierPriority:    *policy.TierPriority,
		Priority:        *policy.Priority,
		Rules:           rules.([]rule.Response),
		AppliedToGroups: policy.AppliedToGroups,
		SourceType:      policy.SourceRef.Type,
	}, nil
}

func listTransform(l interface{}) (interface{}, error) {
	policyList := l.(*cpv1beta1.NetworkPolicyList)
	result := []Response{}
	for _, item := range policyList.Items {
		o, _ := objectTransform(&item)
		result = append(result, o.(Response))
	}
	return result, nil
}

func Transform(reader io.Reader, single bool) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta1.NetworkPolicy{}),
		reflect.TypeOf(cpv1beta1.NetworkPolicyList{}),
		objectTransform,
		listTransform,
	)(reader, single)
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME", "APPLIED-TO", "RULES", "SOURCE-TYPE"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.NameSpace, r.Name, common.GenerateTableElementWithSummary(r.AppliedToGroups, maxColumnLength), strconv.Itoa(len(r.Rules)), string(r.SourceType)}
}

func (r Response) SortRows() bool {
	return true
}

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
	"sort"
	"strconv"

	"github.com/vmware-tanzu/antrea/pkg/antctl/transform"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy"
)

type Response struct {
	*cpv1beta.NetworkPolicy
}

func objectTransform(o interface{}, _ map[string]string) (interface{}, error) {
	return Response{o.(*cpv1beta.NetworkPolicy)}, nil
}

func listTransform(l interface{}, opts map[string]string) (interface{}, error) {
	policyList := l.(*cpv1beta.NetworkPolicyList)
	sortBy := ""
	if sb, ok := opts["sort-by"]; ok {
		sortBy = sb
	}
	npSorter := &NPSorter{
		networkPolicies: policyList.Items,
		sortBy:          sortBy,
	}
	sort.Sort(npSorter)
	result := make([]Response, 0, len(policyList.Items))
	for i := range npSorter.networkPolicies {
		o, _ := objectTransform(&npSorter.networkPolicies[i], opts)
		result = append(result, o.(Response))
	}
	return result, nil
}

func Transform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(cpv1beta.NetworkPolicy{}),
		reflect.TypeOf(cpv1beta.NetworkPolicyList{}),
		objectTransform,
		listTransform,
		opts,
	)(reader, single)
}

const sortByEffectivePriority = "effectivePriority"

// Compute a tierPriority value in between the application tier and the baseline tier,
// which can be used to sort all policies by tier.
var effectiveTierPriorityK8sNP = (networkpolicy.DefaultTierPriority + networkpolicy.BaselineTierPriority) / 2

type NPSorter struct {
	networkPolicies []cpv1beta.NetworkPolicy
	sortBy          string
}

func (nps *NPSorter) Len() int { return len(nps.networkPolicies) }
func (nps *NPSorter) Swap(i, j int) {
	nps.networkPolicies[i], nps.networkPolicies[j] = nps.networkPolicies[j], nps.networkPolicies[i]
}
func (nps *NPSorter) Less(i, j int) bool {
	switch nps.sortBy {
	case sortByEffectivePriority:
		var ti, tj int32
		if nps.networkPolicies[i].TierPriority == nil {
			ti = effectiveTierPriorityK8sNP
		} else {
			ti = *nps.networkPolicies[i].TierPriority
		}
		if nps.networkPolicies[j].TierPriority == nil {
			tj = effectiveTierPriorityK8sNP
		} else {
			tj = *nps.networkPolicies[j].TierPriority
		}
		if ti != tj {
			return ti < tj
		}
		pi, pj := nps.networkPolicies[i].Priority, nps.networkPolicies[j].Priority
		if pi != nil && pj != nil && *pi != *pj {
			return *pi < *pj
		}
		fallthrough
	default:
		// Do not need a tie-breaker here since NetworkPolicy names are set as UID
		// of the source policy and will be unique.
		return nps.networkPolicies[i].Name < nps.networkPolicies[j].Name
	}
}

func priorityToString(p interface{}) string {
	if reflect.ValueOf(p).IsNil() {
		return ""
	} else if pInt32, ok := p.(*int32); ok {
		return strconv.Itoa(int(*pInt32))
	} else {
		pFloat64, _ := p.(*float64)
		return strconv.FormatFloat(*pFloat64, 'f', -1, 64)
	}
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAME", "APPLIED-TO", "RULES", "SOURCE", "TIER-PRIORITY", "PRIORITY"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{
		r.Name, common.GenerateTableElementWithSummary(r.AppliedToGroups, maxColumnLength),
		strconv.Itoa(len(r.Rules)), r.SourceRef.ToString(),
		priorityToString(r.TierPriority), priorityToString(r.Priority),
	}
}

func (r Response) SortRows() bool {
	return false
}

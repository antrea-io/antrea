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

package endpoint

import (
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform"
	"github.com/vmware-tanzu/antrea/pkg/antctl/transform/common"
	"github.com/vmware-tanzu/antrea/pkg/controller/apiserver/handlers/endpoint"
	"io"
	"reflect"
)

type Policy struct {
	Name string
}

type Response struct {
	Applied Policy
}

func objectTransform(o interface{}) (interface{}, error) {
	policies := o.(*endpoint.Policies)
	responses := make([]Response, 0)
	for _, policy := range policies.Applied {
		response := Response{
			Applied: Policy{
				Name: policy.Name,
			},
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func listTransform(l interface{}) (interface{}, error) {
	panic("unimplemented")
	return objectTransform(l)
}

func Transform(reader io.Reader, single bool) (interface{}, error) {
	return transform.GenericFactory(
		reflect.TypeOf(endpoint.Policies{}),
		reflect.TypeOf(endpoint.Policies{}),
		objectTransform,
		listTransform,
	)(reader, single)
}

func (r Response) GetTableHeader() []string {
	return []string{"NAME"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Applied.Name}
}

func (r Response) SortRows() bool {
	return true
}

var _ common.TableOutput = new(Response)

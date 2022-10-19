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

package membertoken

import (
	corev1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/antctl/transform/common"
)

type Response struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace" yaml:"namespace"`
}

func Transform(r interface{}, single bool) (interface{}, error) {
	if single {
		return objectTransform(r)
	}
	return listTransform(r)
}

func listTransform(l interface{}) (interface{}, error) {
	secrets := l.([]corev1.Secret)
	var result []interface{}

	for i := range secrets {
		item := secrets[i]
		o, _ := objectTransform(item)
		result = append(result, o.(Response))
	}

	return result, nil
}

func objectTransform(o interface{}) (interface{}, error) {
	secret := o.(corev1.Secret)

	return Response{
		Namespace: secret.Namespace,
		Name:      secret.Name,
	}, nil
}

var _ common.TableOutput = new(Response)

func (r Response) GetTableHeader() []string {
	return []string{"NAMESPACE", "NAME"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{r.Namespace, r.Name}
}

func (r Response) SortRows() bool {
	return true
}

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

package transform

import (
	"encoding/json"
	"io"
	"reflect"
)

type unary func(interface{}, map[string]string) (interface{}, error)
type FuncType func(reader io.Reader, single bool) (interface{}, error)

func GenericFactory(objType, listType reflect.Type, objTransform, listTransform unary, opts map[string]string) FuncType {
	return func(reader io.Reader, single bool) (interface{}, error) {
		var refType reflect.Type
		if single {
			refType = objType
		} else {
			refType = listType
		}
		refVal := reflect.New(refType)
		if err := json.NewDecoder(reader).Decode(refVal.Interface()); err != nil {
			return nil, err
		}
		if single && objTransform != nil {
			return objTransform(refVal.Interface(), opts)
		} else if !single && listTransform != nil {
			return listTransform(refVal.Interface(), opts)
		}
		return refVal.Interface(), nil
	}
}

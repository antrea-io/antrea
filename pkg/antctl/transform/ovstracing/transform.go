// Copyright 2021 Antrea Authors
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

package ovstracing

import (
	"encoding/json"
	"io"
	"io/ioutil"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/ovstracing"
)

func Transform(reader io.Reader, _ bool, _ map[string]string) (interface{}, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	resp := new(ovstracing.Response)
	err = json.Unmarshal(b, resp)
	if err != nil {
		return nil, err
	}
	// Output the raw bytes of the OVS trace command outputs.
	return []byte(resp.Result), nil
}

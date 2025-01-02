// Copyright 2025 Antrea Authors
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

package fqdncache

import (
	"encoding/json"
	"io"

	"antrea.io/antrea/pkg/agent/types"
)

type Response struct {
	*types.DnsCacheEntry
}

func Transform(reader io.Reader, single bool, opts map[string]string) (interface{}, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var resp []Response
	err = json.Unmarshal(b, &resp)
	if err != nil {
		return nil, err
	}
	domain, exists := opts["domain"]
	if exists {
		var filteredResp []Response
		for _, r := range resp {
			if r.FqdnName == domain {
				filteredResp = append(filteredResp, r)
			}
		}
		resp = filteredResp
	}
	if len(resp) == 0 {
		return "", nil
	}
	return resp, nil
}

func (r Response) GetTableHeader() []string {
	return []string{"FQDN", "ADDRESS", "EXPIRATION TIME"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{
		r.FqdnName,
		r.IpAddress.String(),
		r.ExpirationTime.String(),
	}
}

func (r Response) SortRows() bool {
	return false
}

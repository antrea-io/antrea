// Copyright 2019 Antrea Authors
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

package ovsconfig

type Bridge struct {
	Name         string        `json:"name"`
	Protocols    []interface{} `json:"protocols,omitempty"`
	DatapathType string        `json:"datapath_type,omitempty"`
}

type Port struct {
	Name        string        `json:"name"`
	Interfaces  []interface{} `json:"interfaces"`
	ExternalIDs []interface{} `json:"external_ids,omitempty"`
}

type Interface struct {
	Name          string        `json:"name"`
	Type          string        `json:"type,omitempty"`
	OFPortRequest int32         `json:"ofport_request,omitempty"`
	Options       []interface{} `json:"options,omitempty"`
}

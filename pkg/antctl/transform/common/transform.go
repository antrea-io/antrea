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

package common

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

type GroupMember struct {
	Pod *cpv1beta.PodReference `json:"pod,omitempty"`
	// IP maintains the IPAddresses associated with the Pod.
	IP string `json:"ip,omitempty"`
	// Ports maintain the named port mapping of this Pod.
	Ports []cpv1beta.NamedPort `json:"ports,omitempty"`
}

func GroupMemberPodTransform(member cpv1beta.GroupMember) GroupMember {
	var ipStr string
	for i, ip := range member.IPs {
		if i != 0 {
			ipStr += ", "
		}
		ipStr += net.IP(ip).String()
	}
	return GroupMember{Pod: member.Pod, IP: ipStr, Ports: member.Ports}
}

type TableOutput interface {
	GetTableHeader() []string
	GetTableRow(maxColumnLength int) []string
	SortRows() bool
}

func Int32ToString(val int32) string {
	return strconv.Itoa(int(val))
}

func Int64ToString(val int64) string {
	return strconv.Itoa(int(val))
}

func GenerateTableElementWithSummary(list []string, maxColumnLength int) string {
	element := ""
	sort.Strings(list)
	for i, ele := range list {
		val := ele
		if i != 0 {
			val = "," + val
		}

		// If we can't show the information in one line, generate a summary.
		summary := fmt.Sprintf(" + %d more...", len(list)-i)
		if len(element)+len(val) > maxColumnLength {
			element += summary
			if len(element) > maxColumnLength {
				newEle := ""
				for i, ele := range list {
					val := ele
					if i != 0 {
						val = "," + val
					}
					if i != 0 && len(newEle)+len(val)+len(summary) > maxColumnLength {
						break
					}
					newEle += val
				}
				newEle += summary
				return newEle
			}
			break
		}
		element += val
	}
	return element
}

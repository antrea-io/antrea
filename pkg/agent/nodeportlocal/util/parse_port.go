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

package util

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	delim = ":"
)

// BuildPortProto creates a single string using port and protocol separated by a delimiter.
func BuildPortProto(port, protocol string) string {
	return fmt.Sprint(port) + delim + strings.ToLower(protocol)
}

// ParsePortProto separates out port and protocol from a string generated using BuildPortProto.
func ParsePortProto(portProtocol string) (int, string, error) {
	portProtoSlice := strings.Split(portProtocol, delim)
	if len(portProtoSlice) != 2 {
		return 0, "", fmt.Errorf("invalid format for PortProto string '%s'", portProtoSlice)
	}
	port, err := strconv.Atoi(portProtoSlice[0])
	protocol := portProtoSlice[1]
	return port, protocol, err
}

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

package cipher

import (
	"crypto/tls"
	"strings"

	"k8s.io/component-base/cli/flag"
)

var TLSVersionMap = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// GenerateCipherSuitesList generates Cipher Suite list from comma-separated Cipher Suite string.
func GenerateCipherSuitesList(cipherSuites string) ([]uint16, error) {
	csStrList := strings.Split(strings.ReplaceAll(cipherSuites, " ", ""), ",")
	if len(csStrList) == 1 && csStrList[0] == "" {
		return []uint16{}, nil
	}
	csIntList, err := flag.TLSCipherSuites(csStrList)
	if err != nil {
		return nil, err
	}
	return csIntList, nil
}

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

package options

import (
	"crypto/tls"
	"fmt"
)

const DefaultTLSVersion = tls.VersionTLS12

func TLSVersion(version string) (uint16, error) {
	switch version {
	case "":
		return DefaultTLSVersion, nil
	case "VersionTLS12":
		return tls.VersionTLS12, nil
	case "VersionTLS13":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unsupported TLS version: %s", version)
}

func TLSVersionOrDie(version string) uint16 {
	v, err := TLSVersion(version)
	if err != nil {
		panic(err)
	}
	return v
}

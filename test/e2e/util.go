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

package e2e

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// IsDirEmpty checks whether a directory is empty or not.
func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

func timeCost() func(string) {
	start := time.Now()
	return func(status string) {
		tc := time.Since(start)
		klog.Infof("Confirming %s status costs %v", status, tc)
	}
}

func IPFamily(ip string) string {
	switch {
	case net.ParseIP(ip).To4() != nil:
		return "v4"
	case net.ParseIP(ip).To16() != nil:
		return "v6"
	default:
		return ""
	}
}

// getHTTPURLFromIPPort returns a HTTP url based on the IP, port and the additional paths if provided.
// Examples:
// getHTTPURLFromIPPort("1.2.3.4", 80) == "http://1.2.3.4:80"
// getHTTPURLFromIPPort("1.2.3.4", 8080, "clientip") == "http://1.2.3.4:8080/clientip"
// getHTTPURLFromIPPort("1.2.3.4", 8080, "api/v1/metadata?", "foo=bar") == "http://1.2.3.4:8080/api/v1/metadata?foo=bar"
// getHTTPURLFromIPPort("fd74:ca9b:172::b4e", 8080) == "http://[fd74:ca9b:172::b4e]:8080"
func getHTTPURLFromIPPort(ip string, port int32, paths ...string) string {
	url := "http://" + net.JoinHostPort(ip, fmt.Sprint(port))
	if len(paths) > 0 {
		url += "/" + strings.Join(paths, "")
	}
	return url
}

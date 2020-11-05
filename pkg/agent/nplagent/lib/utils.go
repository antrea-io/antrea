// +build !windows

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

package lib

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog"
)

func HasElem(s interface{}, elem interface{}) bool {
	arrV := reflect.ValueOf(s)

	if arrV.Kind() == reflect.Slice {
		for i := 0; i < arrV.Len(); i++ {
			// panics if slice element points to an unexported struct field
			// see https://golang.org/pkg/reflect/#Value.Interface
			if arrV.Index(i).Interface() == elem {
				return true
			}
		}
	}

	return false
}

func ParsePortsRange(portRangeConfig string) (start, end int, err error) {
	portsRange := strings.Split(portRangeConfig, "-")
	if len(portsRange) != 2 {
		return 0, 0, fmt.Errorf("wrong port range format: %s", portRangeConfig)
	}

	if start, err = strconv.Atoi(portsRange[0]); err != nil {
		return 0, 0, err
	}

	if end, err = strconv.Atoi(portsRange[1]); err != nil {
		return 0, 0, err
	}

	if end <= start {
		return 0, 0, fmt.Errorf("invalid port range: %s", portRangeConfig)
	}

	return start, end, nil
}

func IsPortAvailable(mPort int) bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		klog.Warningf("unix socket creation failed with error: %v", err)
		return false
	}
	defer unix.Close(fd)

	err = unix.Bind(fd, &unix.SockaddrInet4{
		Port: mPort,
		Addr: [4]byte{0, 0, 0, 0},
	})

	if err != nil {
		return false
	}

	return true
}

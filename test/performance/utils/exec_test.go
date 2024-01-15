// Copyright 2024 Antrea Authors.
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

package utils

import (
	"fmt"
	"testing"
)

func TestExtractSeconds(t *testing.T) {
	testCases := []struct {
		name string
		log  string
		key  string
	}{
		{
			name: "unknown to up",
			log:  "1234567 Status changed from unknown to up after 100 seconds",
			key:  "unknown to up",
		},
		{
			name: "down to up",
			log:  "12345678 Status changed from down to up after 100 seconds",
			key:  "down to up",
		},
		{
			name: "unknown to down",
			log:  "1709868559530201288 Status changed from unknown to down after 1007982937 nanoseconds",
			key:  "unknown to down",
		},
	}
	for _, tc := range testCases {
		res, err := extractNanoseconds(tc.log, tc.key)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(res)
	}
}

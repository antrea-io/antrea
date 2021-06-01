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

package table

import (
	"os"
	"testing"
	"time"
)

func TestTableName(t *testing.T) {
	startTime := time.Now()
	var rows [][]string
	rows = append(rows, GenerateRow("BenchmarkInitXLargeScaleWithNetpolPerPod-2 123", "success", time.Since(startTime)))
	rows = append(rows, GenerateRow("caseName1", "fail", time.Since(startTime)))
	ShowResult(os.Stdout, rows)
}

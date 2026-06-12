// Copyright 2026 Antrea Authors
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

package gobgp

import (
	"log/slog"
	"runtime"
)

// gobgpExternalWrapperLog is used to simulate GoBGP's internal wrapper in a different file
// for testing the dynamic call stack depth calculation.
// It returns the line number of the logger.Info call so the test can assert it dynamically.
func gobgpExternalWrapperLog(logger *slog.Logger) int {
	_, _, line, _ := runtime.Caller(0)
	expectedLine := line + 2
	logger.Info("external wrapper message",
		slog.String("ext_k1", "ext_v1"),
	)
	return expectedLine
}

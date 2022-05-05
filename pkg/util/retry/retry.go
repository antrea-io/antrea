// Copyright 2022 Antrea Authors
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

package retry

import (
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

// RetryOnErrors allows the caller to retry fn in case the error is in errFns.
func RetryOnErrors(backoff wait.Backoff, fn func() error, errFns ...func(error) bool) error {
	combinedErrFn := func(err error) bool {
		for _, errFn := range errFns {
			if errFn(err) {
				return true
			}
		}
		return false
	}
	return retry.OnError(backoff, combinedErrFn, fn)
}

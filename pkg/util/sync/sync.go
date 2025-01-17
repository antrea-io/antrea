// Copyright 2025 Antrea Authors.
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

package sync

import "sync"

type OnceWithNoError struct {
	done bool
	mu   sync.RWMutex
}

// Do will ensure that only one successful call to f happens. If a successful call has already happened, Do returns
// immediately with `nil`. Otherwise, f is called. If f returns an error, Do will return the error. Concurrent calls to
// f are not possible. If there has not been a successful call to f yet, a new call to Do will wait until the current
// call to f completes, then if this call is not successful, it will call f again itself.
func (o *OnceWithNoError) Do(f func() error) error {
	// Use a read lock to quickly check if f has already succeeded.
	o.mu.RLock()
	if o.done {
		o.mu.RUnlock()
		return nil
	}
	o.mu.RUnlock()

	// Acquire a write lock to ensure exclusive execution of f.
	o.mu.Lock()
	defer o.mu.Unlock()

	// Double-check the done flag in case another goroutine succeeded while we were waiting.
	if o.done {
		return nil
	}

	// Call f; if it returns nil, mark the operation as completed.
	err := f()
	if err == nil {
		o.done = true
	}
	return err
}

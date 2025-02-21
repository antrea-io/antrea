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

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnceWithNoError(t *testing.T) {
	var errNum int
	f := func() error {
		if errNum < 3 {
			errNum++
			return fmt.Errorf("error")
		}
		return nil
	}
	var onceWithNoError OnceWithNoError

	var errOccurred int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := onceWithNoError.Do(f)
			if err != nil {
				atomic.AddInt32(&errOccurred, 1)
			}
		}(i)
	}
	wg.Wait()

	require.Equal(t, int32(3), errOccurred)
}

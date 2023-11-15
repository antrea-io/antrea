// Copyright 2023 Antrea Authors
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

package lazy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type foo struct{}

func TestLazy(t *testing.T) {
	var called int
	lazyFoo := New(func() *foo {
		called++
		return &foo{}
	})
	assert.False(t, lazyFoo.Evaluated())
	assert.Equal(t, 0, called)

	ch := make(chan *foo, 10)
	for i := 0; i < 10; i++ {
		go func() {
			ch <- lazyFoo.Get()
		}()
	}
	// Got the first result.
	foo := <-ch
	assert.True(t, lazyFoo.Evaluated())
	// Got the rest 9 results, all of them should reference the same object.
	for i := 1; i < 10; i++ {
		assert.Same(t, foo, <-ch)
	}
	assert.Equal(t, 1, called, "The getter should only be called exactly once")
}

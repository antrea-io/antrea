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
	"sync"
	"sync/atomic"
)

// Lazy defers the evaluation of getter until it's accessed the first access.
type Lazy[T any] interface {
	// Get returns the value, evaluate it if necessary.
	Get() T
	// Evaluated returns whether the value has been evaluated or not.
	Evaluated() bool
}

type lazy[T any] struct {
	getter func() T
	// res is the cached result.
	res  T
	done uint32
	m    sync.Mutex
}

// New returns a new lazily evaluated value. The getter is executed only when it's accessed the first access.
func New[T any](getter func() T) Lazy[T] {
	return &lazy[T]{getter: getter}
}

func (l *lazy[T]) Get() T {
	if atomic.LoadUint32(&l.done) == 0 {
		return l.doSlow()
	}
	return l.res
}

func (l *lazy[T]) doSlow() T {
	l.m.Lock()
	defer l.m.Unlock()
	if l.done == 0 {
		defer atomic.StoreUint32(&l.done, 1)
		l.res = l.getter()
	}
	return l.res
}

func (l *lazy[T]) Evaluated() bool {
	return atomic.LoadUint32(&l.done) == 1
}

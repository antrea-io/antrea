// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intermediate

import (
	"k8s.io/klog/v2"
)

type aggregationWorker interface {
	start()
	stop()
}

type worker[T any] struct {
	id        int
	inputChan <-chan T
	errChan   chan bool
	job       func(T) error
}

func createWorker[T any](id int, inputChan <-chan T, job func(T) error) *worker[T] {
	return &worker[T]{
		id,
		inputChan,
		make(chan bool),
		job,
	}
}

func (w *worker[T]) start() {
	go func() {
		for {
			select {
			case <-w.errChan:
				return
			case v, ok := <-w.inputChan:
				if !ok { // inputChan is closed and empty
					break
				}
				err := w.job(v)
				if err != nil {
					klog.ErrorS(err, "Failed to process IPFIX input")
				}
			}
		}
	}()
}

func (w *worker[T]) stop() {
	w.errChan <- true
}

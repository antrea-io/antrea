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

package wait

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/utils/clock"
)

// Group allows to wait for a collection of goroutines to finish with a timeout or a stop channel.
type Group struct {
	wg     *sync.WaitGroup
	doneCh chan struct{}
	once   sync.Once
	clock  clock.Clock
}

func NewGroup() *Group {
	return newGroupWithClock(clock.RealClock{})
}

func newGroupWithClock(clock clock.Clock) *Group {
	return &Group{
		wg:     &sync.WaitGroup{},
		doneCh: make(chan struct{}),
		clock:  clock,
	}
}

func (g *Group) Increment() *Group {
	g.wg.Add(1)
	return g
}

func (g *Group) Done() {
	g.wg.Done()
}

func (g *Group) wait() {
	g.once.Do(func() {
		go func() {
			g.wg.Wait()
			close(g.doneCh)
		}()
	})
}

func (g *Group) WaitWithTimeout(timeout time.Duration) error {
	g.wait()
	select {
	case <-g.doneCh:
		return nil
	case <-g.clock.After(timeout):
		return fmt.Errorf("timeout waiting for group")
	}
}

func (g *Group) WaitUntil(stopCh <-chan struct{}) error {
	g.wait()
	select {
	case <-g.doneCh:
		return nil
	case <-stopCh:
		return fmt.Errorf("stopCh closed, stop waiting")
	}
}

func (g *Group) Wait() {
	g.wg.Wait()
}

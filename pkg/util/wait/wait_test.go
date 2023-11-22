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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	clock "k8s.io/utils/clock/testing"
)

func TestGroupWaitWithTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond
	tests := []struct {
		name          string
		add           int
		processFn     func(group *Group, fakeClock *clock.FakeClock)
		expectWaitErr bool
	}{
		{
			name: "add only",
			add:  1,
			processFn: func(group *Group, fakeClock *clock.FakeClock) {
				fakeClock.Step(timeout)
			},
			expectWaitErr: true,
		},
		{
			name: "add greater than done",
			add:  2,
			processFn: func(group *Group, fakeClock *clock.FakeClock) {
				group.Done()
				fakeClock.Step(timeout)
			},
			expectWaitErr: true,
		},
		{
			name: "add equal to done",
			add:  2,
			processFn: func(group *Group, fakeClock *clock.FakeClock) {
				group.Done()
				fakeClock.Step(timeout / 2)
				group.Done()
			},
			expectWaitErr: false,
		},
		{
			name: "add with delay",
			add:  2,
			processFn: func(group *Group, fakeClock *clock.FakeClock) {
				group.Done()
				fakeClock.Step(timeout * 2)
				group.Done()
			},
			expectWaitErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClock := clock.NewFakeClock(time.Now())
			g := newGroupWithClock(fakeClock)
			for i := 0; i < tt.add; i++ {
				g.Increment()
			}
			resCh := make(chan error, 1)
			go func() {
				resCh <- g.WaitWithTimeout(timeout)
			}()
			require.Eventually(t, func() bool {
				return fakeClock.HasWaiters()
			}, 1*time.Second, 10*time.Millisecond)
			tt.processFn(g, fakeClock)
			err := <-resCh
			if tt.expectWaitErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGroupWait(t *testing.T) {
	g := NewGroup()
	g.Increment()
	returnedCh := make(chan struct{})
	go func() {
		g.Wait()
		close(returnedCh)
	}()
	select {
	case <-time.After(100 * time.Millisecond):
	case <-returnedCh:
		t.Errorf("Wait should not return before it's done")
	}
	g.Done()
	select {
	case <-time.After(500 * time.Millisecond):
		t.Errorf("Wait should return after it's done")
	case <-returnedCh:
	}
}

func TestGroupWaitUntil(t *testing.T) {
	g := NewGroup()
	g.Increment()
	stopCh := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(stopCh)
	}()
	err := g.WaitUntil(stopCh)
	assert.Error(t, err)

	stopCh = make(chan struct{})
	g.Done()
	err = g.WaitUntil(stopCh)
	assert.NoError(t, err)
}

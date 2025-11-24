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
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupWaitWithTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond
	tests := []struct {
		name           string
		add            int
		processFn      func(group *Group)
		expectWaitErr  bool
		doneForCleanup int
	}{
		{
			name: "add only",
			add:  1,
			processFn: func(group *Group) {
				time.Sleep(timeout)
			},
			expectWaitErr:  true,
			doneForCleanup: 1,
		},
		{
			name: "add greater than done",
			add:  2,
			processFn: func(group *Group) {
				group.Done()
				time.Sleep(timeout)
			},
			expectWaitErr:  true,
			doneForCleanup: 1,
		},
		{
			name: "add equal to done",
			add:  2,
			processFn: func(group *Group) {
				group.Done()
				time.Sleep(timeout / 2)
				group.Done()
			},
			expectWaitErr: false,
		},
		{
			name: "add with delay",
			add:  2,
			processFn: func(group *Group) {
				group.Done()
				time.Sleep(timeout * 2)
				group.Done()
			},
			expectWaitErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g := NewGroup()
				for range tt.add {
					g.Increment()
				}
				resCh := make(chan error, 1)
				go func() {
					resCh <- g.WaitWithTimeout(timeout)
				}()
				tt.processFn(g)
				synctest.Wait()
				var err error
				select {
				case err = <-resCh:
				default:
					require.Fail(t, "Expected result on resCh")
				}
				if tt.expectWaitErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
				// clean up is needed to make sure that no blocked goroutine remains in the bubble
				for range tt.doneForCleanup {
					g.Done()
				}
			})
		})
	}
}

func TestGroupWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGroup()
		g.Increment()
		returnedCh := make(chan struct{})
		go func() {
			defer close(returnedCh)
			g.Wait()
		}()
		time.Sleep(1 * time.Second)
		synctest.Wait()
		select {
		case <-returnedCh:
			require.Fail(t, "Wait should not return before it's done")
		default:
		}
		g.Done()
		synctest.Wait()
		select {
		case <-returnedCh:
		default:
			require.Fail(t, "Wait should return after it's done")
		}
	})
}

func TestGroupWaitUntil(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGroup()
		g.Increment()

		resCh := make(chan error, 1)

		stopCh := make(chan struct{})
		go func() {
			resCh <- g.WaitUntil(stopCh)
		}()

		synctest.Wait()
		select {
		case <-resCh:
			require.Fail(t, "WaitUntil should not have returned yet")
		default:
		}

		close(stopCh)
		synctest.Wait()
		select {
		case err := <-resCh:
			assert.EqualError(t, err, "stopCh closed, stop waiting")
		default:
			require.Fail(t, "WaitUntil should have returned")
		}

		stopCh = make(chan struct{})
		go func() {
			resCh <- g.WaitUntil(stopCh)
		}()

		synctest.Wait()
		select {
		case <-resCh:
			require.Fail(t, "WaitUntil should not have returned yet")
		default:
		}

		g.Done()
		synctest.Wait()
		select {
		case err := <-resCh:
			assert.NoError(t, err)
		default:
			require.Fail(t, "WaitUntil should have returned")
		}
	})
}

func TestGroupWaitUntilWithContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := NewGroup()
		g.Increment()

		resCh := make(chan error, 1)

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			resCh <- g.WaitUntilWithContext(ctx)
		}()

		synctest.Wait()
		select {
		case <-resCh:
			require.Fail(t, "WaitUntilWithContext should not have returned yet")
		default:
		}

		cancel()
		synctest.Wait()
		select {
		case err := <-resCh:
			assert.ErrorContains(t, err, "context canceled")
		default:
			require.Fail(t, "WaitUntilWithContext should have returned")
		}

		ctx, cancel = context.WithCancel(t.Context())
		defer cancel()
		go func() {
			resCh <- g.WaitUntilWithContext(ctx)
		}()

		synctest.Wait()
		select {
		case <-resCh:
			require.Fail(t, "WaitUntilWithContext should not have returned yet")
		default:
		}

		g.Done()
		synctest.Wait()
		select {
		case err := <-resCh:
			assert.NoError(t, err)
		default:
			require.Fail(t, "WaitUntilWithContext should have returned")
		}
	})
}

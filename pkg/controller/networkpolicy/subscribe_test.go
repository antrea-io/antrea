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

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscribe(t *testing.T) {
	n := newNotifier()
	var callback func()

	n.subscribe("resource1", "subscriber1a", callback)
	n.subscribe("resource1", "subscriber1b", callback)
	n.subscribe("resource2", "subscriber2", callback)
	require.Contains(t, n.subscribers, "resource1")
	require.Contains(t, n.subscribers["resource1"], "subscriber1a")
	require.Contains(t, n.subscribers["resource1"], "subscriber1b")
	require.Contains(t, n.subscribers, "resource2")
	require.Contains(t, n.subscribers["resource2"], "subscriber2")

	n.unsubscribe("resource1", "subscriber1a")
	require.Contains(t, n.subscribers, "resource1")
	require.NotContains(t, n.subscribers["resource1"], "subscriber1a")
	require.Contains(t, n.subscribers["resource1"], "subscriber1b")
	require.Contains(t, n.subscribers, "resource2")

	n.unsubscribe("resource1", "subscriber1b")
	require.NotContains(t, n.subscribers, "resource1")
	require.Contains(t, n.subscribers, "resource2")

	n.unsubscribe("resource2", "subscriber2")
	require.NotContains(t, n.subscribers, "resource2")
}

func TestNotify(t *testing.T) {
	n := newNotifier()
	newCallback := func() (func(), *int) {
		var counter int
		return func() {
			counter++
		}, &counter
	}
	callback1a, counter1a := newCallback()
	callback1b, counter1b := newCallback()
	callback2, counter2 := newCallback()

	n.subscribe("resource1", "subscriber1a", callback1a)
	n.subscribe("resource1", "subscriber1b", callback1b)
	n.subscribe("resource2", "subscriber2", callback2)
	n.notify("resource1")
	assert.Equal(t, 1, *counter1a)
	assert.Equal(t, 1, *counter1b)
	assert.Equal(t, 0, *counter2)
	n.notify("resource2")
	assert.Equal(t, 1, *counter1a)
	assert.Equal(t, 1, *counter1b)
	assert.Equal(t, 1, *counter2)

	n.unsubscribe("resource1", "subscriber1a")
	n.notify("resource1")
	n.notify("resource2")
	assert.Equal(t, 1, *counter1a)
	assert.Equal(t, 2, *counter1b)
	assert.Equal(t, 2, *counter2)

	n.unsubscribe("resource1", "subscriber1b")
	n.notify("resource1")
	n.notify("resource2")
	assert.Equal(t, 1, *counter1a)
	assert.Equal(t, 2, *counter1b)
	assert.Equal(t, 3, *counter2)

	n.unsubscribe("resource2", "subscriber2")
	n.notify("resource1")
	n.notify("resource2")
	assert.Equal(t, 1, *counter1a)
	assert.Equal(t, 2, *counter1b)
	assert.Equal(t, 3, *counter2)
}

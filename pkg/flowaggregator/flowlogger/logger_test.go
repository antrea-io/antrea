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

package flowlogger

import (
	"bufio"
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowrecordtesting "antrea.io/antrea/pkg/flowaggregator/flowrecord/testing"
)

// a thread-safe wrapper around bytes.Buffer
type buffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *buffer) Write(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(p)
}

func (b *buffer) Len() int {
	b.Lock()
	defer b.Unlock()
	return b.b.Len()
}

func (b *buffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

func getTestFlowLogger(maxLatency time.Duration) (*FlowLogger, *buffer) {
	var b buffer
	flowLogger := &FlowLogger{
		maxLatency: maxLatency,
		writer:     bufio.NewWriter(&b),
	}
	return flowLogger, &b
}

func TestWriteRecord(t *testing.T) {
	record := flowrecordtesting.PrepareTestFlowRecord()

	testCases := []struct {
		prettyPrint bool
		expected    string
	}{
		{
			prettyPrint: true,
			expected:    "1637706961,1637706973,10.10.0.79,10.10.0.80,44752,5201,TCP,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,10.10.1.10,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,Drop,K8sNetworkPolicy,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,Invalid,Invalid,test-egress,172.18.0.1,http,mockHttpString,test-egress-node",
		},
		{
			prettyPrint: false,
			expected:    "1637706961,1637706973,10.10.0.79,10.10.0.80,44752,5201,6,perftest-a,antrea-test,k8s-node-control-plane,perftest-b,antrea-test-b,k8s-node-control-plane-b,10.10.1.10,5202,perftest,test-flow-aggregator-networkpolicy-ingress-allow,antrea-test-ns,test-flow-aggregator-networkpolicy-rule,2,1,test-flow-aggregator-networkpolicy-egress-allow,antrea-test-ns-e,test-flow-aggregator-networkpolicy-rule-e,5,4,test-egress,172.18.0.1,http,mockHttpString,test-egress-node",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("pretty print: %t", tc.prettyPrint), func(t *testing.T) {
			flowLogger, b := getTestFlowLogger(MaxLatency)
			err := flowLogger.WriteRecord(record, tc.prettyPrint)
			require.NoError(t, err)
			flowLogger.Flush()
			assert.Contains(t, b.String(), tc.expected)
		})
	}
}

func TestFlushLoop(t *testing.T) {
	flowLogger, b := getTestFlowLogger(100 * time.Millisecond)
	record := flowrecordtesting.PrepareTestFlowRecord()
	err := flowLogger.WriteRecord(record, false)
	require.NoError(t, err)
	assert.Equal(t, 0, b.Len())
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		flowLogger.FlushLoop(stopCh)
	}()
	assert.Eventually(t, func() bool {
		return b.Len() > 0
	}, 1*time.Second, 50*time.Millisecond, "Buffer was never flushed")
	close(stopCh)
	assert.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, 1*time.Second, 10*time.Millisecond, "FlushLoop should return when stopCh is closed")
}

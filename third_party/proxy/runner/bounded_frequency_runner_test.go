/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Copyright 2025 Antrea Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Derived from Kubernetes pkg/proxy/runner/bounded_frequency_runner.go (v1.34.2); Antrea tests ensure timing semantics.

package runner

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"
)

func waitForCalls(t *testing.T, fakeClock *clocktesting.FakeClock, calls *int32, target int32) {
	t.Helper()
	for i := 0; i < 5; i++ {
		runtime.Gosched()
		if atomic.LoadInt32(calls) >= target {
			return
		}
		fakeClock.Step(time.Second)
		runtime.Gosched()
		if atomic.LoadInt32(calls) >= target {
			return
		}
	}

	t.Fatalf("expected %d calls, got %d", target, atomic.LoadInt32(calls))
}

func TestBoundedFrequencyRunnerRuns(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	fn := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	bfr := construct("test-runner", fn, time.Second, time.Second, 5*time.Second, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	bfr.Run()
	waitForCalls(t, fakeClock, &calls, 1)

	close(stopCh)
}

func TestBoundedFrequencyRunnerStops(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	fn := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	bfr := construct("test-stop", fn, time.Second, time.Second, 5*time.Second, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	bfr.Run()
	waitForCalls(t, fakeClock, &calls, 1)

	close(stopCh)

	fakeClock.Step(10 * time.Second)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("runner should not execute after stop, got %d calls", got)
	}
}

func TestBoundedFrequencyRunnerRespectsMinInterval(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	fn := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	minInterval := 2 * time.Second
	bfr := construct("test-interval", fn, minInterval, time.Second, 10*time.Second, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	bfr.Run()
	waitForCalls(t, fakeClock, &calls, 1)

	bfr.Run()
	fakeClock.Step(time.Second)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected no new call before minInterval, got %d", got)
	}

	waitForCalls(t, fakeClock, &calls, 2)

	close(stopCh)
}

func TestBoundedFrequencyRunnerRetry(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	var failUntil int32 = 2
	fn := func() error {
		count := atomic.AddInt32(&calls, 1)
		if count <= failUntil {
			return nil
		}
		return nil
	}

	retryInterval := time.Second
	bfr := construct("test-retry", fn, 500*time.Millisecond, retryInterval, 10*time.Second, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	bfr.Run()
	waitForCalls(t, fakeClock, &calls, 1)

	close(stopCh)
}

func TestBoundedFrequencyRunnerMaxInterval(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	fn := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	maxInterval := 3 * time.Second
	bfr := construct("test-max", fn, time.Second, time.Second, maxInterval, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	runtime.Gosched()
	fakeClock.Step(maxInterval)
	runtime.Gosched()

	waitForCalls(t, fakeClock, &calls, 1)

	fakeClock.Step(maxInterval)
	runtime.Gosched()

	waitForCalls(t, fakeClock, &calls, 2)

	close(stopCh)
}

func TestBoundedFrequencyRunnerConcurrentRun(t *testing.T) {
	fakeClock := clocktesting.NewFakeClock(time.Now())

	var calls int32
	fn := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	bfr := construct("test-concurrent", fn, time.Second, time.Second, 5*time.Second, fakeClock)

	stopCh := make(chan struct{})
	go bfr.Loop(stopCh)

	bfr.Run()
	bfr.Run()
	bfr.Run()

	waitForCalls(t, fakeClock, &calls, 1)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("concurrent Run() calls should coalesce, got %d calls", got)
	}

	close(stopCh)
}

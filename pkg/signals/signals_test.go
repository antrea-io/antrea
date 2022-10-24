//go:build !windows
// +build !windows

// Copyright 2022 Antrea Authors
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

package signals

import (
	"os"
	"syscall"
	"testing"
	"time"
)

var (
	timeout = 5 * time.Second
)

func TestGenerateStopSignal(t *testing.T) {
	defer func() {
		// Reset channel
		notifyCh = make(chan os.Signal, 2)
	}()

	GenerateStopSignal()

	select {
	case <-time.After(timeout):
		t.Fatalf("Timeout after %v waiting for signal", timeout)
	case s := <-notifyCh:
		if s == syscall.SIGTERM {
			// Get expected signal.
			return
		}
		t.Errorf("Unexpected signal %v", s)
	}
}

func TestRegisterSignalHandlers(t *testing.T) {
	stopCh := RegisterSignalHandlers()
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case <-time.After(timeout):
		t.Fatalf("Timeout after %v waiting for channel", timeout)
	case _, ok := <-stopCh:
		if !ok {
			// Channel is closed as expected.
			return
		}
		t.Error("Channel is not closed")
	}
}

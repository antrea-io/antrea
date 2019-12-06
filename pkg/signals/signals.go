// Copyright 2019 Antrea Authors
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
	"os/signal"
	"syscall"

	"k8s.io/klog"
)

var capturedSignals = []os.Signal{syscall.SIGTERM, syscall.SIGINT}

// RegisterSignalHandlers registers a signal handler for capturedSignals and starts a goroutine that
// will block until a signal is received. The first signal received will cause the stopCh channel to
// be closed, giving the opportunity to the program to exist gracefully. If a second signal is
// received before then, we will force exit with code 1.
func RegisterSignalHandlers() <-chan struct{} {
	notifyCh := make(chan os.Signal, 2)
	stopCh := make(chan struct{})

	go func() {
		<-notifyCh
		close(stopCh)
		<-notifyCh
		klog.Warning("Received second signal, will force exit")
		klog.Flush()
		os.Exit(1)
	}()

	signal.Notify(notifyCh, capturedSignals...)

	return stopCh
}

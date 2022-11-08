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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	ctrl "sigs.k8s.io/controller-runtime"

	"antrea.io/antrea/multicluster/test/mocks"
)

var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// The original signal handler function will close a channel twice. If the runLeader
// and runMember run at the same time, there will be a panic. So we need another
// signal handler function to avoid it.
func mockSetupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

func TestCommands(t *testing.T) {
	rootCommand := newControllerCommand()
	rootCommand.AddCommand(newLeaderCommand())
	rootCommand.AddCommand(newMemberCommand())

	assert.Equal(t, "antrea-mc-controller", rootCommand.Use)
	assert.Equal(t, "leader", newLeaderCommand().Use)
	assert.Equal(t, "member", newMemberCommand().Use)
}

func TestRunMember(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockMemberManager := mocks.NewMockManager(mockCtrl)
	initMockManager(mockMemberManager)

	testCase := struct {
		name      string
		setupFunc func(o *Options) (ctrl.Manager, error)
	}{
		name: "Start member controller successfully",
		setupFunc: func(o *Options) (ctrl.Manager, error) {
			return mockMemberManager, nil
		},
	}

	t.Run(testCase.name, func(t *testing.T) {
		setupManagerAndCertControllerFunc = testCase.setupFunc
		ctrl.SetupSignalHandler = mockSetupSignalHandler
		err := runMember(&Options{})
		assert.NoError(t, err, "got error when running runMember")
	})
}

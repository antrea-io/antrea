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

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"antrea.io/antrea/multicluster/controllers/multicluster/member"
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
	testCases := []struct {
		name    string
		options *Options
	}{
		{
			name:    "Start member controller successfully with default options",
			options: &Options{},
		},
		{
			name:    "Start member controller successfully with stretchedNetworkPolicy enabled",
			options: &Options{EnableStretchedNetworkPolicy: true},
		},
		{
			name: "Start member controller successfully with ServiceCIDR",
			options: &Options{
				ServiceCIDR: "10.101.0.0/16",
			},
		},
	}

	for _, tc := range testCases {
		mockCtrl := gomock.NewController(t)
		mockMemberManager := mocks.NewMockManager(mockCtrl)
		initMockManager(mockMemberManager)
		setupManagerAndCertControllerFunc = func(isLeader bool, o *Options) (ctrl.Manager, error) {
			return mockMemberManager, nil
		}
		member.ServiceCIDRDiscoverFn = func(ctx context.Context, k8sClient client.Client, namespace string) (string, error) {
			return "10.101.0.0/16", nil
		}
		ctrl.SetupSignalHandler = mockSetupSignalHandler
		t.Run(tc.name, func(t *testing.T) {
			err := runMember(tc.options)
			assert.NoError(t, err, "got error when running runMember")
		})
	}
}

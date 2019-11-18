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

package openflow

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	ovscfgtest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig/testing"
)

const bridgeName = "dummy-br"

func installNodeFlows(ofClient Client, cacheKey string) (int, error) {
	hostName := cacheKey
	gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	IP, IPNet, _ := net.ParseCIDR("10.0.1.1/24")
	peerNodeIP := net.ParseIP("192.168.1.1")
	err := ofClient.InstallNodeFlows(hostName, gwMAC, IP, *IPNet, peerNodeIP)
	client := ofClient.(*client)
	fCacheI, _ := client.nodeFlowCache.Load(hostName)
	return len(fCacheI.(flowCache)), err
}

func installPodFlows(ofClient Client, cacheKey string) (int, error) {
	containerID := cacheKey
	gwMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	podMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:EE")
	podIP := net.ParseIP("10.0.0.2")
	ofPort := uint32(10)
	err := ofClient.InstallPodFlows(containerID, podIP, podMAC, gwMAC, ofPort)
	client := ofClient.(*client)
	fCacheI, _ := client.podFlowCache.Load(containerID)
	return len(fCacheI.(flowCache)), err
}

// TestIdempotentFlowInstallation checks that InstallNodeFlows and InstallPodFlows are idempotent.
func TestIdempotentFlowInstallation(t *testing.T) {
	testCases := []struct {
		name        string
		cacheKey    string
		numAddCalls int
		installFn   func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host", 2, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			brClient := ovscfgtest.NewMockOVSBridgeClient(ctrl)
			brClient.EXPECT().Name().Return(bridgeName).AnyTimes()
			brClient.EXPECT().GetExternalIDs().Return(map[string]string{roundNumKey: "0"}, nil).AnyTimes()
			brClient.EXPECT().SetExternalIDs(gomock.Any()).Return(nil).AnyTimes()
			m := oftest.NewMockFlowOperations(ctrl)
			ofClient := NewClient(brClient)
			client := ofClient.(*client)
			client.flowOperations = m

			m.EXPECT().Add(gomock.Any()).Return(nil).Times(tc.numAddCalls)
			numCached1, err := tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows")

			// Installing the same flows again must not return an error and should not
			// add additional flows to the cache.
			numCached2, err := tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows again")

			assert.Equal(t, numCached1, numCached2)
		})
	}
}

func TestFlowInstallationPartialSuccess(t *testing.T) {
	testCases := []struct {
		name        string
		cacheKey    string
		numAddCalls int
		installFn   func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host", 2, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			brClient := ovscfgtest.NewMockOVSBridgeClient(ctrl)
			brClient.EXPECT().Name().Return(bridgeName).AnyTimes()
			brClient.EXPECT().GetExternalIDs().Return(map[string]string{roundNumKey: "0"}, nil).AnyTimes()
			brClient.EXPECT().SetExternalIDs(gomock.Any()).Return(nil).AnyTimes()
			m := oftest.NewMockFlowOperations(ctrl)
			ofClient := NewClient(brClient)
			client := ofClient.(*client)
			client.flowOperations = m

			// We generate an error for the last Add call.
			successfulCalls := m.EXPECT().Add(gomock.Any()).Return(nil).Times(tc.numAddCalls - 1)
			errorCall := m.EXPECT().Add(gomock.Any()).Return(errors.New("OF error")).After(successfulCalls)

			var err error
			var numCached int

			numCached, err = tc.installFn(ofClient, tc.cacheKey)
			require.NotNil(t, err, "Installing flows is expected to fail")
			assert.Equal(t, tc.numAddCalls-1, numCached)

			m.EXPECT().Add(gomock.Any()).Return(nil).After(errorCall).Times(1)
			numCached, err = tc.installFn(ofClient, tc.cacheKey)
			require.Nil(t, err, "Error when installing Node flows")
			assert.Equal(t, tc.numAddCalls, numCached)
		})
	}
}

// TestConcurrentFlowInstallation checks that flow installation for a given flow category (e.g. Node
// flows) and for different cache keys (e.g. different Node hostnames) can happen concurrently.
func TestConcurrentFlowInstallation(t *testing.T) {
	testCases := []struct {
		name        string
		cacheKey    string
		numAddCalls int
		installFn   func(ofClient Client, cacheKey string) (int, error)
	}{
		{"NodeFlows", "host", 2, installNodeFlows},
		{"PodFlows", "aaaa-bbbb-cccc-dddd", 5, installPodFlows},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			brClient := ovscfgtest.NewMockOVSBridgeClient(ctrl)
			brClient.EXPECT().Name().Return(bridgeName).AnyTimes()
			brClient.EXPECT().GetExternalIDs().Return(map[string]string{roundNumKey: "0"}, nil).AnyTimes()
			brClient.EXPECT().SetExternalIDs(gomock.Any()).Return(nil).AnyTimes()
			m := oftest.NewMockFlowOperations(ctrl)
			ofClient := NewClient(brClient)
			client := ofClient.(*client)
			client.flowOperations = m

			var wg sync.WaitGroup
			var counter int32        // tracks the number of concurrent Add calls at any given time
			var callIdx int32        // used to distinguish between the first Add call and subsequent calls
			var concurrentCalls bool // set to true if we observe concurrent calls
			var stop bool
			var mutex sync.Mutex
			cond := sync.NewCond(&mutex)

			m.EXPECT().Add(gomock.Any()).DoAndReturn(func(args ...interface{}) error {
				cond.L.Lock()
				defer cond.L.Unlock()
				counter += 1
				callIdx += 1
				if callIdx == 1 { // first call
					// we wait until we need to stop
					// we stop when one of these conditions is met:
					// 1) we detected concurrent Add calls (test is a success), or
					// 2) the test timed out
					for !stop {
						cond.Wait()
					}
				} else if counter > 1 {
					concurrentCalls = true
					stop = true
					cond.Signal()
				}
				return nil
			}).AnyTimes()

			wg.Add(2)
			go func() {
				tc.installFn(ofClient, tc.cacheKey)
				wg.Done()
			}()
			go func() {
				tc.installFn(ofClient, tc.cacheKey)
				wg.Done()
			}()

			// enforce a timeout of one second for the test
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			go func() {
				<-ctx.Done()
				cond.L.Lock()
				defer cond.L.Unlock()
				stop = true
			}()

			wg.Wait()
			cancel()

			assert.True(t, concurrentCalls)
		})
	}
}

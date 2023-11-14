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

package hostlocal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

type testFs struct {
	afero.Fs
	removeError  error
	removedFiles []string
}

func (fs *testFs) Remove(name string) error {
	if fs.removeError != nil {
		err := &os.PathError{Op: "remove", Path: name, Err: fs.removeError}
		// reset error
		fs.removeError = nil
		return err
	}
	if err := fs.Fs.Remove(name); err != nil {
		return err
	}
	fs.removedFiles = append(fs.removedFiles, name)
	return nil
}

// forceRemoveError forces the next Remove call to fail. Error will be cleared after the first call.
func (fs *testFs) forceRemoveError() {
	fs.removeError = fmt.Errorf("permission denied")
}

func (fs *testFs) removedIPs() sets.Set[string] {
	s := sets.New[string]()
	for _, p := range fs.removedFiles {
		s.Insert(getIPFromPath(p))
	}
	return s
}

// from https://github.com/containernetworking/plugins/blob/38f18d26ecfef550b8bac02656cc11103fd7cff1/plugins/ipam/host-local/backend/disk/backend.go#L197
func getEscapedPath(dir string, fname string) string {
	if runtime.GOOS == "windows" {
		fname = strings.ReplaceAll(fname, ":", "_")
	}
	return filepath.Join(dir, fname)
}

func allocateIPs(t *testing.T, fs afero.Fs, dir string, ips ...string) {
	for _, ip := range ips {
		path := getEscapedPath(dir, ip)
		// The real host-local IPAM plugin writes the container ID + interface name to the
		// file, but it is irrelevant in our case.
		require.NoError(t, afero.WriteFile(fs, path, []byte("foo"), 0o600))
	}
}

func TestGcContainerIPs(t *testing.T) {
	dir := networkDir("antrea")

	newTestFs := func() *testFs {
		return &testFs{
			Fs: afero.NewMemMapFs(),
		}
	}

	t.Run("missing directory", func(t *testing.T) {
		fs := newTestFs()
		// create the plugin data directory, but not the "network" sub-directory
		require.NoError(t, fs.MkdirAll(dataDir, 0o755))
		assert.NoError(t, gcContainerIPs(fs, dir, sets.New[string]()))
		removedIPs := fs.removedIPs()
		assert.Empty(t, removedIPs)
	})

	t.Run("remove error", func(t *testing.T) {
		ips := []string{"10.0.0.1", "10.0.0.2"}
		fs := newTestFs()
		require.NoError(t, fs.MkdirAll(dir, 0o755))
		allocateIPs(t, fs, dir, ips...)
		fs.forceRemoveError()
		require.Error(t, gcContainerIPs(fs, dir, sets.New[string]()))
		// one of the IPs will fail to be released, the other one will succeed
		removedIPs := fs.removedIPs()
		assert.Len(t, removedIPs, 1)
	})

	resolveIP := func(id int, ipv6 bool) string {
		if ipv6 {
			return fmt.Sprintf("2001:db8:a::%d", id)
		} else {
			return fmt.Sprintf("10.0.0.%d", id)
		}
	}

	// some success test cases, will be run for both IPv4 and IPv6
	testCases := []struct {
		name               string
		desiredIPs         []int
		allocatedIPs       []int
		expectedRemovedIPs []int
	}{
		{
			name:               "same sets",
			desiredIPs:         []int{1, 2},
			allocatedIPs:       []int{1, 2},
			expectedRemovedIPs: []int{},
		},
		{
			name:               "multiple removals",
			desiredIPs:         []int{1, 3},
			allocatedIPs:       []int{1, 2, 3, 4},
			expectedRemovedIPs: []int{2, 4},
		},
		{
			name:               "extra ip",
			desiredIPs:         []int{1, 2, 3},
			allocatedIPs:       []int{1, 2},
			expectedRemovedIPs: []int{},
		},
	}

	runTests := func(t *testing.T, ipv6 bool) {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}

		toIPSet := func(ids []int) sets.Set[string] {
			ips := sets.New[string]()
			for _, id := range ids {
				ip := resolveIP(id, ipv6)
				require.NotEmpty(t, ip)
				ips.Insert(ip)
			}
			return ips
		}

		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				fs := newTestFs()
				require.NoError(t, fs.MkdirAll(dir, 0o755))
				desiredIPs := toIPSet(tc.desiredIPs)
				allocatedIPs := toIPSet(tc.allocatedIPs)
				expectedRemovedIPs := toIPSet(tc.expectedRemovedIPs)
				allocateIPs(t, fs, dir, allocatedIPs.UnsortedList()...)
				require.NoError(t, gcContainerIPs(fs, dir, desiredIPs))
				assert.Equal(t, expectedRemovedIPs, fs.removedIPs())
			}
		})
	}

	runTests(t, false)
	runTests(t, true)
}

// TestGarbageCollectContainerIPs tests some edge cases and logic that depends on the real OS
// filesystem. The actual GC logic is tested by TestGcContainerIPs.
func TestGarbageCollectContainerIPs(t *testing.T) {
	ips := sets.New[string]()
	tempDir, err := os.MkdirTemp("", "test-networks")
	require.NoError(t, err)
	savedDir := dataDir
	defer func() {
		dataDir = savedDir
	}()
	dataDir = tempDir
	defer os.RemoveAll(tempDir)

	idx := 0
	networkName := func() string {
		idx++
		return fmt.Sprintf("net%d", idx)
	}

	lockFile := func(network string) string {
		return filepath.Join(tempDir, network, "lock")
	}

	t.Run("missing directory", func(t *testing.T) {
		network := networkName()
		// there is no directory in tempDir for the "antrea" network
		// we don't expect an error, and the lock file should not be created
		require.NoError(t, GarbageCollectContainerIPs(network, ips))
		assert.NoFileExists(t, lockFile(network))
	})

	t.Run("not a directory", func(t *testing.T) {
		network := networkName()
		netDir := filepath.Join(tempDir, network)
		// create a file instead of a directory: GarbageCollectContainerIPs should return an
		// error
		_, err := os.Create(netDir)
		require.NoError(t, err)
		defer os.Remove(netDir)
		assert.ErrorContains(t, GarbageCollectContainerIPs(network, ips), "not a directory")
	})

	t.Run("lock file created", func(t *testing.T) {
		network := networkName()
		netDir := filepath.Join(tempDir, network)
		require.NoError(t, os.Mkdir(netDir, 0o755))
		defer os.RemoveAll(netDir)
		// make sure that the lock file is created in the right place
		require.NoError(t, GarbageCollectContainerIPs(network, ips))
		assert.FileExists(t, lockFile(network))
	})
}

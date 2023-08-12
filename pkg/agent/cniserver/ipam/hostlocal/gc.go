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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
	"github.com/spf13/afero"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

// dataDir is a variable so it can be overridden by tests if needed
var dataDir = "/var/lib/cni/networks"

func networkDir(network string) string {
	return filepath.Join(dataDir, network)
}

// This is a hacky approach as we access the internals of the host-local plugin,
// instead of using the CNI interface. However, crafting a CNI DEL request from
// scratch would also be hacky.
func GarbageCollectContainerIPs(network string, desiredIPs sets.Set[string]) error {
	dir := networkDir(network)

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			klog.V(2).InfoS("Host-local IPAM data directory does not exist, nothing to do", "dir", dir)
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path '%s' is not a directory: %w", dir, err)
	}

	lk, err := disk.NewFileLock(dir)
	if err != nil {
		return err
	}
	defer lk.Close()
	lk.Lock()
	defer lk.Unlock()

	fs := afero.NewOsFs()
	return gcContainerIPs(fs, dir, desiredIPs)
}

// Internal version of GarbageCollectContainerIPs which does not acquire the
// file lock and can work with an arbitrary afero filesystem.
func gcContainerIPs(fs afero.Fs, dir string, desiredIPs sets.Set[string]) error {
	paths := make([]string, 0)

	if err := afero.Walk(fs, dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return fmt.Errorf("error when gathering IP filenames in the host-local data directory: %w", err)
	}

	hasRemovalError := false
	for _, p := range paths {
		ip := getIPFromPath(p)
		if net.ParseIP(ip) == nil {
			// not a valid IP, nothing to do
			continue
		}
		if desiredIPs.Has(ip) {
			// IP is in-use
			continue
		}
		if err := fs.Remove(p); err != nil {
			klog.ErrorS(err, "Failed to release unused IP from host-local IPAM plugin", "IP", ip)
			hasRemovalError = true
			continue
		}
		klog.InfoS("Unused IP was successfully released from host-local IPAM plugin", "IP", ip)
	}

	if hasRemovalError {
		return fmt.Errorf("not all unused IPs could be released from host-local IPAM plugin, some IPs may be leaked")
	}

	// Note that it is perfectly possible for some IPs to be in desiredIPs but not in the
	// host-local data directory. This can be the case when another IPAM plugin (e.g.,
	// AntreaIPAM) is also used.

	return nil
}

func getIPFromPath(path string) string {
	fname := filepath.Base(path)
	// need to unespace IPv6 addresses on Windows
	// see https://github.com/containernetworking/plugins/blob/38f18d26ecfef550b8bac02656cc11103fd7cff1/plugins/ipam/host-local/backend/disk/backend.go#L197
	if runtime.GOOS == "windows" {
		fname = strings.ReplaceAll(fname, "_", ":")
	}
	return fname
}

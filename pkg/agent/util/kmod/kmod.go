//go:build !windows
// +build !windows

// Copyright 2021 Antrea Authors
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

package kmod

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func modulesDir() (string, error) {
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return "", err
	}
	// unameBuf.Release is a fixed-size 65-byte array, we need to remove the trailing null
	// characters from it first.
	kernelVersionStr := string(bytes.TrimRight(unameBuf.Release[:], "\x00"))
	return path.Join("/lib/modules", kernelVersionStr), nil
}

func searchBuiltinModules(modulesDir string, suffix string) (bool, error) {
	builtinFile := path.Join(modulesDir, "modules.builtin")
	f, err := os.Open(builtinFile)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Splits on newlines by default.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), suffix) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// CheckIfKernelModuleExists checks if a kernel module exists. It searches for the corresponding .ko
// file in /lib/modules and, if includeBuiltinModules is true, it also searches through the list of
// built-in modules. name is the name of the module. subPath limits the search to a specific
// sub-directory; use an empty string if you are unsure about which value to provide.
func CheckIfKernelModuleExists(name string, subPath string, includeBuiltinModules bool) (bool, error) {
	dir, err := modulesDir()
	if err != nil {
		return false, fmt.Errorf("cannot determine modules directory: %w", err)
	}
	dir = path.Join(dir, subPath)
	expectedSuffix := fmt.Sprintf("/%s.ko", name)

	if includeBuiltinModules {
		moduleFound, err := searchBuiltinModules(dir, expectedSuffix)
		if err != nil {
			return false, fmt.Errorf("error when searching in modules.builtin: %w", err)
		}
		if moduleFound {
			return true, nil
		}
		// continue on to loadable modules
	}

	// sentinel error value used to end the walk early when the module file is found.
	moduleFoundError := errors.New("ending walk early")
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, expectedSuffix) {
			return moduleFoundError
		}
		return nil
	})
	if err != nil && err != moduleFoundError {
		return false, fmt.Errorf("error when searching for module in %s: %w", dir, err)
	}
	return (err == moduleFoundError), nil
}

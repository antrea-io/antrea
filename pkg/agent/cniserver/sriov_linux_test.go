//go:build linux
// +build linux

// Copyright 2025 Antrea Authors
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

package cniserver

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper to create a fake net directory with interface names
func createFakeVFNetDir(t *testing.T, base string, pciAddr string, interfaces []string) string {
	vfNetDir := filepath.Join(base, pciAddr, "net")
	if err := os.MkdirAll(vfNetDir, 0755); err != nil {
		t.Fatalf("failed to create fake VF dir: %v", err)
	}

	for _, iface := range interfaces {
		ifacePath := filepath.Join(vfNetDir, iface)
		if err := os.Mkdir(ifacePath, 0755); err != nil {
			t.Fatalf("failed to create fake interface dir: %v", err)
		}
	}
	return vfNetDir
}

func fakeSysBusPCI(tmpDir string) func() {
	oldSysBusPCI := SysBusPCI
	SysBusPCI = tmpDir
	return func() { SysBusPCI = oldSysBusPCI }
}

func TestGetVFLinkName_Success(t *testing.T) {
	tmpDir := t.TempDir()
	defer fakeSysBusPCI(tmpDir)()

	pciAddr := "0000:03:00.1"
	ifaces := []string{"eth0", "eth1"}
	createFakeVFNetDir(t, tmpDir, pciAddr, ifaces)

	name, err := GetVFLinkName(pciAddr)
	assert.NoError(t, err)
	assert.Equal(t, "eth0", name)
}

func TestGetVFLinkName_NoDir(t *testing.T) {
	tmpDir := t.TempDir()
	defer fakeSysBusPCI(tmpDir)()

	_, err := GetVFLinkName("0000:99:99.9")
	assert.ErrorContains(t, err, "no such file or directory")
}

func TestGetVFLinkName_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	defer fakeSysBusPCI(tmpDir)()

	pciAddr := "0000:04:00.0"
	vfNetDir := filepath.Join(tmpDir, pciAddr, "net")
	if err := os.MkdirAll(vfNetDir, 0755); err != nil {
		t.Fatalf("failed to create empty vf dir: %v", err)
	}

	_, err := GetVFLinkName(pciAddr)
	assert.EqualError(t, err, fmt.Sprintf("VF device %s sysfs path (%s) has no entries", pciAddr, vfNetDir))
}

// +build !windows

// Copyright 2020 Antrea Authors
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

package iptables

import (
	"os"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/rand"
)

func TestLock(t *testing.T) {
	filePath1 := "/tmp/xtables.lock." + rand.String(8)
	filePath2 := "/tmp/xtables.lock." + rand.String(8)
	filePath3 := "/tmp/xtables.lock." + rand.String(8)
	filePath4 := "/tmp/xtables.lock." + rand.String(8)
	tests := []struct {
		name         string
		lockFilePath string
		prepareFunc  func(filePath string)
		wantErr      bool
	}{
		{
			name:         "non-existing-lock",
			lockFilePath: filePath1,
			wantErr:      false,
		},
		{
			name:         "lock-already-acquired",
			lockFilePath: filePath2,
			prepareFunc: func(filePath string) {
				Lock(filePath, 2*time.Second)
			},
			wantErr: true,
		},
		{
			name:         "lock-already-released",
			lockFilePath: filePath3,
			prepareFunc: func(filePath string) {
				unlockFunc, _ := Lock(filePath, 2*time.Second)
				unlockFunc()
			},
			wantErr: false,
		},
		{
			name:         "lock-released-in-one-second",
			lockFilePath: filePath4,
			prepareFunc: func(filePath string) {
				unlockFunc, _ := Lock(filePath, 2*time.Second)
				go func() {
					time.Sleep(1 * time.Second)
					unlockFunc()
				}()
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer os.Remove(tt.lockFilePath)
			if tt.prepareFunc != nil {
				tt.prepareFunc(tt.lockFilePath)
			}
			unlockFunc, err := Lock(tt.lockFilePath, 2*time.Second)
			if (err != nil) != tt.wantErr {
				t.Fatalf("lock() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if err := unlockFunc(); err != nil {
					t.Fatalf("unlock() error: %v", err)
				}
			}
		})
	}
}

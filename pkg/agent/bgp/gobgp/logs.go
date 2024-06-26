// Copyright 2024 Antrea Authors
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

package gobgp

import (
	"sort"

	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"k8s.io/klog/v2"
)

// goBGPLogger implements https://github.com/osrg/gobgp/blob/master/pkg/log/logger.go interface.
type goBGPLogger struct{}

func newGoBGPLogger() *goBGPLogger {
	return &goBGPLogger{}
}

func (g *goBGPLogger) Panic(msg string, fields gobgplog.Fields) {
	klog.ErrorS(nil, msg, toSlice(fields)...)
}

func (g *goBGPLogger) Fatal(msg string, fields gobgplog.Fields) {
	klog.ErrorS(nil, msg, toSlice(fields)...)
}

func (g *goBGPLogger) Error(msg string, fields gobgplog.Fields) {
	klog.ErrorS(nil, msg, toSlice(fields)...)
}

func (g *goBGPLogger) Warn(msg string, fields gobgplog.Fields) {
	klog.V(0).InfoS(msg, toSlice(fields)...)
}

func (g *goBGPLogger) Info(msg string, fields gobgplog.Fields) {
	klog.V(0).InfoS(msg, toSlice(fields)...)
}

func (g *goBGPLogger) Debug(msg string, fields gobgplog.Fields) {
	klog.V(4).InfoS(msg, toSlice(fields)...)
}

// This should never be used in Antrea.
func (g *goBGPLogger) SetLevel(level gobgplog.LogLevel) {
}

// This should never be used in Antrea.
func (g *goBGPLogger) GetLevel() gobgplog.LogLevel {
	return gobgplog.LogLevel(0)
}

func toSlice(fields gobgplog.Fields) []interface{} {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	args := make([]interface{}, 0, len(fields)*2)
	for _, key := range keys {
		args = append(args, key, fields[key])
	}
	return args
}

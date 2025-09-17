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
	"maps"
	"slices"

	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"k8s.io/klog/v2"
)

// goBGPLogger implements https://github.com/osrg/gobgp/blob/master/pkg/log/logger.go interface.
type goBGPLogger struct {
	routerID string
}

func newGoBGPLogger(routerID string) *goBGPLogger {
	return &goBGPLogger{
		routerID: routerID,
	}
}

// We use a depth of 1 for all log messages to get more useful source information.
// Otherwise, the reported source location would be the line where the klog function is invoked.

func (g *goBGPLogger) Panic(msg string, fields gobgplog.Fields) {
	klog.ErrorSDepth(1, nil, msg, g.logFieldsToKeysAndValues(fields)...)
}

func (g *goBGPLogger) Fatal(msg string, fields gobgplog.Fields) {
	klog.ErrorSDepth(1, nil, msg, g.logFieldsToKeysAndValues(fields)...)
}

func (g *goBGPLogger) Error(msg string, fields gobgplog.Fields) {
	klog.ErrorSDepth(1, nil, msg, g.logFieldsToKeysAndValues(fields)...)
}

func (g *goBGPLogger) Warn(msg string, fields gobgplog.Fields) {
	klog.V(0).InfoSDepth(1, msg, g.logFieldsToKeysAndValues(fields)...)
}

func (g *goBGPLogger) Info(msg string, fields gobgplog.Fields) {
	klog.V(0).InfoSDepth(1, msg, g.logFieldsToKeysAndValues(fields)...)
}

func (g *goBGPLogger) Debug(msg string, fields gobgplog.Fields) {
	klog.V(4).InfoSDepth(1, msg, g.logFieldsToKeysAndValues(fields)...)
}

// This should never be used in Antrea.
func (g *goBGPLogger) SetLevel(level gobgplog.LogLevel) {
}

// This should never be used in Antrea.
func (g *goBGPLogger) GetLevel() gobgplog.LogLevel {
	return gobgplog.LogLevel(0)
}

func (g *goBGPLogger) logFieldsToKeysAndValues(fields gobgplog.Fields) []interface{} {
	keysAndValues := make([]interface{}, 0, (len(fields)+1)*2)
	// Add routerID to all log messages for more context.
	keysAndValues = append(keysAndValues, "routerID", g.routerID)
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		keysAndValues = append(keysAndValues, key, fields[key])
	}
	return keysAndValues
}

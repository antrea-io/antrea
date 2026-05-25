// Copyright 2026 Antrea Authors
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
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
)

// gobgpWrapperLog is used to simulate GoBGP's internal wrapper for testing
// the dynamic call stack depth calculation.
// It returns the line number of the logger.Info call so the test can assert it dynamically.
func gobgpWrapperLog(logger *slog.Logger) int {
	_, _, line, _ := runtime.Caller(0)
	expectedLine := line + 2
	logger.Info("wrapper message",
		slog.String("wrapper_k1", "wrapper_v1"),
	)
	return expectedLine
}

func TestKlogHandler_With(t *testing.T) {
	logger, _ := newGoBGPLogger("1.1.1.1")
	h1 := logger.Handler().(*klogHandler)

	// Test WithAttrs
	h2 := h1.WithAttrs([]slog.Attr{slog.String("k1", "v1")}).(*klogHandler)
	assert.Empty(t, h1.attrs, "original handler should not be mutated")
	assert.Equal(t, []slog.Attr{slog.String("k1", "v1")}, h2.attrs)

	// Test WithGroup
	h3 := h2.WithGroup("g1").(*klogHandler)
	// h3.inner will be wrapped with a group, but h3.attrs remains the same
	assert.Equal(t, []slog.Attr{slog.String("k1", "v1")}, h3.attrs)

	// Test WithAttrs after WithGroup
	h4 := h3.WithAttrs([]slog.Attr{slog.String("k2", "v2")}).(*klogHandler)
	assert.Equal(t, []slog.Attr{slog.String("k1", "v1")}, h3.attrs, "original handler should not be mutated")
	assert.Equal(t, []slog.Attr{slog.String("k1", "v1"), slog.String("k2", "v2")}, h4.attrs)
}

// Helper function to simulate GoBGP internal wrapper and test depth calculation
func TestKlogHandler_Handle(t *testing.T) {
	// Redirect klog output to a buffer.
	var buf bytes.Buffer
	// Create a local FlagSet to avoid mutating the global flag.CommandLine. This ensures our klog configuration
	// (like verbosity) is strictly isolated to this test and won't cause flaky behavior in other concurrent tests.
	klogFlagSet := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(klogFlagSet)
	require.NoError(t, klogFlagSet.Set("logtostderr", "false"))
	require.NoError(t, klogFlagSet.Set("v", "4"))
	klog.SetOutput(&buf)
	defer klog.SetOutput(os.Stderr) // Reset to standard error after test

	logger, _ := newGoBGPLogger("1.1.1.1")

	// Test Info log
	_, _, line, _ := runtime.Caller(0)
	logger.Info("info message", slog.String("key1", "value1"))
	klog.Flush()
	output := buf.String()
	// Assert the presence of the caller location and each expected key/value as separate substrings.
	// This is because neither slog nor klog guarantee a stable attribute ordering in their text output.
	// Hard-coding the exact string (e.g., key1 before routerID) would make the test brittle across Go/klog versions.
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "info message"`, line+1))
	assert.Contains(t, output, `key1="value1"`)
	assert.Contains(t, output, `routerID="1.1.1.1"`)
	buf.Reset()

	// Test Warn log
	_, _, line, _ = runtime.Caller(0)
	logger.Warn("warn message", slog.String("key2", "value2"))
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "warn message"`, line+1))
	assert.Contains(t, output, `key2="value2"`)
	assert.Contains(t, output, `routerID="1.1.1.1"`)
	assert.Regexp(t, `(?m)^W\d{4} `, output) // klog Warn prefix (W<MMDD>)
	buf.Reset()

	// Test Error log
	_, _, line, _ = runtime.Caller(0)
	logger.Error("error message")
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "error message"`, line+1))
	assert.Contains(t, output, `routerID="1.1.1.1"`)
	assert.Regexp(t, `(?m)^E\d{4} `, output) // klog Error prefix (E<MMDD>)
	buf.Reset()

	// Test Debug log
	_, _, line, _ = runtime.Caller(0)
	logger.Debug("debug message")
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "debug message"`, line+1))
	assert.Contains(t, output, `routerID="1.1.1.1"`)
	buf.Reset()

	// Test nested groups with WithGroup and inline groups
	// GoBGP doesn't currently use this, but we test it to ensure the underlying
	// logr.ToSlogHandler handles it correctly if GoBGP ever does.
	nestedLogger := logger.WithGroup("outer").
		With("k1", "v1")
	_, _, line, _ = runtime.Caller(0)
	nestedLogger.Info("nested message", slog.String("k2", "v2"))
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "nested message"`, line+1))
	assert.Contains(t, output, `outer.k2="v2"`)
	assert.Contains(t, output, `outer.routerID="1.1.1.1"`)
	assert.Contains(t, output, `outer.k1="v1"`)
	buf.Reset()

	// Test depth calculation through a wrapper function
	wrapperLine := gobgpWrapperLog(logger)
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_test.go:%d] "wrapper message"`, wrapperLine))
	assert.Contains(t, output, `wrapper_k1="wrapper_v1"`)
	assert.Contains(t, output, `routerID="1.1.1.1"`)
	buf.Reset()

	// Test depth calculation through a wrapper function in another file
	extWrapperLine := gobgpExternalWrapperLog(logger)
	klog.Flush()
	output = buf.String()
	assert.Contains(t, output, fmt.Sprintf(`logs_external_wrapper_test.go:%d] "external wrapper message"`, extWrapperLine))
	assert.Contains(t, output, `ext_k1="ext_v1"`)
	assert.Contains(t, output, `routerID="1.1.1.1"`)
}

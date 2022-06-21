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

// Package log processes the klog flags, and enforces the maximum log file
// size and maximum log file number limits.
package log

import (
	"flag"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

const (
	logFlushFreqFlag = "log-flush-frequency"
)

var (
	klogFlags = flag.NewFlagSet("logging", flag.ContinueOnError)

	logFlushFreq time.Duration
)

func init() {
	klog.InitFlags(klogFlags)
}

func addKlogFlags(fs *pflag.FlagSet) {
	klogFlags.VisitAll(func(f *flag.Flag) {
		pf := pflag.PFlagFromGoFlag(f)
		fs.AddFlag(pf)
	})
}

func AddFlags(fs *pflag.FlagSet) {
	addKlogFlags(fs)
	fs.Uint16Var(&maxNumArg, maxNumFlag, maxNumArg, "Maximum number of log files per severity level to be kept. Value 0 means unlimited.")
	fs.DurationVar(&logFlushFreq, logFlushFreqFlag, 5*time.Second, "Maximum number of seconds between log flushes")
}

type Options struct {
	withFlushDaemon bool
}

func WithoutFlushDaemon(options *Options) {
	options.withFlushDaemon = false
}

func initKlog(options *Options) {
	if options.withFlushDaemon {
		klog.StartFlushDaemon(logFlushFreq)
	}
	klog.EnableContextualLogging(false)
}

func InitLogs(fs *pflag.FlagSet, opts ...func(options *Options)) {
	options := Options{
		withFlushDaemon: true,
	}
	for _, opt := range opts {
		opt(&options)
	}
	initKlog(&options)
	initLogFileLimits(fs)
	initLogLevelManager(fs)
}

func FlushLogs() {
	klog.Flush()
}

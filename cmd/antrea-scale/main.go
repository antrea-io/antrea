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

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"k8s.io/klog/v2"

	"antrea.io/antrea/test/performance/config"
	"antrea.io/antrea/test/performance/framework"
)

type options struct {
	kubeConfigPath string
	configPath     string
	timeout        int
	loglevel       string
}

var (
	option = options{}
)

func init() {
	flag.StringVar(&option.kubeConfigPath, "kubeConfigPath", "", "Cluster config path")
	flag.StringVar(&option.configPath, "config", "", "Config file of scale test cases list")
	flag.IntVar(&option.timeout, "timeout", 10, "Timeout limit (minutes) of the whole scale test")
	flag.StringVar(&option.loglevel, "v", "2", "")
	flag.Parse()
}

func main() {
	var l klog.Level
	if err := l.Set(option.loglevel); err != nil {
		klog.ErrorS(err, "Set log level error")
		return
	}
	startTime := time.Now()
	klog.InfoS("Starting scale test", "startTime", startTime)
	defer func() {
		klog.InfoS("Shutting down scale test", "durationTime", time.Since(startTime))
	}()
	if err := run(); err != nil {
		klog.Fatalf("Test failed: %v", err)
	}
}

func run() error {
	globalCtx, globalCancelFunc := context.WithTimeout(context.Background(), time.Duration(option.timeout)*time.Minute)
	defer globalCancelFunc()

	testData, err := framework.ScaleUp(globalCtx, option.kubeConfigPath, option.configPath)
	if err != nil {
		return fmt.Errorf("error when creating TestData: %w", err)
	}

	defer func() {
		if testData.Specification.TearDown {
			if err := testData.ScaleDown(context.TODO()); err != nil {
				klog.ErrorS(err, "Destroy Test Namespace error")
			}
		}
	}()

	for _, tc := range testData.Specification.Scales {
		if tc.RepeatTimes <= 0 {
			klog.InfoS("Skip test", "Case", tc)
		}
		for i := 0; i < tc.RepeatTimes; i++ {
			klog.InfoS("Start test", "Case", tc, "Repeat", i+1)
			tCase, err := framework.NewScaleTestCase(tc.Name, false)
			if err != nil {
				return err
			}
			if err := tCase.Run(globalCtx, testData); err != nil {
				return err
			}
			time.Sleep(config.WaitInterval)
		}
		klog.Infoln(strings.Repeat("==", 100))
	}
	return nil
}

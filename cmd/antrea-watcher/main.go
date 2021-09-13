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

// Package main under directory cmd parses and validates user input,
// instantiates and initializes objects imported from pkg, and runs
// the process.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/signals"
	"antrea.io/antrea/pkg/util/k8s"
)

type Options struct {
	// The path to the K8s configuration file
	kubeConfig string
}

func main() {
	stopCh := signals.RegisterSignalHandlers()
	opts := &Options{}

	cmd := &cobra.Command{
		Use:  "antrea-watcher",
		Long: "The Antrea Watcher.",
		Run: func(cmd *cobra.Command, args []string) {
			wait.Until(func() {
				if err := run(opts, stopCh); err != nil {
					klog.ErrorS(err, "Failed to watch config files, will retry later")
				}
			}, time.Minute, stopCh)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.kubeConfig, "kube-config", opts.kubeConfig, "The path to the K8s configuration file")

	if err := cmd.Execute(); err != nil {
		klog.Errorf("fail to run watcher %v", err)
		os.Exit(1)
	}
}

func run(opts *Options, stopCh <-chan struct{}) error {
	k8sClient, _, _, _, err := k8s.CreateClients(config.ClientConnectionConfiguration{Kubeconfig: opts.kubeConfig}, "")
	if err != nil {
		return fmt.Errorf("fail to create K8s client: %v", err)
	}
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 60*time.Minute)
	watcher := NewWatcher(k8sClient, informerFactory)
	informerFactory.Start(stopCh)
	go watcher.Run(stopCh)
	<-stopCh
	klog.Info("Stopping Antrea Watcher")
	return nil
}

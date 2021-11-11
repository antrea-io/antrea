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
	"fmt"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"github.com/spf13/pflag"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Options struct {
	// The path of configuration file.
	configFile     string
	SelfSignedCert bool
	options        ctrl.Options
}

func newOptions() *Options {
	return &Options{
		// TODO: remove cert-manager dependency and
		// use self signed cert in the future
		SelfSignedCert: false,
	}
}

func (o *Options) complete(args []string) error {
	var err error
	options := ctrl.Options{Scheme: scheme}
	ctrlConfig := &mcsv1alpha1.MultiClusterConfig{}
	if len(o.configFile) > 0 {
		options, err = options.AndFrom(ctrl.ConfigFile().AtPath(o.configFile).OfKind(ctrlConfig))
		if err != nil {
			return fmt.Errorf("fail to load options from configuration file %s", o.configFile)
		}
		o.options = options
	}
	o.setDefaults()
	return nil
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

func (o *Options) setDefaults() {
	o.options = ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     ":8080",
		Port:                   9443,
		HealthProbeBindAddress: ":8081",
		LeaderElection:         false,
	}
}

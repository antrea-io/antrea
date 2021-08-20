// Copyright 2019 Antrea Authors
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
	"errors"
	"io/ioutil"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/features"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *ControllerConfig
}

func newOptions() *Options {
	return &Options{
		config: &ControllerConfig{
			EnablePrometheusMetrics: true,
			SelfSignedCert:          true,
			LegacyCRDMirroring:      true,
		},
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		if err := o.loadConfigFromFile(); err != nil {
			return err
		}
	}
	o.setDefaults()
	return features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
}

// validate validates all the required options.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no positional arguments are supported")
	}
	return nil
}

func (o *Options) loadConfigFromFile() error {
	data, err := ioutil.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	return yaml.UnmarshalStrict(data, &o.config)
}

func (o *Options) setDefaults() {
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaControllerAPIPort
	}

	// These defaults override the client-go defaults of 5.0 for QPS and 20
	// for Burst (https://pkg.go.dev/k8s.io/client-go@v0.21.1/rest#Config).
	// These values will be used for all the Controller's clientsets, and in
	// particular the CRD clientset. We have observed that these defaults
	// work much better for the CRD mirroring controller when Antrea is
	// upgraded in a cluster with a large number of existing Antrea-native
	// policies. In this scenario, the mirroring controller needs to mirror
	// many legacy (*.antrea.tanzu.vmware.com) CRDs to their crd.antrea.io
	// replacement, which will take a very long time with client-go's QPS
	// and Burst defaults.
	if o.config.ClientConnection.QPS == 0.0 {
		o.config.ClientConnection.QPS = 50
	}
	if o.config.ClientConnection.Burst == 0 {
		o.config.ClientConnection.Burst = 200
	}
}

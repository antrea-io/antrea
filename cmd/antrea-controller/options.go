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

	"github.com/vmware-tanzu/antrea/pkg/apis"
	"github.com/vmware-tanzu/antrea/pkg/features"
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
}

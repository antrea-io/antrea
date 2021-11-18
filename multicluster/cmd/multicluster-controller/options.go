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
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

type Options struct {
	// The path of configuration file.
	configFile     string
	SelfSignedCert bool
	options        ctrl.Options
	leader         bool
	member         bool
}

func newOptions() *Options {
	return &Options{
		SelfSignedCert: true,
	}
}

func (o *Options) complete(args []string) error {
	var err error
	o.setDefaults()
	options := ctrl.Options{Scheme: scheme}
	ctrlConfig := &mcsv1alpha1.MultiClusterConfig{}
	if len(o.configFile) > 0 {
		// TODO: remove this and just use the options from ctrlConfig
		options, err = options.AndFrom(ctrl.ConfigFile().AtPath(o.configFile).OfKind(ctrlConfig))
		if err != nil {
			return fmt.Errorf("fail to load options from configuration file %s", o.configFile)
		}
		o.options = options
		data, err := ioutil.ReadFile(o.configFile)
		if err != nil {
			return err
		}
		jsonData, err := yaml.ToJSON(data)
		if err != nil {
			klog.Errorf("Error converting to json", string(data))
			return err
		}
		err = json.Unmarshal(jsonData, &ctrlConfig)
		if err != nil {
			klog.Errorf("Error unmarshalling json", string(jsonData))
			return err
		}
		o.leader = ctrlConfig.Leader
		if o.leader {
			klog.InfoS("Running as Leader Cluster of ClusterSet")
		}
		o.member = ctrlConfig.Member
		if o.member {
			klog.InfoS("Running as Member Cluster of ClusterSet")
		}
		return nil
	}
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
	o.member = true
}

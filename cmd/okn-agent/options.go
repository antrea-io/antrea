package main

import (
	"errors"
	"io/ioutil"

	"okn/pkg/cni"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *AgentConfig
}

func newOptions() *Options {
	return &Options{
		config: new(AgentConfig),
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file.")
}

// complete completes all the required options.
func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		c, err := o.loadConfigFromFile(o.configFile)
		if err != nil {
			return err
		}
		o.config = c
	}
	o.setDefaults()
	return nil
}

// validate validates all the required options.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no arguments are supported")
	}
	return nil
}

func (o *Options) loadConfigFromFile(file string) (*AgentConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var c AgentConfig
	err = yaml.UnmarshalStrict(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (o *Options) setDefaults() {
	if o.config.CNISocket == "" {
		o.config.CNISocket = cni.OKNCniAddr
	}
}

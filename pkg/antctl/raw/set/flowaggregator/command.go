// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowaggregator

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"antrea.io/antrea/pkg/antctl/raw"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
)

// Command is the support bundle command implementation.
var Command *cobra.Command

type FlowAggregatorConfigMutator func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error

var mutators map[string]FlowAggregatorConfigMutator

var getClients = getk8sClient

var example = strings.Trim(`
  Enable ClickHouse
  $ antctl set flow-aggregator clickHouse.enable=true
  Update ClickHouse database
  $ antctl set flow-aggregator clickHouse.database=name
  Update ClickHouse databaseURL
  $ antctl set flow-aggregator clickHouse.databaseURL=http://xxxxx
  Update ClickHouse debug
  $ antctl set flow-aggregator clickHouse.debug=true
  Update ClickHouse compress
  $ antctl set flow-aggregator clickHouse.compress=true
  Update ClickHouse commitInterval
  $ antctl set flow-aggregator clickHouse.commitInterval=10s
  Update IPFIX Flow Collector address
  $ antctl set flow-aggregator flowCollector.address=<IP>:<port>[:<proto>]
  Enable IPFIX Flow Collector
  $ antctl set flow-aggregator flowCollector.enable=true
`, "\n")

func NewFlowAggregatorSetCommand() *cobra.Command {
	Command = &cobra.Command{
		Use:     "flow-aggregator",
		Short:   "Update configuration parameters used in Flow Aggregator",
		Example: example,
		RunE:    updateRunE,
	}
	mutators = map[string]FlowAggregatorConfigMutator{
		"clickHouse.enable": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setBoolOrFail(&c.ClickHouse.Enable, value)
		},
		"clickHouse.database": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setStringOrFail(&c.ClickHouse.Database, value)
		},
		"clickHouse.databaseURL": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setStringOrFail(&c.ClickHouse.DatabaseURL, value)
		},
		"clickHouse.debug": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setBoolOrFail(&c.ClickHouse.Debug, value)
		},
		"clickHouse.compress": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			if c.ClickHouse.Compress == nil {
				c.ClickHouse.Compress = new(bool)
			}
			return setBoolOrFail(c.ClickHouse.Compress, value)
		},
		"clickHouse.commitInterval": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setCommitIntervalOrFail(&c.ClickHouse.CommitInterval, value)
		},
		"flowCollector.enable": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setBoolOrFail(&c.FlowCollector.Enable, value)
		},
		"flowCollector.address": func(c *flowaggregatorconfig.FlowAggregatorConfig, value string) error {
			return setStringOrFail(&c.FlowCollector.Address, value)
		},
	}
	return Command
}

func getk8sClient(cmd *cobra.Command) (kubernetes.Interface, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, err
	}
	k8sClient, _, err := raw.SetupClients(kubeconfig)
	return k8sClient, err
}

func updateRunE(cmd *cobra.Command, args []string) error {
	k8sClient, err := getClients(cmd)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}
	configMapName := os.Getenv("FA_CONFIG_MAP_NAME")
	configMap, err := GetFAConfigMap(k8sClient, configMapName)
	if err != nil {
		return err
	}
	var flowAggregatorConf flowaggregatorconfig.FlowAggregatorConfig
	if err := yaml.Unmarshal([]byte(configMap.Data["flow-aggregator.conf"]), &flowAggregatorConf); err != nil {
		return err
	}
	for _, query := range args {
		pair := strings.Split(query, "=")
		if len(pair) != 2 {
			return fmt.Errorf("query should contain exactly one '='")
		}
		mutatorFn, ok := mutators[pair[0]]
		if !ok {
			return fmt.Errorf("unknown configuration parameter, please check antctl set flow-aggregator -h")
		}
		if err := mutatorFn(&flowAggregatorConf, pair[1]); err != nil {
			return err
		}
	}
	// marshal back the changed parameters to configmap
	b, err := yaml.Marshal(&flowAggregatorConf)
	if err != nil {
		return err
	}

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	configMap.Data["flow-aggregator.conf"] = string(b)
	if _, err := k8sClient.CoreV1().ConfigMaps(os.Getenv("POD_NAMESPACE")).Update(context.TODO(), configMap, metav1.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

func setBoolOrFail(b *bool, value string) error {
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	*b = boolValue
	return nil
}

func setStringOrFail(b *string, value string) error {
	*b = value
	return nil
}

func setCommitIntervalOrFail(b *string, value string) error {
	commitInterval, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	if commitInterval < flowaggregatorconfig.MinClickHouseCommitInterval {
		return fmt.Errorf("commitInterval %s is too small: shortest supported interval is %s", commitInterval, flowaggregatorconfig.MinClickHouseCommitInterval)
	}
	*b = value
	return nil
}

// GetFAConfigMap is used to get and return the flow-aggregator configmap
func GetFAConfigMap(k8sClient kubernetes.Interface, configMapName string) (*corev1.ConfigMap, error) {
	if len(configMapName) == 0 {
		return nil, fmt.Errorf("failed to locate %s ConfigMap volume", "flow-aggregator-config")
	}
	configMap, err := k8sClient.CoreV1().ConfigMaps("flow-aggregator").Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s: %v", configMapName, err)
	}
	return configMap, nil
}

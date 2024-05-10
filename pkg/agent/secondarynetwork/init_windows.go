//go:build windows
// +build windows

// Copyright 2024 Antrea Authors
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

package secondarynetwork

import (
	"errors"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	componentbaseconfig "k8s.io/component-base/config"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/util/channel"
)

func Initialize(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	nodeName string,
	podUpdateSubscriber channel.Subscriber,
	stopCh <-chan struct{},
	secNetConfig *agentconfig.SecondaryNetworkConfig, ovsdb *ovsdb.OVSDB) error {
	return errors.New("not supported on Windows")
}

func RestoreHostInterfaceConfiguration(secNetConfig *agentconfig.SecondaryNetworkConfig) {
	// Not supported on Windows.
}

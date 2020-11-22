// +build windows

// Copyright 2020 Antrea Authors
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

package nodeportlocal

import (
	"errors"

	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
)

// InitializeNPLAgent starts NodePortLocal (NPL) agent.
// Currently NPL is disabled for windows.
func InitializeNPLAgent(kubeClient clientset.Interface, informerFactory informers.SharedInformerFactory, portRange string, stop <-chan struct{}) error {
	return errors.New("Windows Platform not supported fot NPL")
}

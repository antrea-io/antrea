// Copyright 2022 Antrea Authors
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

package scheme

import (
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	mcsscheme "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/scheme"

	antreamcscheme "antrea.io/antrea/multicluster/pkg/client/clientset/versioned/scheme"
)

var Scheme = k8sruntime.NewScheme()

func init() {
	utilruntime.Must(mcsscheme.AddToScheme(Scheme))
	utilruntime.Must(antreamcscheme.AddToScheme(Scheme))
	utilruntime.Must(k8sscheme.AddToScheme(Scheme))
}

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

package framework

import (
	"context"

	"antrea.io/antrea/test/performance/framework/namespace"
)

// ScaleDown delete pods/ns and verify if it gets deleted
func (data *ScaleData) ScaleDown(ctx context.Context) error {
	return namespace.ScaleDown(ctx, data.kubernetesClientSet, ScaleTestNamespacePrefix)
}

// ScaleDownOnlyPods delete pods only so it will get recreated inside same ns
func (data *ScaleData) ScaleDownOnlyPods(ctx context.Context) error {
	return nil
}

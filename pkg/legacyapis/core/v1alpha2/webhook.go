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

package v1alpha2

import (
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
)

// WebhookImpl implements webhook validator of a resource.
type WebhookImpl interface {
	Default(in *ExternalEntity)
	ValidateCreate(in *ExternalEntity) error
	ValidateUpdate(in *ExternalEntity, old runtime.Object) error
	ValidateDelete(in *ExternalEntity) error
}

var (
	externalEntityWebhook WebhookImpl
)

// RegisterWebhook registers webhook implementation of a resource.
func RegisterWebhook(in runtime.Object, webhook WebhookImpl) error {
	switch in.(type) {
	case *ExternalEntity:
		if externalEntityWebhook != nil {
			return fmt.Errorf("externalEntityWebhook already registered")
		}
		externalEntityWebhook = webhook
	default:
		return fmt.Errorf("unknown type %s to register webhook", reflect.TypeOf(in).Elem().Name())
	}
	return nil
}

// Default implements webhook Defaulter.
func (in *ExternalEntity) Default() {
	if externalEntityWebhook != nil {
		externalEntityWebhook.Default(in)
	}
	return
}

// ValidateCreate implements webhook Validator.
func (in *ExternalEntity) ValidateCreate() error {
	if externalEntityWebhook != nil {
		return externalEntityWebhook.ValidateCreate(in)
	}
	return nil
}

// ValidateUpdate implements webhook Validator.
func (in *ExternalEntity) ValidateUpdate(old runtime.Object) error {
	if externalEntityWebhook != nil {
		return externalEntityWebhook.ValidateUpdate(in, old)
	}

	return nil
}

// ValidateDelete implements webhook Validator.
func (in *ExternalEntity) ValidateDelete() error {
	if externalEntityWebhook != nil {
		return externalEntityWebhook.ValidateDelete(in)
	}
	return nil
}

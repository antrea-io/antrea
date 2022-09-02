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

package common

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type FakeCtrlRuntimeClient struct {
	client.Client
	ShouldError bool
}

func (fc FakeCtrlRuntimeClient) Create(
	ctx context.Context,
	obj client.Object,
	opts ...client.CreateOption) error {
	if fc.ShouldError {
		return errors.New("failed to create object")
	}
	return fc.Client.Create(ctx, obj)
}

func (fc FakeCtrlRuntimeClient) Update(
	ctx context.Context,
	obj client.Object,
	opts ...client.UpdateOption) error {
	if fc.ShouldError {
		return errors.New("failed to update object")
	}
	return fc.Client.Update(ctx, obj)
}

func (fc FakeCtrlRuntimeClient) Delete(
	ctx context.Context,
	obj client.Object,
	opts ...client.DeleteOption) error {
	if fc.ShouldError {
		return errors.New("failed to delete object")
	}
	return fc.Client.Delete(ctx, obj)
}

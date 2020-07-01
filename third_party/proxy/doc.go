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

// Package proxy is copied from
// k8s.io/kubernetes@/v1.17.6(https://github.com/kubernetes/kubernetes/tree/v1.17.6)
// to avoid importing the whole kubernetes repo. Some unneeded functions are removed.

package proxy

// TODO: remove this package once the github.com/kubernetes/pkg/proxy becomes
// an independent module

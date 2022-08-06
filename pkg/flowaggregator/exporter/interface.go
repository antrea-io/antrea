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

package exporter

import (
	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"

	"antrea.io/antrea/pkg/flowaggregator/options"
)

// Interface is the interface that all supported exporters must implement.
// Note that the objects implementing this interface make no concurrency
// guarantee: none of the interface functions should be called concurrently.
type Interface interface {
	Start()
	Stop()
	AddRecord(record ipfixentities.Record, isRecordIPv6 bool) error
	UpdateOptions(opt *options.Options)
}

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

package yaml

import (
	"bytes"

	"go.yaml.in/yaml/v3"
	"k8s.io/klog/v2"
)

// UnmarshalLenient tries strict decoding first, then fall back to lenient decoding, which tolerates unknown fields
// (note that duplicate fields will still cause an error). It's typically used to avoid error when the provided data
// contains new fields that are not yet known to this version of code, which may happen when doing upgrade.
func UnmarshalLenient(data []byte, v interface{}) error {
	strictErr := func() error {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		return dec.Decode(v)
	}()
	if strictErr != nil {
		err := yaml.Unmarshal(data, v)
		if err != nil {
			// The data is malformed, return the original strict error.
			return strictErr
		}
		if e, ok := strictErr.(*yaml.TypeError); ok {
			// TypeError.Errors is a []string slice; log each entry directly.
			klog.InfoS("Used lenient decoding as strict decoding failed", "err", e.Errors)
		} else {
			klog.InfoS("Used lenient decoding as strict decoding failed", "err", e)
		}
	}
	return nil
}

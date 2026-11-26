// Copyright 2026 Antrea Authors
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
	"io"

	"go.yaml.in/yaml/v4"
)

// NewDumper returns a YAML Dumper with the output settings of the go-yaml v3
// Encoder and the given indentation. The line width is set explicitly because
// in go-yaml v4.0.0, both yaml.NewEncoder and yaml.WithV3Defaults() wrap long
// lines at 80 columns, while the v3 Encoder never wrapped them; see
// https://github.com/yaml/go-yaml/issues/525.
func NewDumper(w io.Writer, indent int) (*yaml.Dumper, error) {
	return yaml.NewDumper(w, yaml.WithV3Defaults(), yaml.WithIndent(indent), yaml.WithLineWidth(-1))
}

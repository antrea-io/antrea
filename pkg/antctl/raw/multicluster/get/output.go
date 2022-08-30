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

package get

import (
	"io"

	antctlOutput "antrea.io/antrea/pkg/antctl/output"
)

func output(resources interface{}, single bool, outputFormat string, output io.Writer,
	transform func(r interface{}, single bool) (interface{}, error)) error {
	switch outputFormat {
	case "json":
		if err := antctlOutput.JsonOutput(resources, output); err != nil {
			return err
		}
	case "yaml":
		if err := antctlOutput.YamlOutput(resources, output); err != nil {
			return err
		}
	default:
		obj, err := transform(resources, single)
		if err != nil {
			return err
		}
		err = antctlOutput.TableOutputForGetCommands(obj, output)
		if err != nil {
			return err
		}
	}

	return nil
}

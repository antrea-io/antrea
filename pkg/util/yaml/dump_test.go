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
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDumper(t *testing.T) {
	type Nested struct {
		Message string `yaml:"message"`
	}
	type Config struct {
		LongField string `yaml:"longField"`
		Nested    Nested `yaml:"nested"`
	}

	longString := "this is a very long string that exceeds the default 80 column width limit of go-yaml v4 and should not be wrapped onto multiple lines"
	cfg := Config{
		LongField: longString,
		Nested: Nested{
			Message: "hello world",
		},
	}

	tests := []struct {
		name           string
		indent         int
		expectedIndent string
	}{
		{
			name:           "indent 2",
			indent:         2,
			expectedIndent: "  message: hello world\n",
		},
		{
			name:           "indent 4",
			indent:         4,
			expectedIndent: "    message: hello world\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			dumper, err := NewDumper(&buf, tt.indent)
			require.NoError(t, err)
			require.NoError(t, dumper.Dump(cfg))
			require.NoError(t, dumper.Close())

			output := buf.String()

			// Verify long string is not wrapped
			expectedLine := "longField: " + longString
			assert.Contains(t, output, expectedLine)

			// Verify no line wrapping inside longField
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "longField:") {
					assert.Equal(t, expectedLine, line)
				}
			}

			// Verify indentation
			assert.Contains(t, output, tt.expectedIndent)
		})
	}
}

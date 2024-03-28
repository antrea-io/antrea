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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalLenient(t *testing.T) {
	type SubConfig struct {
		SubFoo string `yaml:"subFoo"`
	}
	type Config struct {
		Foo string    `yaml:"foo"`
		Bar int       `yaml:"bar"`
		Baz SubConfig `yaml:"baz"`
	}
	tests := []struct {
		name      string
		data      []byte
		expectedV *Config
		wantErr   bool
	}{
		{
			name: "correct data",
			data: []byte(`
foo: abc
bar: 123
baz:
  subFoo: xyz
`),
			expectedV: &Config{
				Foo: "abc",
				Bar: 123,
				Baz: SubConfig{SubFoo: "xyz"},
			},
		},
		{
			name: "unmatched type",
			data: []byte(`
foo: abc
bar: abc
`),
			wantErr: true,
		},
		{
			name: "malformed data",
			data: []byte(`
foo: abc
 bar: 123
`),
			wantErr: true,
		},
		{
			name: "duplicate field",
			data: []byte(`
foo: abc
bar: 123
foo: abcd
`),
			expectedV: &Config{
				Foo: "abcd",
				Bar: 123,
			},
		},
		{
			name: "unknown field",
			data: []byte(`
foo: abc
bar: 123
newBar: xyz
`),
			expectedV: &Config{
				Foo: "abc",
				Bar: 123,
			},
		},
		{
			name: "unknown nested field",
			data: []byte(`
foo: abc
bar: 123
baz:
  subFoo: xyz
  subBar: 123
`),
			expectedV: &Config{
				Foo: "abc",
				Bar: 123,
				Baz: SubConfig{SubFoo: "xyz"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotV := &Config{}
			err := UnmarshalLenient(tt.data, gotV)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedV, gotV)
		})
	}
}

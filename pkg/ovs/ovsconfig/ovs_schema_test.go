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

package ovsconfig

import (
	"encoding/json"
	"testing"

	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOVSDBSchemaLargeIntegerBounds guards against the schema decoding failure
// on 32-bit platforms reported in #8438. These column definitions reproduce
// integer bounds used by Open_vSwitch, without requiring an OVSDB server.
func TestOVSDBSchemaLargeIntegerBounds(t *testing.T) {
	const schemaJSON = `{
		"name": "Open_vSwitch",
		"version": "1.0.0",
		"tables": {
			"Interface": {
				"columns": {
					"ifindex": {
						"type": {
							"key": {"type": "integer", "minInteger": 0, "maxInteger": 4294967295},
							"min": 0,
							"max": 1
						}
					}
				}
			},
			"QoS": {
				"columns": {
					"queues": {
						"type": {
							"key": {"type": "integer", "minInteger": 0, "maxInteger": 4294967295},
							"value": "uuid",
							"min": 0,
							"max": "unlimited"
						}
					}
				}
			},
			"CT_Timeout_Policy": {
				"columns": {
					"timeouts": {
						"type": {
							"key": "string",
							"value": {"type": "integer", "minInteger": 0, "maxInteger": 4294967295},
							"min": 0,
							"max": "unlimited"
						}
					}
				}
			}
		}
	}`

	var schema ovsdb.DatabaseSchema
	require.NoError(t, json.Unmarshal([]byte(schemaJSON), &schema))

	for _, tc := range []struct {
		table    string
		column   string
		mapValue bool
	}{
		{table: "Interface", column: "ifindex"},
		{table: "QoS", column: "queues"},
		{table: "CT_Timeout_Policy", column: "timeouts", mapValue: true},
	} {
		t.Run(tc.table+"."+tc.column, func(t *testing.T) {
			column := schema.Tables[tc.table].Columns[tc.column]
			require.NotNil(t, column)
			require.NotNil(t, column.TypeObj)

			base := column.TypeObj.Key
			if tc.mapValue {
				base = column.TypeObj.Value
			}
			require.NotNil(t, base)

			encoded, err := json.Marshal(base)
			require.NoError(t, err)

			var bounds struct {
				MaxInteger int64 `json:"maxInteger"`
			}
			require.NoError(t, json.Unmarshal(encoded, &bounds))
			assert.Equal(t, int64(4294967295), bounds.MaxInteger,
				"schema bounds must be preserved even when int is 32 bits")
		})
	}
}

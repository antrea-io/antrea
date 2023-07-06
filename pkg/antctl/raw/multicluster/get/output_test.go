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
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/pkg/antctl/transform/clusterset"
)

type fakeWriter struct{}

func (f fakeWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("not supported")
}

func TestOutput(t *testing.T) {
	// Here we test error cases only since common cases will be
	// covered by 'antctl mc get *' commands.
	tests := []struct {
		name         string
		outputFormat string
		expectedErr  string
		resources    interface{}
	}{
		{
			name:         "error to parse json output",
			outputFormat: "json",
			expectedErr:  "error when encoding data in json: error when encoding data in json: json: unsupported type: chan int",
			resources:    make(chan int),
		},
		{
			name:         "error to parse yaml output",
			outputFormat: "yaml",
			expectedErr:  "error when outputing in yaml format: json: unsupported type: chan int",
			resources:    make(chan int),
		},
		{
			name:        "error to print default output",
			expectedErr: "error when copy output into writer: not supported",
			resources: mcv1alpha2.ClusterSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "clusterset-name",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var writer io.Writer
			if tt.outputFormat != "" {
				writer = new(bytes.Buffer)
			} else {
				writer = fakeWriter{}
			}
			err := output(tt.resources, true, tt.outputFormat, writer, clusterset.Transform)
			if err == nil {
				t.Error("Expected to get error but it's nil")
			} else {
				assert.Equal(t, tt.expectedErr, err.Error())
			}
		})
	}
}

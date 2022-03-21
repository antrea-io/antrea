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

package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v2"

	"antrea.io/antrea/pkg/antctl/transform/common"
)

const (
	maxTableOutputColumnLength int = 50
)

func TableOutput(obj interface{}, writer io.Writer) error {
	target, err := respTransformer(obj)
	if err != nil {
		return fmt.Errorf("error when transforming obj: %w", err)
	}

	list, multiple := target.([]interface{})
	var args []string
	if multiple {
		for _, el := range list {
			m := el.(map[string]interface{})
			for k := range m {
				args = append(args, k)
			}
			// break after one iteration intentionally (we are just retrieving attribute
			// names to use as the table header in the output)
			break // nolint:staticcheck
		}
	} else {
		m, _ := target.(map[string]interface{})
		for k := range m {
			args = append(args, k)
		}
	}

	var buffer bytes.Buffer
	for _, arg := range args {
		buffer.WriteString(arg)
		buffer.WriteString("\t")
	}
	attrLine := buffer.String()

	var valLines []string
	if multiple {
		for _, el := range list {
			m := el.(map[string]interface{})
			buffer.Reset()
			for _, k := range args {
				var output bytes.Buffer
				if err = jsonEncode(m[k], &output); err != nil {
					return fmt.Errorf("error when encoding data in json: %w", err)
				}
				buffer.WriteString(strings.Trim(output.String(), "\"\n"))
				buffer.WriteString("\t")
			}
			valLines = append(valLines, buffer.String())
		}
	} else {
		buffer.Reset()
		m, _ := target.(map[string]interface{})
		for _, k := range args {
			var output bytes.Buffer
			if err = jsonEncode(m[k], &output); err != nil {
				return fmt.Errorf("error when encoding: %w", err)
			}
			buffer.WriteString(strings.Trim(output.String(), "\"\n"))
			buffer.WriteString("\t")
		}
		valLines = append(valLines, buffer.String())
	}

	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 15, 0, 1, ' ', 0)
	fmt.Fprintln(w, attrLine)
	for _, line := range valLines {
		fmt.Fprintln(w, line)
	}
	w.Flush()

	if _, err = io.Copy(writer, &b); err != nil {
		return fmt.Errorf("error when copy output into writer: %w", err)
	}

	return nil
}

func JsonOutput(obj interface{}, writer io.Writer) error {
	var output bytes.Buffer
	if err := jsonEncode(obj, &output); err != nil {
		return fmt.Errorf("error when encoding data in json: %w", err)
	}

	var prettifiedBuf bytes.Buffer
	err := json.Indent(&prettifiedBuf, output.Bytes(), "", "  ")
	if err != nil {
		return fmt.Errorf("error when formatting outputing in json: %w", err)
	}
	_, err = io.Copy(writer, &prettifiedBuf)
	if err != nil {
		return fmt.Errorf("error when outputing in json format: %w", err)
	}
	return nil
}

func YamlOutput(obj interface{}, writer io.Writer) error {
	var jsonObj interface{}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(obj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	// Comment copied from: sigs.k8s.io/yaml
	// We are using yaml.Unmarshal here (instead of json.Unmarshal) because the
	// Go JSON library doesn't try to pick the right number type (int, float,
	// etc.) when unmarshalling to interface{}, it just picks float64
	// universally. go-yaml does go through the effort of picking the right
	// number type, so we can preserve number type throughout this process.
	if err := yaml.Unmarshal(buf.Bytes(), &jsonObj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	if err := yaml.NewEncoder(writer).Encode(jsonObj); err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	return nil
}

// tableOutputForGetCommands formats the table output for "get" commands.
func TableOutputForGetCommands(obj interface{}, writer io.Writer) error {
	var list []common.TableOutput
	if reflect.TypeOf(obj).Kind() == reflect.Slice {
		s := reflect.ValueOf(obj)
		if s.Len() == 0 || s.Index(0).Interface() == nil {
			var buffer bytes.Buffer
			buffer.WriteString("\n")
			if _, err := io.Copy(writer, &buffer); err != nil {
				return fmt.Errorf("error when copy output into writer: %w", err)
			}
			return nil
		}
		if _, ok := s.Index(0).Interface().(common.TableOutput); !ok {
			return TableOutput(obj, writer)
		}
		for i := 0; i < s.Len(); i++ {
			ele := s.Index(i)
			list = append(list, ele.Interface().(common.TableOutput))
		}
	} else {
		ele, ok := obj.(common.TableOutput)
		if !ok {
			return TableOutput(obj, writer)
		}
		list = []common.TableOutput{ele}
	}

	// Get the elements and headers of table.
	args := list[0].GetTableHeader()
	rows := make([][]string, len(list)+1)
	rows[0] = list[0].GetTableHeader()
	for i, element := range list {
		rows[i+1] = element.GetTableRow(maxTableOutputColumnLength)
	}

	if list[0].SortRows() {
		// Sort the table rows according to columns in order.
		body := rows[1:]
		sort.Slice(body, func(i, j int) bool {
			for k := range body[i] {
				if body[i][k] != body[j][k] {
					return body[i][k] < body[j][k]
				}
			}
			return true
		})
	}
	// Construct the table.
	numRows, numCols := len(list)+1, len(args)
	widths := GetColumnWidths(numRows, numCols, rows)
	return ConstructTable(numRows, numCols, widths, rows, writer)
}

func GetColumnWidths(numRows int, numCols int, rows [][]string) []int {
	widths := make([]int, numCols)
	if numCols == 1 {
		// Do not limit the column length for a single column table.
		// This is for the case a single column table can have long rows which cannot
		// fit into a single line (one example is the ovsflows outputs).
		widths[0] = 0
	} else {
		// Get the width of every column.
		for j := 0; j < numCols; j++ {
			width := len(rows[0][j])
			for i := 1; i < numRows; i++ {
				if len(rows[i][j]) == 0 {
					rows[i][j] = "<NONE>"
				}
				if width < len(rows[i][j]) {
					width = len(rows[i][j])
				}
			}
			widths[j] = width
			if j != 0 {
				widths[j]++
			}
		}
	}
	return widths
}

func ConstructTable(numRows int, numCols int, widths []int, rows [][]string, writer io.Writer) error {
	var buffer bytes.Buffer
	for i := 0; i < numRows; i++ {
		for j := 0; j < numCols; j++ {
			val := ""
			if j != 0 {
				val = " " + val
			}
			val += rows[i][j]
			if widths[j] > 0 {
				val += strings.Repeat(" ", widths[j]-len(val))
			}
			buffer.WriteString(val)
		}
		buffer.WriteString("\n")
	}
	if _, err := io.Copy(writer, &buffer); err != nil {
		return fmt.Errorf("error when copy output into writer: %w", err)
	}

	return nil
}

func jsonEncode(obj interface{}, output *bytes.Buffer) error {
	if err := json.NewEncoder(output).Encode(obj); err != nil {
		return fmt.Errorf("error when encoding data in json: %w", err)
	}
	return nil
}

// respTransformer collects output fields in original transformedResponse
// and flattens them. respTransformer realizes this by turning obj into
// JSON and unmarshalling it.
// E.g. agent's transformedVersionResponse will only have two fields after
// transforming: agentVersion and antctlVersion.
func respTransformer(obj interface{}) (interface{}, error) {
	var jsonObj bytes.Buffer
	if err := json.NewEncoder(&jsonObj).Encode(obj); err != nil {
		return nil, fmt.Errorf("error when encoding data in json: %w", err)
	}
	jsonStr := jsonObj.String()

	var target interface{}
	if err := json.Unmarshal([]byte(jsonStr), &target); err != nil {
		return nil, fmt.Errorf("error when unmarshalling data in json: %w", err)
	}
	return target, nil
}

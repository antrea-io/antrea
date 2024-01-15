// Copyright 2021 Antrea Authors
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

package table

import (
	"io"
	"strings"

	"github.com/olekukonko/tablewriter"
)

const (
	CtxAverageEffectiveTime = "AverageEffectiveTime"
	CtxMaxEffectiveTime     = "MaxEffectiveTime"
	CtxMinEffectiveTime     = "MinEffectiveTime"
	CtxScaleNum             = "Scale"
)

func GenerateRow(name, result string, duration, avgTime, maxTime, minTime, scaleNum string) []string {
	name = strings.ReplaceAll(name, " ", "-")
	return []string{name, result, scaleNum, duration, avgTime, maxTime, minTime}
}

func ShowResult(w io.Writer, rows [][]string) {
	table := tablewriter.NewWriter(w)
	for _, row := range rows {
		colors := []tablewriter.Colors{{}, generateColor(row[1]), {}}
		table.Rich(row, colors)
	}
	table.SetAutoFormatHeaders(false)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	headers := []string{"Name", "Result", CtxScaleNum, "Duration", CtxAverageEffectiveTime, CtxMaxEffectiveTime, CtxMinEffectiveTime}
	table.SetHeader(headers)
	table.SetAutoMergeCells(true)
	table.SetAutoWrapText(true)
	table.SetRowLine(true)
	table.Render()
}

func generateColor(result string) tablewriter.Colors {
	if result == "success" {
		return tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlueColor}
	}
	return tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor}
}

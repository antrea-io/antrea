// Copyright 2020 Antrea Authors
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

package main

import (
	"fmt"
)

type SeverityType int

const (
	SeverityDefCon1    SeverityType = 1
	SeverityCritical   SeverityType = 2
	SeverityHigh       SeverityType = 3
	SeverityMedium     SeverityType = 4
	SeverityLow        SeverityType = 5
	SeverityNegligible SeverityType = 6
	SeverityUnknown    SeverityType = 7
)

func (s SeverityType) String() string {
	switch s {
	case SeverityDefCon1:
		return "DefCon1"
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	case SeverityNegligible:
		return "Negligible"
	case SeverityUnknown:
		return "Unknown"
	default:
		panic("Not a valid severity value")
	}
}

func SeverityFromString(s string) SeverityType {
	switch s {
	case "DefCon1":
		return SeverityDefCon1
	case "Critical":
		return SeverityCritical
	case "High":
		return SeverityHigh
	case "Medium":
		return SeverityMedium
	case "Low":
		return SeverityLow
	case "Negligible":
		return SeverityNegligible
	case "Unknown":
		return SeverityUnknown
	default:
		return SeverityUnknown
	}
}

// Score values from https://github.com/yfoelling/yair#image-scoring.
var (
	severityScore = map[SeverityType]int{
		SeverityDefCon1:    1296,
		SeverityCritical:   625,
		SeverityHigh:       265,
		SeverityMedium:     81,
		SeverityLow:        16,
		SeverityNegligible: 1,
		SeverityUnknown:    0,
	}
)

type reportStats struct {
	imageName         string
	count             int
	countBySeverity   map[SeverityType]int
	score             int
	countHighOrHigher int
}

func (s *reportStats) PrettyString() string {
	str := "*** Report Stats ***\n"
	str += fmt.Sprintf("imageName: %s\n", s.imageName)
	str += fmt.Sprintf("count: %d\n", s.count)
	str += fmt.Sprintf("countBySeverity:\n")
	for k, v := range s.countBySeverity {
		str += fmt.Sprintf("\t%s: %d\n", k, v)
	}
	str += fmt.Sprintf("score: %d\n", s.score)
	str += fmt.Sprintf("countHighOrHigher: %d\n", s.countHighOrHigher)
	str += fmt.Sprintf("********************")
	return str
}

func (s *reportStats) Print() {
	fmt.Println(s.PrettyString())
}

func analyzeReport(report *vulnerabilityReport) (*reportStats, error) {
	stats := &reportStats{
		imageName:       report.Image,
		countBySeverity: make(map[SeverityType]int),
	}

	for _, v := range report.Vulnerabilities {
		stats.count += 1
		severity := SeverityFromString(v.Severity)
		stats.countBySeverity[severity] += 1
		stats.score += severityScore[severity]

		if severity <= SeverityHigh {
			stats.countHighOrHigher += 1
		}
	}

	return stats, nil
}

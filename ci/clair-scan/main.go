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
	"k8s.io/klog/v2"

	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
)

const (
	defaultMaxScore = 1500
)

func parseReport(jsonPath string) (*vulnerabilityReport, error) {
	reportData, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("error when reading report file: %v", err)
	}
	var report vulnerabilityReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("error when unmarshalling JSON report: %v", err)
	}
	return &report, nil
}

func parseAndAnalyze(jsonPath string) *reportStats {
	if jsonPath == "" {
		return nil
	}
	report, err := parseReport(jsonPath)
	if err != nil {
		klog.Fatalf("Failed to parse '%s': %v", jsonPath, err)
	}

	stats, err := analyzeReport(report)
	if err != nil {
		klog.Fatalf("Failed to analyze report '%s': %v", jsonPath, err)
	}
	stats.Print()
	return stats
}

func main() {
	fileReport := flag.String("report", "", "The JSON report produced by clair-scanner that we need to analyze.")
	maxScore := flag.Int("max-score", defaultMaxScore, "Max vulnerability score for which no email notification is generated.")
	fileReportCmp := flag.String("report-cmp", "", "A second JSON report produced by clair-scanner, to compare to the first one.")
	flag.Parse()

	if *fileReport == "" {
		klog.Fatalf("--report is required")
	}

	stats := parseAndAnalyze(*fileReport)
	statsCmp := parseAndAnalyze(*fileReportCmp)

	err := notifyIfNeeded(stats, *maxScore, statsCmp, *fileReport, *fileReportCmp)
	if err != nil {
		klog.Fatalf("Failed to send email: %v", err)
	}
}

// Copyright 2019 Antrea Authors
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

package e2e

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkBandwidthIntraNode runs the benchmark of bandwidth between Pods on same node.
func BenchmarkBandwidthIntraNode(b *testing.B) {
	withPerfTestSetup(func(data *TestData) {
		b.StartTimer()

		podDefA := createPerfTestPodDefinition("perftest-a", perftoolContainerName, perftoolImage)
		if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(podDefA); err != nil {
			b.Fatalf("Error when creating the first perftest Pod: %v", err)
		}
		podDefB := createPerfTestPodDefinition("perftest-b", perftoolContainerName, perftoolImage)
		if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(podDefB); err != nil {
			b.Fatalf("Error when creating the second perftest Pod: %v", err)
		}
		podBIP, err := data.podWaitForIP(defaultTimeout, podDefB.Name, testNamespace)
		if err != nil {
			b.Fatalf("Error when getting perftest Pod IP: %v", err)
		}
		stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", perftoolContainerName, []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", podBIP)})
		if err != nil {
			b.Fatalf("Error when running iperf3 client: %v", err)
		}
		stdout = strings.TrimSpace(stdout)
		results := strings.Split(stdout, " ")
		if len(results) != 2 {
			b.Fatalf("Error when parsing iperf result: cannot parse output `%s`", stdout)
		}
		// Disable default output.
		b.ReportMetric(0, "ns/op")
		bandwidthNum, _ := strconv.ParseFloat(results[0], 64)
		bandwidthUnit := strings.TrimSpace(results[1])
		b.ReportMetric(bandwidthNum, bandwidthUnit)
	}, b)
}

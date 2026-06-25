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

package traceflow

import (
	"fmt"
	"io"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

const (
	indent    = "  "
	branch    = "├── "
	leaf      = "└── "
	vertical  = "│   "
	arrowDown = "▼"
)


func renderTree(tf *v1beta1.Traceflow, w io.Writer) error {
	
	fmt.Fprintf(w, "\nTRACE ID: %s\n", tf.Name)
	fmt.Fprintf(w, "SOURCE:   %s/%s\n", tf.Spec.Source.Namespace, tf.Spec.Source.Pod)

	dest := ""
	if len(tf.Spec.Destination.IP) > 0 {
		dest = tf.Spec.Destination.IP
	} else if len(tf.Spec.Destination.Pod) != 0 {
		dest = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Pod)
	} else if len(tf.Spec.Destination.Service) != 0 {
		dest = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Service)
	}
	fmt.Fprintf(w, "DEST:     %s\n\n", dest)

	results := tf.Status.Results
	if len(results) == 0 {
		fmt.Fprintln(w, "No observations found.")
		return nil
	}

	lastNode := ""
	for _, nodeResult := range results {
		
		if nodeResult.Node != lastNode {
			if lastNode != "" {
				
				fmt.Fprintf(w, "%s        %s\n", indent, vertical)
				fmt.Fprintf(w, "%s        %s (Cross-Node Traffic)\n", indent, vertical)
				fmt.Fprintf(w, "%s        %s\n", indent, arrowDown)
			}
			fmt.Fprintf(w, "[Node: %s]\n", nodeResult.Node)
			lastNode = nodeResult.Node
		}

		
		observations := nodeResult.Observations
		for i, obs := range observations {
			isLast := i == len(observations)-1
			prefix := indent + branch
			if isLast {
				prefix = indent + leaf
			}

			status := formatAction(obs.Action)
			extra := ""
			if obs.ComponentInfo != "" {
				extra = fmt.Sprintf(" (%s)", obs.ComponentInfo)
			}

			
			fmt.Fprintf(w, "%s%-20s %s%s\n", prefix, obs.Component, status, extra)
		}
	}
	fmt.Fprintln(w, "") 
	return nil
}


func formatAction(action v1beta1.TraceflowAction) string {
	switch action {
	case v1beta1.ActionDropped, v1beta1.ActionRejected:
		return fmt.Sprintf("[%s] ❌", action)
	case v1beta1.ActionDelivered:
		return fmt.Sprintf("[%s] ✅", action)
	case v1beta1.ActionForwarded:
		return fmt.Sprintf("[%s] ->", action)
	default:
		return fmt.Sprintf("[%s]", action)
	}
}

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

package graphviz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestGenGraph(t *testing.T) {
	liveTf := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-live-traceflow",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			LiveTraffic: true,
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{
					ICMP: &crdv1alpha1.ICMPEchoRequestHeader{
						ID:       123,
						Sequence: 1,
					},
				},
			},
			Source: crdv1alpha1.Source{
				Namespace: "default",
				Pod:       "test-pod",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			CapturedPacket: &crdv1alpha1.Packet{
				DstIP: "10.10.0.2",
				IPHeader: crdv1alpha1.IPHeader{
					Flags:    2,
					Protocol: 1,
					TTL:      63,
				},
				TransportHeader: crdv1alpha1.TransportHeader{
					ICMP: &crdv1alpha1.ICMPEchoRequestHeader{
						ID:       123,
						Sequence: 1,
					},
					TCP: &crdv1alpha1.TCPHeader{
						SrcPort: 123,
						DstPort: 1,
						Flags:   2,
					},
				},
				Length: 84,
				SrcIP:  "10.10.1.4",
			},
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-worker-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionForwarded,
							Component: crdv1alpha1.ComponentSpoofGuard,
						},
						{
							Action:        crdv1alpha1.ActionForwarded,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							TunnelDstIP:   "192.168.77.100",
						},
					},
				},
				{
					Node: "k8s-node-control-plane",
					Observations: []crdv1alpha1.Observation{
						{
							Action:        crdv1alpha1.ActionReceived,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Classification",
						},
						{
							Action:        crdv1alpha1.ActionDelivered,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
						},
					},
				},
			},
		},
	}

	liveTfWithSourceIP := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-live-traceflow-source-ip",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			LiveTraffic: true,
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{},
			},
			Source: crdv1alpha1.Source{
				IP: "192.168.225.5",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			CapturedPacket: &crdv1alpha1.Packet{
				DstIP: "192.168.226.5",
				IPHeader: crdv1alpha1.IPHeader{
					Flags:    2,
					Protocol: 1,
					TTL:      63,
				},
				Length: 84,
				SrcIP:  "192.168.225.5",
			},
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionReceived,
							Component: crdv1alpha1.ComponentForwarding,
						},
						{
							Action:        crdv1alpha1.ActionDelivered,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
						},
					},
				},
			},
		},
	}

	tfInOneNode := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-traceflow-one-node",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{},
			},
			Source: crdv1alpha1.Source{
				Namespace: "default",
				Pod:       "pod-1",
			},
			Destination: crdv1alpha1.Destination{
				Namespace: "default",
				Pod:       "pod-2",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionForwarded,
							Component: crdv1alpha1.ComponentSpoofGuard,
						},
						{
							Action:        crdv1alpha1.ActionDelivered,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
						},
					},
				},
			},
		},
	}

	liveTfWithSourceIPTwoNodes := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-live-traceflow-source-ip-two-nodes",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			LiveTraffic: true,
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{
					ICMP: &crdv1alpha1.ICMPEchoRequestHeader{
						ID:       123,
						Sequence: 1,
					},
				},
			},
			Source: crdv1alpha1.Source{
				IP: "192.168.225.5",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			CapturedPacket: &crdv1alpha1.Packet{
				DstIP: "10.10.0.2",
				IPHeader: crdv1alpha1.IPHeader{
					Flags:    2,
					Protocol: 1,
					TTL:      63,
				},
				TransportHeader: crdv1alpha1.TransportHeader{
					UDP: &crdv1alpha1.UDPHeader{
						SrcPort: 68,
						DstPort: 80,
					},
				},
				Length: 84,
				SrcIP:  "10.10.1.4",
			},
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-worker-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionForwarded,
							Component: crdv1alpha1.ComponentSpoofGuard,
						},
						{
							Action:        crdv1alpha1.ActionForwarded,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							TunnelDstIP:   "192.168.77.100",
						},
					},
				},
				{
					Node: "k8s-node-control-plane",
					Observations: []crdv1alpha1.Observation{
						{
							Action:        crdv1alpha1.ActionReceived,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Classification",
						},
						{
							Action:        crdv1alpha1.ActionForwarded,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
						},
					},
				},
			},
		},
	}

	nonliveTf := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-non-live-traceflow",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			LiveTraffic: false,
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{
					ICMP: &crdv1alpha1.ICMPEchoRequestHeader{
						ID:       123,
						Sequence: 1,
					},
				},
			},
			Source: crdv1alpha1.Source{
				Namespace: "default",
				Pod:       "pod-1",
			},
			Destination: crdv1alpha1.Destination{
				Namespace: "default",
				Pod:       "pod-2",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-worker-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionForwarded,
							Component: crdv1alpha1.ComponentSpoofGuard,
						},
						{
							Action:        crdv1alpha1.ActionForwarded,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
							TunnelDstIP:   "192.168.77.100",
						},
					},
				},
				{
					Node: "k8s-node-control-plane",
					Observations: []crdv1alpha1.Observation{
						{
							Action:        crdv1alpha1.ActionReceived,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Classification",
						},
						{
							Action:        crdv1alpha1.ActionDropped,
							Component:     crdv1alpha1.ComponentNetworkPolicy,
							ComponentInfo: "IngressRule",
						},
					},
				},
			},
		},
	}

	tfEgressFromLocalNode := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-traceflow-egress-local-node",
		},
		Spec: crdv1alpha1.TraceflowSpec{
			Packet: crdv1alpha1.Packet{
				IPHeader: crdv1alpha1.IPHeader{
					Protocol: 1,
				},
				TransportHeader: crdv1alpha1.TransportHeader{},
			},
			Source: crdv1alpha1.Source{
				Namespace: "default",
				Pod:       "pod-1",
			},
			Destination: crdv1alpha1.Destination{
				IP: "192.168.100.100",
			},
		},
		Status: crdv1alpha1.TraceflowStatus{
			Phase: crdv1alpha1.Succeeded,
			Results: []crdv1alpha1.NodeResult{
				{
					Node: "k8s-node-1",
					Observations: []crdv1alpha1.Observation{
						{
							Action:    crdv1alpha1.ActionForwarded,
							Component: crdv1alpha1.ComponentSpoofGuard,
						},
						{
							Component: crdv1alpha1.ComponentEgress,
							Action:    crdv1alpha1.ActionMarkedForSNAT,
							Egress:    "egressA",
							EgressIP:  "192.168.225.5",
						},
						{
							Action:        crdv1alpha1.ActionForwardedOutOfOverlay,
							Component:     crdv1alpha1.ComponentForwarding,
							ComponentInfo: "Output",
						},
					},
				},
			},
		},
	}

	expectedOutputWithSourcePod := `digraph G {
	center=true;
	label="test-live-traceflow";
	labelloc=t;
	"default/test-pod"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	"10.10.0.2"->cluster_destination_1[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_destination_1->cluster_destination_2[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_source_2->cluster_destination_2[ color="#C0C0C0", constraint=false, dir=forward, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label="k8s-node-worker-1";
	labeljust=l;
	style="filled,bold";
	"default/test-pod" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Forwarded
Tunnel Destination IP : 192.168.77.100", shape=box, style="rounded,filled,solid" ];

}
;
	subgraph cluster_destination {
	bgcolor="#F8F8FF";
	label="k8s-node-control-plane";
	labeljust=r;
	style="filled,bold";
	"10.10.0.2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	capturedPacket [ color="#696969", label="Captured Packet:\lSource IP: 10.10.1.4\lDestination IP: 10.10.0.2\lLength: 84\lIPv4 Header: \l    Flags: 2\l    Protocol: 1\l    TTL: 63\lTransport Header: \l    TCP: \l        Source Port: 123\l        Destination Port: 1\l    ICMP: \l        ID: 123\l        Sequence: 1\l", shape=note, style="rounded,filled,solid" ];
	cluster_destination_1 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Delivered", shape=box, style="rounded,filled,solid" ];
	cluster_destination_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Classification
Received", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	expectedOutputWithSourceIP := `digraph G {
	center=true;
	label="test-live-traceflow-source-ip";
	labelloc=t;
	newrank=true;
	"192.168.225.5"->"192.168.225.5"[ style=invis ];
	"192.168.226.5"->cluster_destination_1[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_destination_1->cluster_destination_2[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	"192.168.225.5"->cluster_destination_2[ color="#C0C0C0", constraint=false, dir=forward, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label=source;
	labeljust=l;
	style="filled,bold";
	"192.168.225.5" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];

}
;
	subgraph cluster_destination {
	bgcolor="#F8F8FF";
	label="k8s-node-1";
	labeljust=r;
	style="filled,bold";
	"192.168.226.5" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	capturedPacket [ color="#696969", label="Captured Packet:\lSource IP: 192.168.225.5\lDestination IP: 192.168.226.5\lLength: 84\lIPv4 Header: \l    Flags: 2\l    Protocol: 1\l    TTL: 63\l", shape=note, style="rounded,filled,solid" ];
	cluster_destination_1 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Delivered", shape=box, style="rounded,filled,solid" ];
	cluster_destination_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Received", shape=box, style="rounded,filled,solid" ];

}
;
	subgraph force_node_same_level {
	rank=same;
	"192.168.225.5" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_destination_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Received", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	expectedOutputInOneNode := `digraph G {
	center=true;
	label="test-traceflow-one-node";
	labelloc=t;
	"default/pod-1"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_2->"default/pod-2"[ color="#C0C0C0", dir=forward, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label="k8s-node-1";
	labeljust=l;
	style="filled,bold";
	"default/pod-1" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	"default/pod-2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Delivered", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	expectedOutputWithSourceIPTwoNodes := `digraph G {
	center=true;
	label="test-live-traceflow-source-ip-two-nodes";
	labelloc=t;
	"192.168.225.5"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	"10.10.0.2"->cluster_destination_1[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_destination_1->cluster_destination_2[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_source_2->cluster_destination_2[ color="#C0C0C0", constraint=false, dir=forward, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label="k8s-node-worker-1";
	labeljust=l;
	style="filled,bold";
	"192.168.225.5" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Forwarded
Tunnel Destination IP : 192.168.77.100", shape=box, style="rounded,filled,solid" ];

}
;
	subgraph cluster_destination {
	bgcolor="#F8F8FF";
	label="k8s-node-control-plane";
	labeljust=r;
	style="filled,bold";
	"10.10.0.2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	capturedPacket [ color="#696969", label="Captured Packet:\lSource IP: 10.10.1.4\lDestination IP: 10.10.0.2\lLength: 84\lIPv4 Header: \l    Flags: 2\l    Protocol: 1\l    TTL: 63\lTransport Header: \l    UDP: \l        Source Port: 68\l        Destination Port: 80\l", shape=note, style="rounded,filled,solid" ];
	cluster_destination_1 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_destination_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Classification
Received", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	expectedOutputWithNonliveTf := `digraph G {
	center=true;
	label="test-non-live-traceflow";
	labelloc=t;
	"default/pod-1"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	"default/pod-2"->cluster_destination_1[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0, style="invis" ];
	cluster_destination_1->cluster_destination_2[ color="#C0C0C0", dir=back, minlen=1, penwidth=2.0 ];
	cluster_source_2->cluster_destination_2[ color="#C0C0C0", constraint=false, dir=forward, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label="k8s-node-worker-1";
	labeljust=l;
	style="filled,bold";
	"default/pod-1" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
Forwarded
Tunnel Destination IP : 192.168.77.100", shape=box, style="rounded,filled,solid" ];

}
;
	subgraph cluster_destination {
	bgcolor="#F8F8FF";
	label="k8s-node-control-plane";
	labeljust=r;
	style="filled,bold";
	"default/pod-2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_destination_1 [ color="#B22222", fillcolor="#EDD5D5", label="NetworkPolicy
IngressRule
Dropped", shape=box, style="rounded,filled,solid" ];
	cluster_destination_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Classification
Received", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	expectedOutputEgressFromLocalNode := `digraph G {
	center=true;
	label="test-traceflow-egress-local-node";
	labelloc=t;
	"default/pod-1"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	cluster_source_2->cluster_source_3[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
	subgraph cluster_source {
	bgcolor="#F8F8FF";
	label="k8s-node-1";
	labeljust=l;
	style="filled,bold";
	"default/pod-1" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
	cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
Forwarded", shape=box, style="rounded,filled,solid" ];
	cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Egress
MarkedForSNAT
Egress IP : 192.168.225.5
Egress : egressA", shape=box, style="rounded,filled,solid" ];
	cluster_source_3 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
Output
ForwardedOutOfOverlay", shape=box, style="rounded,filled,solid" ];

}
;

}
`

	tests := []struct {
		name           string
		traceflow      crdv1alpha1.Traceflow
		expectedOutput string
	}{
		{
			name:           "live traceflow with source Pod",
			traceflow:      liveTf,
			expectedOutput: expectedOutputWithSourcePod,
		},
		{
			name:           "live traceflow with source IP",
			traceflow:      liveTfWithSourceIP,
			expectedOutput: expectedOutputWithSourceIP,
		},
		{
			name:           "traceflow in one Node",
			traceflow:      tfInOneNode,
			expectedOutput: expectedOutputInOneNode,
		},
		{
			name:           "live traceflow with source IP two Nodes",
			traceflow:      liveTfWithSourceIPTwoNodes,
			expectedOutput: expectedOutputWithSourceIPTwoNodes,
		},
		{
			name:           "live traceflow set to false",
			traceflow:      nonliveTf,
			expectedOutput: expectedOutputWithNonliveTf,
		},
		{
			name:           "traceflow egress from local Node",
			traceflow:      tfEgressFromLocalNode,
			expectedOutput: expectedOutputEgressFromLocalNode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := GenGraph(&tt.traceflow)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedOutput, output)
		})
	}
}

func TestGetTraceflowStatusMessage(t *testing.T) {
	baseTf := crdv1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tf",
		},
		Status: crdv1alpha1.TraceflowStatus{
			Reason: "test",
		},
	}
	tests := []struct {
		name         string
		phase        crdv1alpha1.TraceflowPhase
		expectOutput string
	}{
		{
			name:         "failed traceflow",
			phase:        crdv1alpha1.Failed,
			expectOutput: "\"Traceflow test-tf failed: test\"",
		},
		{
			name:         "running traceflow",
			phase:        crdv1alpha1.Running,
			expectOutput: "\"Traceflow test-tf is running...\"",
		},
		{
			name:         "pending traceflow",
			phase:        crdv1alpha1.Pending,
			expectOutput: "\"Traceflow test-tf is pending...\"",
		},
		{
			name:         "pending traceflow",
			expectOutput: "\"Unknown Traceflow status. Please check whether Antrea is running.\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseTf.Status.Phase = tt.phase
			got := getTraceflowStatusMessage(&baseTf)
			assert.Equal(t, tt.expectOutput, got)
		})
	}
}

func TestFindClusterString(t *testing.T) {
	testCases := []struct {
		name        string
		graphStr    string
		clusterName string
		startIndex  int
		endIndex    int
	}{
		{
			name: "Graph with cluster",
			graphStr: `center=true;
            label="test-traceflow-one-node";
            labelloc=t;
            "default/pod-1"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
            cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
            cluster_source_2->"default/pod-2"[ color="#C0C0C0", dir=forward, penwidth=2.0 ];
            subgraph cluster_source {
            bgcolor="#F8F8FF";
            label="k8s-node-1";
            labeljust=l;
            style="filled,bold";
            "default/pod-1" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
            "default/pod-2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
            cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
        Forwarded", shape=box, style="rounded,filled,solid" ];
            cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
        Output
        Delivered", shape=box, style="rounded,filled,solid" ];

        }
        ;

        }
        `,
			clusterName: "cluster_source",
			startIndex:  394,
			endIndex:    1048,
		},
		{
			name: "Graph with no cluster",
			graphStr: `center=true;
            label="test-traceflow-one-node";
            labelloc=t;
            "default/pod-1"->cluster_source_1[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
            cluster_source_1->cluster_source_2[ color="#C0C0C0", dir=forward, minlen=1, penwidth=2.0 ];
            cluster_source_2->"default/pod-2"[ color="#C0C0C0", dir=forward, penwidth=2.0 ];
            subgraph cluster_source {
            bgcolor="#F8F8FF";
            label="k8s-node-1";
            labeljust=l;
            style="filled,bold";
            "default/pod-1" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
            "default/pod-2" [ color="#808080", fillcolor="#C8C8C8", style="filled,bold" ];
            cluster_source_1 [ color="#696969", fillcolor="#DCDCDC", label="SpoofGuard
        Forwarded", shape=box, style="rounded,filled,solid" ];
            cluster_source_2 [ color="#696969", fillcolor="#DCDCDC", label="Forwarding
        Output
        Delivered", shape=box, style="rounded,filled,solid" ];

        }
        ;

        }
		`,
			clusterName: "cluster_destination",
			endIndex:    1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotStartIndex, gotEndIndex := findClusterString(tc.graphStr, tc.clusterName)
			assert.Equal(t, tc.startIndex, gotStartIndex)
			assert.Equal(t, tc.endIndex, gotEndIndex)
		})
	}
}

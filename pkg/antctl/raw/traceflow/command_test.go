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
	"bytes"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	antreafakeclient "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

const (
	srcPod = "default/pod-1"
	dstPod = "default/pod-2"
	ipv4   = "192.168.10.10"
)

var (
	pod1 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
		},
	}
	pod2 = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-2",
			Namespace: "default",
		},
	}
	k8sClient   = k8sfake.NewSimpleClientset(&pod1, &pod2)
	protocolTCP = int32(6)
)

func modifyCommandAndOption(src, dst, outputType, liveTraffic, droppedOnly, nowait string) {
	Command.Flags().Set("source", src)
	Command.Flags().Set("destination", dst)
	Command.Flags().Set("output", outputType)
	Command.Flags().Set("live-traffic", liveTraffic)
	Command.Flags().Set("dropped-only", droppedOnly)
	Command.Flags().Set("nowait", nowait)
}

// TestGetPortFields tests if a flow can be turned into a map.
func TestGetPortFields(t *testing.T) {
	tcs := []struct {
		flow     string
		success  bool
		expected map[string]int
	}{
		{
			flow:    "a=1,b",
			success: true,
			expected: map[string]int{
				"a": 1,
				"b": 0,
			},
		},
		{
			flow:     "a=",
			success:  false,
			expected: nil,
		},
		{
			flow:     "=1",
			success:  false,
			expected: nil,
		},
	}

	for _, tc := range tcs {
		m, err := getPortFields(tc.flow)
		if err != nil {
			if tc.success {
				t.Errorf("error when running getPortFields(): %+v", err)
			}
		} else {
			assert.Equal(t, tc.expected, m)
		}
	}
}

// TestParseFlow tests if a flow can be parsed correctly.
func TestParseFlow(t *testing.T) {
	tcs := []struct {
		flow     string
		success  bool
		expected *v1beta1.Traceflow
	}{
		{
			flow:    "udp,udp_src=1234,udp_dst=4321",
			success: true,
			expected: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Packet: v1beta1.Packet{
						IPHeader: &v1beta1.IPHeader{
							Protocol: 17,
						},
						TransportHeader: v1beta1.TransportHeader{
							UDP: &v1beta1.UDPHeader{
								SrcPort: 1234,
								DstPort: 4321,
							},
						},
					},
				},
			},
		},
		{
			flow:    " icmp,",
			success: true,
			expected: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Packet: v1beta1.Packet{
						IPHeader: &v1beta1.IPHeader{
							Protocol: 1,
						},
						TransportHeader: v1beta1.TransportHeader{},
					},
				},
			},
		},
		{
			flow:    "tcp,tcp_dst=4321",
			success: true,
			expected: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Packet: v1beta1.Packet{
						IPHeader: &v1beta1.IPHeader{
							Protocol: 6,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
				},
			},
		},
		{
			flow:    "tcp,tcp_dst=4321,ipv6",
			success: true,
			expected: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		option.flow = tc.flow
		pkt, err := parseFlow()
		if err != nil {
			if tc.success {
				t.Errorf("error when running parseFlow(): %v", err)
			}
		} else {
			assert.Equal(t, tc.expected.Spec.Packet, *pkt)
		}
	}
}

func TestRunE(t *testing.T) {
	tcs := []struct {
		name        string
		src         string
		dst         string
		outputType  string
		liveTraffic string
		droppedOnly string
		expected    string
	}{
		{
			name:     "no source",
			expected: "Please provide source",
		},
		{
			name:     "no destination",
			src:      srcPod,
			expected: "Please provide destination",
		},
		{
			name:        "live traffic",
			liveTraffic: "1",
			expected:    "One of source and destination must be a Pod",
		},
		{
			name:        "dropped-only",
			src:         srcPod,
			dst:         ipv4,
			droppedOnly: "1",
			expected:    "--dropped-only works only with live-traffic Traceflow",
		},
		{
			name:       "dummy-traceflow-pod-to-pod",
			src:        srcPod,
			dst:        dstPod,
			outputType: "yaml",
			expected: `phase: Succeeded
source: default/pod-1
destination: default/pod-2
`,
		},
		{
			name:       "dummy-traceflow-pod-to-service",
			src:        srcPod,
			dst:        "default/service",
			outputType: "yaml",
			expected: `phase: Succeeded
source: default/pod-1
destination: default/service
`,
		},
		{
			name:       "dummy-traceflow-pod-to-ipv4",
			src:        srcPod,
			dst:        ipv4,
			outputType: "json",
			expected: `
  "phase": "Succeeded",
  "source": "default/pod-1",
  "destination": "192.168.10.10"
`,
		},
		{
			name:        "dummy-traceflow-livetraffic",
			src:         srcPod,
			liveTraffic: "1",
			outputType:  "yaml",
			expected: `phase: Succeeded
source: default/pod-1
`,
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			modifyCommandAndOption(tt.src, tt.dst, tt.outputType, tt.liveTraffic, tt.droppedOnly, "")
			defer modifyCommandAndOption("", "", "yaml", "", "", "")

			client := antreafakeclient.NewSimpleClientset()
			client.PrependReactor("create", "traceflows", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				obj := createAction.GetObject().(*v1beta1.Traceflow)
				obj.Status.Phase = v1beta1.Succeeded
				return false, obj, nil
			})

			getClients = func(cmd *cobra.Command) (kubernetes.Interface, antrea.Interface, error) {
				return k8sClient, client, nil
			}
			defer func() { getClients = getK8sClient }()

			buf := new(bytes.Buffer)
			Command.SetOutput(buf)
			Command.SetOut(buf)
			Command.SetErr(buf)
			err := runE(Command, nil)
			require.NoError(t, err)
			assert.Contains(t, buf.String(), tt.expected)
		})
	}
}

func TestGetK8sClient(t *testing.T) {
	tcs := []struct {
		name        string
		fakeConfigs []byte
		expectedErr string
	}{
		{
			name:        "kubeconfig not defined",
			expectedErr: "flag accessed but not defined: kubeconfig",
		},
		{
			name: "valid kubeconfig",
			fakeConfigs: []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJTHJac3Z6ZFQ3ekF3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TWpBNE1qSXdNakl6TXpkYUZ3MHlNekE0TWpJd01qSXpNemxhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTB4N2JEd2NqSzN3VjRGSzkKYUtrd0FUdjVoT2NsbHhUSEI1ejFUbHZJV3pmdTNYNjZtaWkxUE04ODI1dTArdDRRdisxUVRIRHFzUkNvWFA1awpuNGNWZkxkeTlad25uN01uSDExVTRsRWRoeXBrdlZsc0RmajlBdWh3WHBZVE82eE5kM2o2Y3BIZGNMOW9PbGw2CkowcGU2RzBleHpTSHMvbHRUZXlyalRGbXM2Sm5zSWV6T2lHRmhZOTJCbDBmZ1krb2p6MFEwM2cvcE5QZUszcGMKK05wTWh4eG1UY1lVNzlaZVRqV1JPYTFQSituNk1SMEhDbW0xQk5QNmdwWmozbGtWSktkZnBEYmovWHYvQWNkVQpab3E5Ym95aGNDUCtiYmgyaWVtaTc0bnZqZ1BUTkVDZWU2a3ZHY3VNaXRKUkdvWjBxbFpZbXZDaWdEeGlSTnBNClBPa1dud0lEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JSc2VoZXVkM0l5VWRNdkhhRS9YU3MrOFErLwpiVEFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBcmg4UFRadFgvWjlHVzlMYmxZZ1FWWE04VlRrWEtGSEpTZldOCkJLNXo2NWNWdGN2cFZ0WDZNTlppTFhuYkFzQ0JPY1RqejBJRlphYkNNUkZzYmdYbEVqV0ZuRE5abzBMVHFTZUcKQ2RqTWljK0JzbmFGUThZOXJ5TTVxZ0RhQzNWQkdTSXVscklXeGxPYmRmUEpWRnpUaVNTcmJBR1Z3Uk5sQlpmYgpYOXBlRlpNNmNFNUhTOE5RTmNoZkh2SWhGSUVuR2YxOUx2enp0WGUzQWwwb3hYNjdRKzhyWXd0Tm56dS9xM29BCmJIN1dsNld5ODVYNS90RWlQcWU0ZU1GalRDME9tR2NHZ2lQdU90NjlIejAwV2hvaWNYYWpma1FZOHNKMk5Uc1cKdUcxbWZqb0tTdUN0OC9BRmhPNURlaHZ3eFNIQU12eG1VQUJYL294bU1DNzdwV0VnRWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`),
		},
		{
			name: "invalid kubeconfig",
			fakeConfigs: []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: data
    server: https://localhost
  name: fake-cluster
contexts:
- context:
    cluster:  fake-cluster
    user:  user-id
  name:  fake-cluster
current-context:  fake-cluster
kind: Config`),
			expectedErr: "failed to create clientset: failed to create K8s clientset: unable to load root certificates: unable to parse bytes as PEM block",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{
				RunE: runE,
				Args: cobra.NoArgs,
			}
			if tc.fakeConfigs != nil {
				fakeKubeconfig, err := os.CreateTemp("", "fakeKubeconfig")
				if err != nil {
					log.Fatal(err)
				}
				defer os.Remove(fakeKubeconfig.Name())
				fakeKubeconfig.Write(tc.fakeConfigs)
				cmd.Flags().String("kubeconfig", fakeKubeconfig.Name(), "path of kubeconfig")
			}
			_, _, err := getK8sClient(cmd)
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestNewTraceflow(t *testing.T) {
	tcs := []struct {
		name        string
		src         string
		dst         string
		liveTraffic string
		droppedOnly string
		expectedTf  *v1beta1.Traceflow
	}{
		{
			name: "dummy-traceflow-dst-pod",
			dst:  dstPod,
			expectedTf: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Destination: v1beta1.Destination{
						Namespace: "default",
						Pod:       "pod-2",
					},
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
					Timeout: 10,
				},
			},
		},
		{
			name: "dummy-traceflow-src-pod",
			src:  srcPod,
			expectedTf: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Source: v1beta1.Source{
						Namespace: "default",
						Pod:       "pod-1",
					},
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
					Timeout: 10,
				},
			},
		},
		{
			name: "dummy-traceflow-pod-to-ipv4",
			src:  "pod-1",
			dst:  ipv4,
			expectedTf: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Source: v1beta1.Source{
						Namespace: "default",
						Pod:       "pod-1",
					},
					Destination: v1beta1.Destination{
						IP: ipv4,
					},
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
					Timeout: 10,
				},
			},
		},
		{
			name:        "dummy-traceflow-ipv4-to-pod-with-liveTraffic",
			src:         ipv4,
			dst:         "pod-2",
			liveTraffic: "1",
			expectedTf: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Source: v1beta1.Source{
						IP: ipv4,
					},
					Destination: v1beta1.Destination{
						Namespace: "default",
						Pod:       "pod-2",
					},
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
					LiveTraffic: true,
					Timeout:     10,
				},
			},
		},
		{
			name: "dummy-traceflow-pod-to-service",
			src:  srcPod,
			dst:  "service",
			expectedTf: &v1beta1.Traceflow{
				Spec: v1beta1.TraceflowSpec{
					Source: v1beta1.Source{
						Namespace: "default",
						Pod:       "pod-1",
					},
					Destination: v1beta1.Destination{
						Namespace: "default",
						Service:   "service",
					},
					Packet: v1beta1.Packet{
						IPv6Header: &v1beta1.IPv6Header{
							NextHeader: &protocolTCP,
						},
						TransportHeader: v1beta1.TransportHeader{
							TCP: &v1beta1.TCPHeader{
								DstPort: 4321,
							},
						},
					},
					Timeout: 10,
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			modifyCommandAndOption(tc.src, tc.dst, "yaml", tc.liveTraffic, tc.droppedOnly, "")
			defer modifyCommandAndOption("", "", "yaml", "", "", "")

			tf, err := newTraceflow(k8sClient)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTf.Spec, tf.Spec)
		})
	}
}

func TestGetTFName(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		nowait   string
		expected string
	}{
		{
			name:     "nowait is true",
			prefix:   "default-pod1-to-default-pod2",
			nowait:   "1",
			expected: "default-pod1-to-default-pod2",
		},
		{
			name:     "nowait is true and prefix contains IPv6",
			prefix:   "default-pod1-to-fc00:f853:ccd:e793::2",
			nowait:   "1",
			expected: "default-pod1-to-fc00-f853-ccd-e793-2",
		},
		{
			name:     "nowait is false",
			prefix:   "default-pod1-to-default-pod2",
			expected: "default-pod1-to-default-pod2",
		},
		{
			name:     "nowait is false and prefix contains IPv6",
			prefix:   "default-pod1-to-fc00:f853:ccd:e793::2",
			expected: "default-pod1-to-fc00-f853-ccd-e793-2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			modifyCommandAndOption("", "", "", "", "", tc.nowait)
			defer modifyCommandAndOption("", "", "yaml", "", "", "")

			got := getTFName(tc.prefix)
			if tc.nowait != "" {
				assert.Equal(t, tc.expected, got)
			} else {
				assert.Regexp(t, fmt.Sprintf("^%s-.{8}$", tc.expected), got)
			}
		})
	}
}

// Copyright 2025 Antrea Authors.
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

package packetcapture

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antreafakeclient "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

const (
	srcPod        = "default/pod-1"
	dstPod        = "pod-2"
	ipv4          = "192.168.10.10"
	testNum int32 = 10
)

var (
	antreaAgentPod = v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "antrea-agent-1",
			Namespace: "kube-system",
		},
	}
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
	k8sClient = k8sfake.NewSimpleClientset(&pod1, &pod2, &antreaAgentPod)
)

type testPodFile struct{}

func (p *testPodFile) CopyFromPod(ctx context.Context, fs afero.Fs, namespace, name, containerName, srcPath, dstDir string) error {
	return nil
}

func TestPacketCaptureRun(t *testing.T) {
	tcs := []struct {
		name      string
		option    packetCaptureOptions
		expectErr string
	}{
		{
			name: "pod-2-pod",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_src=50060,tcp_dst=80",
				number: testNum,
			},
		},
		{
			name: "pod-2-ip",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   ipv4,
				nowait: true,
				number: testNum,
				flow:   "udp,udp_src=1234,udp_dst=1234",
			},
		},
		{
			name: "invalid-packetcapture",
			option: packetCaptureOptions{
				source: ipv4,
				dest:   ipv4,
				flow:   "icmp",
				number: testNum,
			},
			expectErr: "error when constructing a PacketCapture CR: one of source and destination must be a Pod",
		},
		{
			name: "invalid timeout settings",
			option: packetCaptureOptions{
				source:  srcPod,
				dest:    dstPod,
				timeout: 500 * time.Second,
				number:  testNum,
			},
			expectErr: "timeout cannot be longer than 5m0s",
		},
		{
			name: "invalid packet number",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   dstPod,
			},
			expectErr: "packet number should be larger than 0",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			client := antreafakeclient.NewSimpleClientset()
			client.PrependReactor("create", "packetcaptures", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				obj := createAction.GetObject().(*v1alpha1.PacketCapture)
				if tt.expectErr == "" {
					obj.Status.FilePath = fmt.Sprintf("%s:/tmp/antrea/packages/%s.pcapng", antreaAgentPod.Name, antreaAgentPod.Name)
					obj.Status.Conditions = []v1alpha1.PacketCaptureCondition{
						{
							Type:   v1alpha1.PacketCaptureComplete,
							Status: metav1.ConditionTrue,
						},
					}
				}
				return false, obj, nil
			})
			getCopier = func(config *rest.Config, client kubernetes.Interface) raw.PodFileCopier {
				return &testPodFile{}
			}
			defer func() {
				getCopier = getPodFileCopier
			}()
			buf := new(bytes.Buffer)
			err := packetCaptureRun(context.TODO(), buf, nil, k8sClient, client, &tt.option)
			if tt.expectErr == "" {
				require.NoError(t, err)
				if tt.option.nowait {
					assert.Contains(t, buf.String(), fmt.Sprintf("PacketCapture Name: %s", getPCName(&tt.option)))
				} else {
					assert.Contains(t, buf.String(), fmt.Sprintf("%s.pcapng", antreaAgentPod.Name))
				}

			} else {
				assert.ErrorContains(t, err, tt.expectErr)
			}
		})
	}
}

func TestTokenizeTCPFlags(t *testing.T) {
	tcs := []struct {
		name        string
		tcp_flags   string
		expectSet   []string
		expectUnset []string
		expectErr   string
	}{
		{
			name:        "good-input-1",
			tcp_flags:   "+syn-ack",
			expectSet:   []string{"syn"},
			expectUnset: []string{"ack"},
		},
		{
			name:        "good-input-2",
			tcp_flags:   "+fin+ack",
			expectSet:   []string{"fin", "ack"},
			expectUnset: nil,
		},
		{
			name:      "bad-input-1",
			tcp_flags: "syn",
			expectErr: "invalid character 's' at 1, expected '+' or '-'",
		},
		{
			name:      "bad-input-2",
			tcp_flags: "+syn#ack",
			expectErr: "invalid character '#' at 5, expected '+' or '-'",
		},
		{
			name:      "bad-input-3",
			tcp_flags: "-acck",
			expectErr: "invalid TCP flag acck",
		},
		{
			name:      "bad-input-4",
			tcp_flags: "-",
			expectErr: "missing TCP flag after '-' at 1",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			set, unset, err := tokenizeTCPFlags(tt.tcp_flags)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectSet, set)
				assert.Equal(t, tt.expectUnset, unset)
			}
		})
	}
}

func TestNewPacketCapture(t *testing.T) {
	tcs := []struct {
		name      string
		option    packetCaptureOptions
		expectErr string
		expectPC  *v1alpha1.PacketCapture
	}{
		{
			name: "pod-2-pod-tcp-syn",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_dst=80,tcp_flags=+syn",
				number: testNum,
			},
			expectPC: &v1alpha1.PacketCapture{
				Spec: v1alpha1.PacketCaptureSpec{
					Source: v1alpha1.Source{
						Pod: &v1alpha1.PodReference{
							Namespace: "default",
							Name:      "pod-1",
						},
					},
					Destination: v1alpha1.Destination{
						Pod: &v1alpha1.PodReference{
							Namespace: "default",
							Name:      "pod-2",
						},
					},
					Timeout: ptr.To(int32(0)),
					CaptureConfig: v1alpha1.CaptureConfig{
						FirstN: &v1alpha1.PacketCaptureFirstNConfig{
							Number: testNum,
						},
					},
					Packet: &v1alpha1.Packet{
						IPFamily: v1.IPv4Protocol,
						Protocol: ptr.To(intstr.FromInt(6)),
						TransportHeader: v1alpha1.TransportHeader{
							TCP: &v1alpha1.TCPHeader{
								DstPort: ptr.To(int32(80)),
								Flags:   []v1alpha1.TCPFlagsMatcher{{Value: 0x2, Mask: ptr.To(int32(0x2))}},
							},
						},
					},
				},
			},
		},
		{
			name: "no-pod",
			option: packetCaptureOptions{
				source: "127.0.0.1",
				dest:   "127.0.0.1",
			},
			expectErr: "one of source and destination must be a Pod",
		},
		{
			name: "bad-flow",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_dst=invalid",
			},
			expectErr: "failed to parse flow: strconv.ParseUint: parsing \"invalid\": invalid syntax",
		},
		{
			name: "bad-flow-2",
			option: packetCaptureOptions{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_dst=80=80",
			},
			expectErr: "failed to parse flow: tcp_dst=80=80 is not valid in flow",
		},
		{
			name: "pod-2-pod-with-direction-both",
			option: packetCaptureOptions{
				source:    srcPod,
				dest:      dstPod,
				number:    testNum,
				direction: "Both",
			},
			expectPC: &v1alpha1.PacketCapture{
				Spec: v1alpha1.PacketCaptureSpec{
					Source: v1alpha1.Source{
						Pod: &v1alpha1.PodReference{
							Namespace: "default",
							Name:      "pod-1",
						},
					},
					Destination: v1alpha1.Destination{
						Pod: &v1alpha1.PodReference{
							Namespace: "default",
							Name:      "pod-2",
						},
					},
					Direction: v1alpha1.CaptureDirectionBoth,
					Timeout:   ptr.To(int32(0)),
					CaptureConfig: v1alpha1.CaptureConfig{
						FirstN: &v1alpha1.PacketCaptureFirstNConfig{
							Number: testNum,
						},
					},
					Packet: &v1alpha1.Packet{
						IPFamily: v1.IPv4Protocol,
					},
				},
			},
		},
		{
			name: "pod-2-pod-with-invalid-direction",
			option: packetCaptureOptions{
				source:    srcPod,
				dest:      dstPod,
				number:    testNum,
				direction: "InvalidDirection",
			},
			expectErr: "invalid direction: \"InvalidDirection\", must be one of SourceToDestination, DestinationToSource, or Both",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			pc, err := newPacketCapture(&tt.option)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectPC.Spec, pc.Spec)
			}
		})
	}
}

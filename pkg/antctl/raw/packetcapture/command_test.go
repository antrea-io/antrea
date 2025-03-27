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
	"github.com/spf13/cobra"
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
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	antreafakeclient "antrea.io/antrea/pkg/client/clientset/versioned/fake"
)

const (
	srcPod            = "default/pod-1"
	dstPod            = "pod-2"
	ipv4              = "192.168.10.10"
	testNum     int32 = 10
	testTimeout       = 3 * time.Second
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

type testPodFile struct {
}

func (p *testPodFile) CopyFromPod(ctx context.Context, fs afero.Fs, namespace, name, containerName, srcPath, dstDir string) error {
	return nil
}

func TestRun(t *testing.T) {
	tcs := []struct {
		name      string
		option    options
		expectErr string
	}{
		{
			name: "pod-2-pod",
			option: options{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_src=50060,tcp_dst=80",
			},
		},
		{
			name: "pod-2-ip",
			option: options{
				source: srcPod,
				dest:   ipv4,
				nowait: true,
				flow:   "udp,udp_src=1234,udp_dst=1234",
			},
		},
		{
			name: "timeout",
			option: options{
				source: srcPod,
				dest:   dstPod,
				flow:   "icmp",
			},
			expectErr: "timeout while waiting for PacketCapture to complete",
		},
		{
			name: "invalid-packetcapture",
			option: options{
				source: ipv4,
				dest:   ipv4,
				flow:   "icmp",
			},
			expectErr: "error when constructing a PacketCapture CR: one of source and destination must be a Pod",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			tt.option.number = 10
			tt.option.timeout = testTimeout
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
			getClients = func(cmd *cobra.Command) (*rest.Config, kubernetes.Interface, antrea.Interface, error) {
				return nil, k8sClient, client, nil
			}
			getCopier = func(cmd *cobra.Command) (raw.PodFileCopier, error) {
				return &testPodFile{}, nil
			}
			defer func() {
				getClients = getConfigAndClients
				getCopier = getPodFileCopier
			}()
			buf := new(bytes.Buffer)
			Command.SetOut(buf)
			Command.SetErr(buf)
			Command.SetContext(context.Background())

			err := packetCaptureRun(Command, &tt.option)
			if tt.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.expectErr)
			}
		})
	}
}

func TestNewPacketCapture(t *testing.T) {
	tcs := []struct {
		name      string
		option    options
		expectErr string
		expectPC  *v1alpha1.PacketCapture
	}{
		{
			name: "pod-2-pod-tcp",
			option: options{
				source:  srcPod,
				dest:    dstPod,
				flow:    "tcp,tcp_dst=80",
				number:  testNum,
				timeout: testTimeout,
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
					Timeout: ptr.To(int32(3)),
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
							},
						},
					},
				},
			},
		},
		{
			name: "no-pod",
			option: options{
				source: "127.0.0.1",
				dest:   "127.0.0.1",
			},
			expectErr: "one of source and destination must be a Pod",
		},
		{
			name: "bad-flow",
			option: options{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_dst=invalid",
			},
			expectErr: "failed to parse flow: error when parsing the flow: strconv.Atoi: parsing \"invalid\": invalid syntax",
		},
		{
			name: "bad-flow-2",
			option: options{
				source: srcPod,
				dest:   dstPod,
				flow:   "tcp,tcp_dst=80=80",
			},
			expectErr: "failed to parse flow: error when parsing the flow: tcp_dst=80=80 is not valid in flow",
		},
	}

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			pc, err := newPacketCapture(&tt.option)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
			} else {
				require.Nil(t, err)
				assert.Equal(t, tt.expectPC.Spec, pc.Spec)
			}
		})
	}
}

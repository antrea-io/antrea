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

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
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

type testPodFile struct {
}

func (p *testPodFile) CopyFromPod(ctx context.Context, namespace, name, containerName, srcPath, dstDir string) error {
	return nil
}

func setCommandOptions(src, dst, notwait, flow string) {
	Command.Flags().Set("source", src)
	Command.Flags().Set("destination", dst)
	Command.Flags().Set("nowait", notwait)
	Command.Flags().Set("number", "10")
	Command.Flags().Set("flow", flow)
}

func TestRun(t *testing.T) {
	tcs := []struct {
		name      string
		src       string
		dst       string
		nowait    string
		flow      string
		expectErr string
	}{
		{
			name: "pod-2-pod",
			src:  srcPod,
			dst:  dstPod,
			flow: "tcp,tcp_src=500060,tcp_dst=80",
		},
		{
			name:   "pod-2-ip",
			src:    srcPod,
			dst:    ipv4,
			nowait: "true",
			flow:   "udp,udp_src=1234,udp_dst=1234",
		},
		{
			name:      "timeout",
			src:       srcPod,
			dst:       dstPod,
			flow:      "icmp",
			expectErr: "timeout waiting for PacketCapture done",
		},
		{
			name:      "invalid-packetcapture",
			src:       ipv4,
			dst:       ipv4,
			flow:      "icmp",
			expectErr: "error when filling up PacketCapture config: one of source and destination must be a Pod",
		},
	}
	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			setCommandOptions(tt.src, tt.dst, tt.nowait, tt.flow)
			defaultTimeout = 3 * time.Second
			defer func() {
				setCommandOptions("", "", "", "")
				defaultTimeout = 60 * time.Second
			}()

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
			getCopier = func(cmd *cobra.Command) (PodFileCopy, error) {
				return &testPodFile{}, nil
			}

			defer func() {
				getClients = getConfigAndClients
				getCopier = getPodFile
			}()
			buf := new(bytes.Buffer)
			Command.SetOutput(buf)
			Command.SetOut(buf)
			Command.SetErr(buf)

			err := packetCaptureRunE(Command, nil)
			if tt.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.NotNil(t, err)
				require.Equal(t, tt.expectErr, err.Error())
			}
		})
	}
}

func TestNewPacketCapture(t *testing.T) {
	tcs := []struct {
		name      string
		src       string
		dst       string
		flow      string
		expectErr string
		expectPC  *v1alpha1.PacketCapture
	}{
		{
			name: "pod-2-pod-tcp",
			src:  srcPod,
			dst:  dstPod,
			flow: "tcp,tcp_dst=80",
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
			name:      "no-pod",
			src:       "127.0.0.1",
			dst:       "127.0.0.1",
			expectErr: "one of source and destination must be a Pod",
		},
		{
			name:      "bad-flow",
			src:       srcPod,
			dst:       dstPod,
			flow:      "tcp,tcp_dst=invalid",
			expectErr: "failed to parse flow: error when parsing the flow: strconv.Atoi: parsing \"invalid\": invalid syntax",
		},
		{
			name:      "bad-flow-2",
			src:       srcPod,
			dst:       dstPod,
			flow:      "tcp,tcp_dst=80=80",
			expectErr: "failed to parse flow: error when parsing the flow: tcp_dst=80=80 is not valid in flow",
		},
	}

	defer func() {
		option.source = ""
		option.dest = ""
		option.flow = ""
		option.number = 0
	}()

	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			option.source = tt.src
			option.dest = tt.dst
			option.flow = tt.flow
			option.number = testNum

			pc, err := newPacketCapture()
			if tt.expectErr != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.expectErr, err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, tt.expectPC.Spec, pc.Spec)
			}

		})
	}

}

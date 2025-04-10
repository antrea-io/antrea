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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/util/env"
)

var (
	defaultTimeout          = time.Second * 60
	maxPacketCaptureTimeout = time.Second * 300
	Command                 *cobra.Command
	getCopier               = getPodFileCopier
	defaultFS               = afero.NewOsFs()
)

type packetCaptureOptions struct {
	source    string
	dest      string
	nowait    bool
	timeout   time.Duration
	number    int32
	flow      string
	outputDir string
}

var options = &packetCaptureOptions{}

var packetCaptureExample = `  Start capturing packets from pod1 to pod2, both Pods are in Namespace default
  $ antctl packetcapture -S pod1 -D pod2
  Start capturing packets from pod1 in Namespace ns1 to a destination IP
  $ antctl packetcapture -S ns1/pod1 -D 192.168.123.123
  Start capturing UDP packets from pod1 to pod2, with destination port 1234
  $ antctl packetcapture -S pod1 -D pod2 -f udp,udp_dst=1234
  Save the packets file to a specified directory
  $ antctl packetcapture -S 192.168.123.123 -D pod2 -f tcp,tcp_dst=80 -o /tmp
`

func init() {
	Command = &cobra.Command{
		Use:     "packetcapture",
		Short:   "Start capture packets",
		Long:    "Start capturing packets on the target flow",
		Aliases: []string{"pc", "packetcaptures"},
		Example: packetCaptureExample,
		RunE:    packetCaptureRunE,
	}

	Command.Flags().StringVarP(&options.source, "source", "S", "", "source of the the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().StringVarP(&options.dest, "destination", "D", "", "destination of the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().Int32VarP(&options.number, "number", "n", 1, "target number of packets to capture, the capture will stop when it is reached")
	Command.Flags().StringVarP(&options.flow, "flow", "f", "", "specify the flow (packet headers) of the PacketCapture, including tcp_src, tcp_dst, udp_src, udp_dst")
	Command.Flags().BoolVarP(&options.nowait, "nowait", "", false, "if set, command returns without retrieving results")
	Command.Flags().StringVarP(&options.outputDir, "output-dir", "o", ".", "save the packets file to the target directory")
}

var protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

func getPodFileCopier(config *rest.Config, client kubernetes.Interface) raw.PodFileCopier {
	return raw.NewPodFileCopier(config, client)
}

func getConfigAndClients(cmd *cobra.Command) (*rest.Config, kubernetes.Interface, antrea.Interface, error) {
	kubeConfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	k8sClientset, client, err := raw.SetupClients(kubeConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return kubeConfig, k8sClientset, client, nil
}

func getPCName(options *packetCaptureOptions) string {
	replace := func(s string) string {
		return strings.ReplaceAll(s, "/", "-")
	}
	prefix := fmt.Sprintf("%s-%s", replace(options.source), replace(options.dest))
	if options.nowait {
		return prefix
	}
	return fmt.Sprintf("%s-%s", prefix, rand.String(8))
}

func packetCaptureRunE(cmd *cobra.Command, args []string) error {
	options.timeout, _ = cmd.Flags().GetDuration("timeout")
	restConfig, k8sClient, antreaClient, err := getConfigAndClients(cmd)
	if err != nil {
		return err
	}
	return packetCaptureRun(cmd.Context(), cmd.OutOrStdout(), restConfig, k8sClient, antreaClient, options)
}

func packetCaptureRun(ctx context.Context, out io.Writer, restConfig *rest.Config, k8sClient kubernetes.Interface, antreaClient antrea.Interface, options *packetCaptureOptions) error {
	if options.timeout > maxPacketCaptureTimeout {
		return fmt.Errorf("timeout cannot be longer than %v", maxPacketCaptureTimeout)
	}
	if options.timeout == 0 {
		options.timeout = defaultTimeout
	}
	if options.number == 0 {
		return errors.New("packet number should be larger than 0")
	}

	pc, err := newPacketCapture(options)
	if err != nil {
		return fmt.Errorf("error when constructing a PacketCapture CR: %w", err)
	}
	createCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := antreaClient.CrdV1alpha1().PacketCaptures().Create(createCtx, pc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating PacketCapture, is PacketCapture feature gate enabled? %w", err)
	}

	if options.nowait {
		fmt.Fprintf(out, "PacketCapture Name: %s\n", pc.Name)
		return nil
	} else {
		defer func() {
			if err = antreaClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), pc.Name, metav1.DeleteOptions{}); err != nil {
				fmt.Fprintf(out, "error when deleting PacketCapture: %s", err.Error())
			}
		}()
	}

	var latestPC *v1alpha1.PacketCapture

	// add extra timeout to make sure the wait won't be interrupted before PacketCapture timeout.
	err = wait.PollUntilContextTimeout(ctx, 1*time.Second, options.timeout+time.Second*5, false, func(ctx context.Context) (bool, error) {
		res, err := antreaClient.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range res.Status.Conditions {
			if cond.Type == v1alpha1.PacketCaptureComplete && cond.Status == metav1.ConditionTrue {
				latestPC = res
				if cond.Reason == "Failed" {
					return false, errors.New(cond.Message)
				}
				return true, nil
			}
		}
		return false, nil
	})

	if wait.Interrupted(err) {
		err = errors.New("timeout while waiting for PacketCapture to complete")
		if latestPC == nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("error when checking PacketCapture status: %w", err)
	}

	splits := strings.Split(latestPC.Status.FilePath, ":")
	fileName := path.Base(splits[1])
	copier := getCopier(restConfig, k8sClient)
	if err := copier.CopyFromPod(ctx, defaultFS, env.GetAntreaNamespace(), splits[0], "antrea-agent", splits[1], options.outputDir); err != nil {
		return fmt.Errorf("error when copying pcapng file from container: %w", err)
	}
	fmt.Fprintf(out, "Captured packets file: %s\n", path.Join(options.outputDir, fileName))
	return nil
}

func parseEndpoint(endpoint string) (*v1alpha1.PodReference, *string) {
	var pod *v1alpha1.PodReference
	var ip *string
	parsedIP := net.ParseIP(endpoint)
	if parsedIP != nil && parsedIP.To4() != nil {
		ip = ptr.To(parsedIP.String())
	} else {
		split := strings.Split(endpoint, "/")
		if len(split) == 1 {
			pod = &v1alpha1.PodReference{
				Namespace: "default",
				Name:      split[0],
			}
		} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
			pod = &v1alpha1.PodReference{
				Namespace: split[0],
				Name:      split[1],
			}
		}
	}
	return pod, ip
}

func getFlowFields(flow string) (map[string]int, error) {
	fields := map[string]int{}
	for _, v := range strings.Split(flow, ",") {
		kv := strings.Split(v, "=")
		if len(kv) == 2 && len(kv[0]) != 0 && len(kv[1]) != 0 {
			r, err := strconv.Atoi(kv[1])
			if err != nil {
				return nil, err
			}
			fields[kv[0]] = r
		} else if len(kv) == 1 {
			if len(kv[0]) != 0 {
				fields[v] = 0
			}
		} else {
			return nil, fmt.Errorf("%s is not valid in flow", v)
		}
	}
	return fields, nil
}

func parseFlow(options *packetCaptureOptions) (*v1alpha1.Packet, error) {
	trimFlow := strings.ReplaceAll(options.flow, " ", "")
	fields, err := getFlowFields(trimFlow)
	if err != nil {
		return nil, fmt.Errorf("error when parsing the flow: %w", err)
	}
	var pkt v1alpha1.Packet
	pkt.IPFamily = v1.IPv4Protocol
	for k, v := range protocols {
		if _, ok := fields[k]; ok {
			pkt.Protocol = ptr.To(intstr.FromInt32(v))
			break
		}
	}
	if r, ok := fields["tcp_src"]; ok {
		pkt.TransportHeader.TCP = new(v1alpha1.TCPHeader)
		pkt.TransportHeader.TCP.SrcPort = ptr.To(int32(r))
	}
	if r, ok := fields["tcp_dst"]; ok {
		if pkt.TransportHeader.TCP == nil {
			pkt.TransportHeader.TCP = new(v1alpha1.TCPHeader)
		}
		pkt.TransportHeader.TCP.DstPort = ptr.To(int32(r))
	}
	if r, ok := fields["udp_src"]; ok {
		pkt.TransportHeader.UDP = new(v1alpha1.UDPHeader)
		pkt.TransportHeader.UDP.SrcPort = ptr.To(int32(r))
	}
	if r, ok := fields["udp_dst"]; ok {
		if pkt.TransportHeader.UDP == nil {
			pkt.TransportHeader.UDP = new(v1alpha1.UDPHeader)
		}
		pkt.TransportHeader.UDP.DstPort = ptr.To(int32(r))
	}
	return &pkt, nil
}

func newPacketCapture(options *packetCaptureOptions) (*v1alpha1.PacketCapture, error) {
	var src v1alpha1.Source
	if options.source != "" {
		src.Pod, src.IP = parseEndpoint(options.source)
		if src.Pod == nil && src.IP == nil {
			return nil, fmt.Errorf("source should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	var dst v1alpha1.Destination
	if options.dest != "" {
		dst.Pod, dst.IP = parseEndpoint(options.dest)
		if dst.Pod == nil && dst.IP == nil {
			return nil, fmt.Errorf("destination should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	if src.Pod == nil && dst.Pod == nil {
		return nil, errors.New("one of source and destination must be a Pod")
	}
	pkt, err := parseFlow(options)
	if err != nil {
		return nil, fmt.Errorf("failed to parse flow: %w", err)
	}

	name := getPCName(options)
	timeout := int32(options.timeout.Seconds())
	pc := &v1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.PacketCaptureSpec{
			Source:      src,
			Destination: dst,
			Timeout:     &timeout,
			Packet:      pkt,
			CaptureConfig: v1alpha1.CaptureConfig{
				FirstN: &v1alpha1.PacketCaptureFirstNConfig{
					Number: options.number,
				},
			},
		},
	}
	return pc, nil
}

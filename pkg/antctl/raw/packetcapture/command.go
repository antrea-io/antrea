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
	"net"
	"path/filepath"
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
	defaultTimeout = time.Second * 60
	Command        *cobra.Command
	getClients     = getConfigAndClients
	getCopier      = getPodFile
	defaultFS      = afero.NewOsFs()
)
var option = &struct {
	source    string
	dest      string
	nowait    bool
	timeout   time.Duration
	number    int32
	flow      string
	outputDir string
}{}

var packetCaptureExample = strings.TrimSpace(`
  Start capture packets from pod1 to pod2, both Pods are in Namespace default
  $ antctl packetcaputre -S pod1 -D pod2
  Start capture packets from pod1 in Namespace ns1 to a destination IP
  $ antctl packetcapture -S ns1/pod1 -D 192.168.123.123
  Start capture UDP packets from pod1 to pod2, with destination port 1234
  $ antctl packetcapture -S pod1 -D pod2 -f udp,udp_dst=1234
  Save the packets file to a specified directory
  $ antctl packetcapture -S 192.168.123.123 -D pod2 -f tcp,tcp_dst=80 -o /tmp
`)

func init() {
	Command = &cobra.Command{
		Use:     "packetcapture",
		Short:   "Start capture packets",
		Long:    "Start capture packets on the target flow.",
		Aliases: []string{"pc", "packetcaptures"},
		Example: packetCaptureExample,
		RunE:    packetCaptureRunE,
	}

	Command.Flags().StringVarP(&option.source, "source", "S", "", "source of the the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().StringVarP(&option.dest, "destination", "D", "", "destination of the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().Int32VarP(&option.number, "number", "n", 0, "target packets number")
	Command.Flags().StringVarP(&option.flow, "flow", "f", "", "specify the flow (packet headers) of the PacketCapture , including tcp_src, tcp_dst, udp_src, udp_dst")
	Command.Flags().BoolVarP(&option.nowait, "nowait", "", false, "if set, command returns without retrieving results")
	Command.Flags().StringVarP(&option.outputDir, "output-dir", "o", ".", "save the packets file to the target directory")
}

var protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
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

func getPodFile(cmd *cobra.Command) (PodFileCopy, error) {
	config, client, _, err := getClients(cmd)
	if err != nil {
		return nil, err
	}
	return &podFile{
		restConfig:    config,
		restInterface: client.CoreV1().RESTClient(),
	}, nil
}

func packetCaptureRunE(cmd *cobra.Command, args []string) error {
	option.timeout, _ = cmd.Flags().GetDuration("timeout")
	if option.timeout > time.Hour {
		return errors.New("timeout cannot be longer than 1 hour")
	}
	if option.timeout == 0 {
		option.timeout = defaultTimeout
	}
	if option.number == 0 {
		return errors.New("packet number should be larger than 0")
	}

	_, _, antreaClient, err := getClients(cmd)
	if err != nil {
		return err
	}
	pc, err := newPacketCapture()
	if err != nil {
		return fmt.Errorf("error when filling up PacketCapture config: %w", err)
	}
	createCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := antreaClient.CrdV1alpha1().PacketCaptures().Create(createCtx, pc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating PacketCapture, is PacketCapture feature gate enabled? %w", err)
	}
	defer func() {
		if !option.nowait {
			if err = antreaClient.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), pc.Name, metav1.DeleteOptions{}); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "error when deleting PacketCapture: %s", err.Error())
			}
		}
	}()

	if option.nowait {
		fmt.Fprintf(cmd.OutOrStdout(), "PacketCapture Name:  %s\n", pc.Name)
		return nil
	}

	var latestPC *v1alpha1.PacketCapture
	err = wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, option.timeout, false, func(ctx context.Context) (bool, error) {
		res, err := antreaClient.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range res.Status.Conditions {
			if cond.Type == v1alpha1.PacketCaptureComplete && cond.Status == metav1.ConditionTrue {
				latestPC = res
				return true, nil
			}
		}
		return false, nil

	})

	if wait.Interrupted(err) {
		err = errors.New("timeout waiting for PacketCapture done")
		if latestPC == nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("error when retrieving PacketCapture: %w", err)
	}

	splits := strings.Split(latestPC.Status.FilePath, ":")
	fileName := filepath.Base(splits[1])
	copier, _ := getCopier(cmd)
	err = copier.CopyFromPod(context.TODO(), env.GetAntreaNamespace(), splits[0], "antrea-agent", splits[1], option.outputDir)
	if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Packet File: %s\n", filepath.Join(option.outputDir, fileName))
	}
	return err
}

func parseEndpoint(endpoint string) (pod *v1alpha1.PodReference, ip *string) {
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
	return
}

func getPCName(src, dest string) string {
	replace := func(s string) string {
		return strings.ReplaceAll(s, "/", "-")
	}
	prefix := fmt.Sprintf("%s-%s", replace(src), replace(dest))
	if option.nowait {
		return prefix
	}
	return fmt.Sprintf("%s-%s", prefix, rand.String(8))
}

func parseFlow() (*v1alpha1.Packet, error) {
	cleanFlow := strings.ReplaceAll(option.flow, " ", "")
	fields, err := getFlowFields(cleanFlow)
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
		if pkt.TransportHeader.UDP != nil {
			pkt.TransportHeader.UDP = new(v1alpha1.UDPHeader)
		}
		pkt.TransportHeader.UDP.DstPort = ptr.To(int32(r))
	}
	return &pkt, nil
}

func newPacketCapture() (*v1alpha1.PacketCapture, error) {
	var src v1alpha1.Source
	if option.source != "" {
		src.Pod, src.IP = parseEndpoint(option.source)
		if src.Pod == nil && src.IP == nil {
			return nil, fmt.Errorf("source should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	var dst v1alpha1.Destination
	if option.dest != "" {
		dst.Pod, dst.IP = parseEndpoint(option.dest)
		if dst.Pod == nil && dst.IP == nil {
			return nil, fmt.Errorf("destination should be in the format of Namespace/Pod, Pod, or IPv4")
		}
	}

	if src.Pod == nil && dst.Pod == nil {
		return nil, errors.New("one of source and destination must be a Pod")
	}
	pkt, err := parseFlow()
	if err != nil {
		return nil, fmt.Errorf("failed to parse flow: %w", err)
	}

	name := getPCName(option.source, option.dest)
	pc := &v1alpha1.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.PacketCaptureSpec{
			Source:      src,
			Destination: dst,
			Packet:      pkt,
			CaptureConfig: v1alpha1.CaptureConfig{
				FirstN: &v1alpha1.PacketCaptureFirstNConfig{
					Number: option.number,
				},
			},
		},
	}
	return pc, nil
}

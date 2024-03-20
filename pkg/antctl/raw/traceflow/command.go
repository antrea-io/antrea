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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
)

const defaultTimeout time.Duration = time.Second * 10

var (
	Command *cobra.Command
	option  = &struct {
		source      string
		destination string
		outputType  string
		flow        string
		liveTraffic bool
		droppedOnly bool
		timeout     time.Duration
		nowait      bool
	}{}
	getClients = getK8sClient
)

var protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

type CapturedPacket struct {
	SrcIP           string                   `json:"srcIP" yaml:"srcIP"`
	DstIP           string                   `json:"dstIP" yaml:"dstIP"`
	Length          int32                    `json:"length" yaml:"length"`
	IPHeader        *v1beta1.IPHeader        `json:"ipHeader,omitempty" yaml:"ipHeader,omitempty"`
	IPv6Header      *v1beta1.IPv6Header      `json:"ipv6Header,omitempty" yaml:"ipv6Header,omitempty"`
	TransportHeader *v1beta1.TransportHeader `json:"transportHeader,omitempty" yaml:"tranportHeader,omitempty"`
}

// Response is the response of antctl Traceflow.
type Response struct {
	Name           string                 `json:"name" yaml:"name"`                                         // Traceflow name
	Phase          v1beta1.TraceflowPhase `json:"phase,omitempty" yaml:"phase,omitempty"`                   // Traceflow phase
	Reason         string                 `json:"reason,omitempty" yaml:"reason,omitempty"`                 // Traceflow phase reason
	Source         string                 `json:"source,omitempty" yaml:"source,omitempty"`                 // Traceflow source, e.g. "default/pod0"
	Destination    string                 `json:"destination,omitempty" yaml:"destination,omitempty"`       // Traceflow destination, e.g. "default/pod1"
	NodeResults    []v1beta1.NodeResult   `json:"results,omitempty" yaml:"results,omitempty"`               // Traceflow node results
	CapturedPacket *CapturedPacket        `json:"capturedPacket,omitempty" yaml:"capturedPacket,omitempty"` // Captured packet in live-traffic Traceflow
}

func init() {
	Command = &cobra.Command{
		Use:     "traceflow",
		Short:   "Start a Traceflows",
		Long:    "Start a Traceflows from one Pod to another Pod/Service/IP.",
		Aliases: []string{"tf", "traceflows"},
		Example: `  Start a Traceflow from pod1 to pod2, both Pods are in Namespace default
  $antctl traceflow -S pod1 -D pod2
  Start a Traceflow from pod1 in Namepace ns1 to a destination IP
  $antctl traceflow -S ns1/pod1 -D 123.123.123.123
  Start a Traceflow from pod1 to Service svc1 in Namespace ns1
  $antctl traceflow -S pod1 -D ns1/svc1 -f tcp,tcp_dst=80
  Start a Traceflow from pod1 to pod2, with a UDP packet to destination port 1234
  $antctl traceflow -S pod1 -D pod2 -f udp,udp_dst=1234
  Start a Traceflow for live TCP traffic from pod1 to svc1, with 1 minute timeout
  $antctl traceflow -S pod1 -D svc1 -f tcp --live-traffic -t 1m
  Start a Traceflow to capture the first dropped TCP packet to pod1 on port 80, within 10 minutes
  $antctl traceflow -D pod1 -f tcp,tcp_dst=80 --live-traffic --dropped-only -t 10m
`,
		RunE: runE,
		Args: cobra.NoArgs,
	}

	Command.Flags().StringVarP(&option.source, "source", "S", "", "source of the Traceflow: Namespace/Pod, Pod, or IP")
	Command.Flags().StringVarP(&option.destination, "destination", "D", "", "destination of the Traceflow: Namespace/Pod, Pod, Namespace/Service, Service or IP")
	Command.Flags().StringVarP(&option.outputType, "output", "o", "yaml", "output type: yaml (default), json")
	Command.Flags().StringVarP(&option.flow, "flow", "f", "", "specify the flow (packet headers) of the Traceflow packet, including tcp_src, tcp_dst, tcp_flags, udp_src, udp_dst, ipv6")
	Command.Flags().BoolVarP(&option.liveTraffic, "live-traffic", "L", false, "if set, the Traceflow will trace the first packet of the matched live traffic flow")
	Command.Flags().BoolVarP(&option.droppedOnly, "dropped-only", "", false, "if set, capture only the dropped packet in a live-traffic Traceflow")
	Command.Flags().BoolVarP(&option.nowait, "nowait", "", false, "if set, command returns without retrieving results")
}

func getK8sClient(cmd *cobra.Command) (kubernetes.Interface, antrea.Interface, error) {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, err
	}
	k8sClientset, client, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return k8sClientset, client, nil
}

func runE(cmd *cobra.Command, _ []string) error {
	option.timeout, _ = cmd.Flags().GetDuration("timeout")
	if option.timeout > time.Hour*12 {
		fmt.Fprintf(cmd.OutOrStdout(), "Timeout cannot be longer than 12 hours")
		return nil
	}
	if option.timeout == 0 {
		option.timeout = defaultTimeout
	}

	if !option.liveTraffic && option.source == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Please provide source")
		return nil
	}

	if !option.liveTraffic && option.destination == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Please provide destination")
		return nil
	}

	if option.source == "" && option.destination == "" {
		fmt.Fprintf(cmd.OutOrStdout(), "One of source and destination must be a Pod")
		return nil
	}

	if !option.liveTraffic && option.droppedOnly {
		fmt.Fprintf(cmd.OutOrStdout(), "--dropped-only works only with live-traffic Traceflow")
		return nil
	}

	k8sclient, client, err := getClients(cmd)
	if err != nil {
		return err
	}
	tf, err := newTraceflow(k8sclient)
	if err != nil {
		return fmt.Errorf("error when filling up Traceflow config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = client.CrdV1beta1().Traceflows().Create(ctx, tf, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating Traceflow, is Traceflow feature gate enabled? %w", err)
	}
	defer func() {
		if !option.nowait {
			if err = client.CrdV1beta1().Traceflows().Delete(context.TODO(), tf.Name, metav1.DeleteOptions{}); err != nil {
				klog.Errorf("error when deleting Traceflow: %+v", err)
			}
		}
	}()

	if option.nowait {
		return nil
	}

	var res *v1beta1.Traceflow
	err = wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, option.timeout, false, func(ctx context.Context) (bool, error) {
		res, err = client.CrdV1beta1().Traceflows().Get(context.TODO(), tf.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if res.Status.Phase != v1beta1.Succeeded && res.Status.Phase != v1beta1.Failed {
			return false, nil
		}
		return true, nil
	})
	if wait.Interrupted(err) {
		err = errors.New("timeout waiting for Traceflow done")
		// Still output the Traceflow results if any.
		if res == nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("error when retrieving Traceflow: %w", err)
	}

	if err := output(res, cmd.OutOrStdout()); err != nil {
		return fmt.Errorf("error when outputting result: %w", err)
	}
	return err
}

func newTraceflow(client kubernetes.Interface) (*v1beta1.Traceflow, error) {
	var srcName, dstName string
	var src v1beta1.Source

	if option.source != "" {
		srcIP := net.ParseIP(option.source)
		if srcIP != nil {
			if !option.liveTraffic {
				return nil, errors.New("source must be a Pod if not a live-traffic Traceflow")
			}
			src.IP = srcIP.String()
			srcName = src.IP
		} else {
			split := strings.Split(option.source, "/")
			if len(split) == 1 {
				src.Namespace = "default"
				src.Pod = split[0]
				srcName = src.Pod
			} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
				src.Namespace = split[0]
				src.Pod = split[1]
				srcName = fmt.Sprintf("%s-%s", src.Namespace, src.Pod)
			} else {
				return nil, errors.New("source should be in the format of Namespace/Pod or Pod, or an IP address")
			}
		}
	} else {
		srcName = "any"
	}

	var dst v1beta1.Destination
	if option.destination != "" {
		dstIP := net.ParseIP(option.destination)
		if dstIP != nil {
			dst.IP = dstIP.String()
			dstName = dst.IP
		} else {
			var isPod bool
			var dest string
			var err error
			split := strings.Split(option.destination, "/")
			if len(split) == 1 {
				dst.Namespace = "default"
				dest = split[0]
				dstName = dest
			} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
				dst.Namespace = split[0]
				dest = split[1]
				dstName = fmt.Sprintf("%s-%s", dst.Namespace, dest)
			} else {
				return nil, fmt.Errorf("destination should be in the format of Namespace/Pod, Pod, Namespace/Service or Service")
			}
			if isPod, err = dstIsPod(client, dst.Namespace, dest); err != nil {
				return nil, fmt.Errorf("failed to check if destination is Pod or Service: %w", err)
			}
			if isPod {
				dst.Pod = dest
			} else {
				dst.Service = dest
			}
		}
	} else {
		dstName = "any"
	}

	if src.Pod == "" && dst.Pod == "" {
		return nil, errors.New("one of source and destination must be a Pod")
	}

	pkt, err := parseFlow()
	if err != nil {
		return nil, fmt.Errorf("failed to parse flow: %w", err)
	}

	name := getTFName(fmt.Sprintf("%s-to-%s", srcName, dstName))
	tf := &v1beta1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1beta1.TraceflowSpec{
			Source:      src,
			Destination: dst,
			Packet:      *pkt,
			LiveTraffic: option.liveTraffic,
			DroppedOnly: option.droppedOnly,
			Timeout:     int32(option.timeout.Seconds()),
		},
	}
	return tf, nil
}

func dstIsPod(client kubernetes.Interface, ns string, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get Pod from Kubernetes API: %w", err)
	}
	return true, nil
}

func parseFlow() (*v1beta1.Packet, error) {
	cleanFlow := strings.ReplaceAll(option.flow, " ", "")
	fields, err := getPortFields(cleanFlow)
	if err != nil {
		return nil, fmt.Errorf("error when parsing the flow: %w", err)
	}

	var pkt v1beta1.Packet

	_, isIPv6 := fields["ipv6"]
	if isIPv6 {
		pkt.IPv6Header = new(v1beta1.IPv6Header)
	} else {
		pkt.IPHeader = new(v1beta1.IPHeader)
	}
	for k, v := range protocols {
		if _, ok := fields[k]; ok {
			if isIPv6 {
				protocol := v
				pkt.IPv6Header.NextHeader = &protocol
			} else {
				pkt.IPHeader.Protocol = v
			}
			break
		}
	}

	if r, ok := fields["tcp_src"]; ok {
		pkt.TransportHeader.TCP = new(v1beta1.TCPHeader)
		pkt.TransportHeader.TCP.SrcPort = int32(r)
	}
	if r, ok := fields["tcp_dst"]; ok {
		if pkt.TransportHeader.TCP == nil {
			pkt.TransportHeader.TCP = new(v1beta1.TCPHeader)
		}
		pkt.TransportHeader.TCP.DstPort = int32(r)
	}
	if r, ok := fields["tcp_flags"]; ok {
		if pkt.TransportHeader.TCP == nil {
			pkt.TransportHeader.TCP = new(v1beta1.TCPHeader)
		}
		tcpFlags := int32(r)
		pkt.TransportHeader.TCP.Flags = &tcpFlags
	}
	if r, ok := fields["udp_src"]; ok {
		pkt.TransportHeader.UDP = new(v1beta1.UDPHeader)
		pkt.TransportHeader.UDP.SrcPort = int32(r)
	}
	if r, ok := fields["udp_dst"]; ok {
		if pkt.TransportHeader.UDP == nil {
			pkt.TransportHeader.UDP = new(v1beta1.UDPHeader)
		}
		pkt.TransportHeader.UDP.DstPort = int32(r)
	}

	return &pkt, nil
}

func getPortFields(cleanFlow string) (map[string]int, error) {
	fields := map[string]int{}
	for _, v := range strings.Split(cleanFlow, ",") {
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

func output(tf *v1beta1.Traceflow, writer io.Writer) error {
	r := Response{
		Name:        tf.Name,
		Phase:       tf.Status.Phase,
		Reason:      tf.Status.Reason,
		Source:      fmt.Sprintf("%s/%s", tf.Spec.Source.Namespace, tf.Spec.Source.Pod),
		NodeResults: tf.Status.Results,
	}
	if len(tf.Spec.Destination.IP) > 0 {
		r.Destination = tf.Spec.Destination.IP
	} else if len(tf.Spec.Destination.Pod) != 0 {
		r.Destination = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Pod)
	} else if len(tf.Spec.Destination.Service) != 0 {
		r.Destination = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Service)
	}

	pkt := tf.Status.CapturedPacket
	if pkt != nil {
		r.CapturedPacket = &CapturedPacket{SrcIP: pkt.SrcIP, DstIP: pkt.DstIP, Length: pkt.Length, IPv6Header: pkt.IPv6Header}
		if pkt.IPv6Header == nil {
			r.CapturedPacket.IPHeader = pkt.IPHeader
		}
		if pkt.TransportHeader.TCP != nil || pkt.TransportHeader.UDP != nil || pkt.TransportHeader.ICMP != nil {
			r.CapturedPacket.TransportHeader = &pkt.TransportHeader
		}
	}

	if option.outputType == "json" {
		if err := jsonOutput(&r, writer); err != nil {
			return fmt.Errorf("error when converting output to json: %w", err)
		}
	} else if option.outputType == "yaml" {
		if err := yamlOutput(&r, writer); err != nil {
			return fmt.Errorf("error when converting output to yaml: %w", err)
		}
	} else {
		return fmt.Errorf("output types should be yaml or json")
	}
	return nil
}

func yamlOutput(r *Response, writer io.Writer) error {
	o, err := yaml.Marshal(&r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%s", o)
	if err != nil {
		return fmt.Errorf("error when outputing in yaml format: %w", err)
	}
	return nil
}

func jsonOutput(r *Response, writer io.Writer) error {
	o, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err = json.Indent(&b, o, "", "  "); err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%s", b.String())
	if err != nil {
		return fmt.Errorf("error when outputing in json format: %w", err)
	}
	return nil
}

func getTFName(prefix string) string {
	// prefix may contain IPv6 address. Replace "::"  and ":" to make it a valid RFC 1123 subdomain.
	prefix = strings.ReplaceAll(prefix, "::", "-")
	prefix = strings.ReplaceAll(prefix, ":", "-")
	if option.nowait {
		return prefix
	}
	return fmt.Sprintf("%s-%s", prefix, rand.String(8))
}

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
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
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
		nowait      bool
		timeout     time.Duration
	}{}
)

var protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

// Response is the response of antctl Traceflow.
type Response struct {
	Name        string                  `json:"name" yaml:"name"`                                   // Traceflow name
	Phase       v1alpha1.TraceflowPhase `json:"phase,omitempty" yaml:"phase,omitempty"`             // Traceflow phase
	Source      string                  `json:"source,omitempty" yaml:"source,omitempty"`           // Traceflow source, e.g. "default/pod0"
	Destination string                  `json:"destination,omitempty" yaml:"destination,omitempty"` // Traceflow destination, e.g. "default/pod1"
	NodeResults []v1alpha1.NodeResult   `json:"results,omitempty" yaml:"results,omitempty"`         // Traceflow node results
}

func init() {
	Command = &cobra.Command{
		Use:     "traceflow",
		Short:   "Start a Traceflows",
		Long:    "Start a Traceflows from one Pod to another Pod/Service/IP.",
		Aliases: []string{"tf", "traceflows"},
		Example: `  Start a Traceflow from busybox0 to busybox1, both Pods are in Namespace default
  $antctl traceflow -S busybox0 -D busybox1
  Start a Traceflow from busybox0 to destination IP, source is in Namespace default
  $antctl traceflow -S busybox0 -D 123.123.123.123
  Start a Traceflow from busybox0 to destination Service, source and destination are in Namespace default
  $antctl traceflow -S busybox0 -D svc0 -f tcp,tcp_dst=80,tcp_flags=2
  Start a Traceflow from busybox0 in Namespace ns0 to busybox1 in Namespace ns1, output type is json
  $antctl traceflow -S ns0/busybox0 -D ns1/busybox1 -o json
  Start a Traceflow from busybox0 to busybox1, with a TCP packet to destination port 80
  $antctl traceflow -S busybox0 -D busybox1 -f tcp,tcp_dst=80
  Start a Traceflow for live TCP traffic from busybox0 to TCP port 80, with 1 minute timeout
  $antctl traceflow -S busybox0 -f tcp,tcp_dst=80 --live-traffic -t 1m
`,
		RunE: runE,
	}

	Command.Flags().StringVarP(&option.source, "source", "S", "", "source of the Traceflow: Namespace/Pod or Pod")
	Command.Flags().StringVarP(&option.destination, "destination", "D", "", "destination of the Traceflow: Namespace/Pod, Pod, Namespace/Service, Service or IP")
	Command.Flags().StringVarP(&option.outputType, "output", "o", "yaml", "output type: yaml (default), json")
	Command.Flags().StringVarP(&option.flow, "flow", "f", "", "specify the flow (packet headers) of the Traceflow packet, including tcp_src, tcp_dst, tcp_flags, udp_src, udp_dst, ipv6")
	Command.Flags().BoolVarP(&option.liveTraffic, "live-traffic", "L", false, "if set, the Traceflow will trace the first packet of the matched live traffic flow")
	Command.Flags().BoolVarP(&option.nowait, "nowait", "", false, "if set, command returns without retrieving results")
}

func runE(cmd *cobra.Command, _ []string) error {
	option.timeout, _ = cmd.Flags().GetDuration("timeout")
	if option.timeout > time.Hour*12 {
		fmt.Println("Timeout cannot be longer than 12 hours")
		return nil
	}
	if option.timeout == 0 {
		option.timeout = defaultTimeout
	}

	if len(option.source) == 0 {
		fmt.Println("Please provide source")
		return nil
	}

	if !option.liveTraffic && len(option.destination) == 0 {
		fmt.Println("Please provide destination")
		return nil
	}

	kubeconfigPath, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		return err
	}
	kubeconfig, err := runtime.ResolveKubeconfig(kubeconfigPath)
	if err != nil {
		return err
	}

	k8sclient, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating kubernetes clientset: %w", err)
	}
	client, err := clientset.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("error when creating clientset: %w", err)
	}

	tf, err := newTraceflow(k8sclient)
	if err != nil {
		return fmt.Errorf("error when filling up Traceflow config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = client.CrdV1alpha1().Traceflows().Create(ctx, tf, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating Traceflow, is Traceflow feature gate enabled? %w", err)
	}
	defer func() {
		if !option.nowait {
			if err = client.CrdV1alpha1().Traceflows().Delete(context.TODO(), tf.Name, metav1.DeleteOptions{}); err != nil {
				klog.Errorf("error when deleting Traceflow: %+v", err)
			}
		}
	}()

	if option.nowait {
		return nil
	}

	var res *v1alpha1.Traceflow
	err = wait.Poll(1*time.Second, option.timeout, func() (bool, error) {
		res, err = client.CrdV1alpha1().Traceflows().Get(context.TODO(), tf.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if res.Status.Phase != v1alpha1.Succeeded && res.Status.Phase != v1alpha1.Failed {
			return false, nil
		}
		return true, nil
	})
	if err == wait.ErrWaitTimeout {
		err = errors.New("timeout waiting for Traceflow done")
		// Still output the Traceflow results if any.
		if res == nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("error when retrieving Traceflow: %w", err)
	}

	if err := output(res); err != nil {
		return fmt.Errorf("error when outputting result: %w", err)
	}
	return err
}

func newTraceflow(client kubernetes.Interface) (*v1alpha1.Traceflow, error) {
	var name string
	var src v1alpha1.Source
	split := strings.Split(option.source, "/")
	if len(split) == 1 {
		src.Namespace = "default"
		src.Pod = split[0]
	} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
		src.Namespace = split[0]
		src.Pod = split[1]
	} else {
		return nil, fmt.Errorf("source should be in the format of Namespace/Pod or Pod")
	}

	var dst v1alpha1.Destination
	if option.destination != "" {
		dstIP := net.ParseIP(option.destination)
		if dstIP != nil {
			dst.IP = dstIP.String()
			name = getTFName(fmt.Sprintf("%s-%s-to-%s", src.Namespace, src.Pod, dst.IP))
		} else {
			var isPod bool
			var dest string
			var err error
			split = strings.Split(option.destination, "/")
			if len(split) == 1 {
				dst.Namespace = "default"
				dest = split[0]
			} else if len(split) == 2 && len(split[0]) != 0 && len(split[1]) != 0 {
				dst.Namespace = split[0]
				dest = split[1]
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
			name = getTFName(fmt.Sprintf("%s-%s-to-%s-%s", src.Namespace, src.Pod, dst.Namespace, dest))
		}
	} else {
		name = getTFName(fmt.Sprintf("%s-%s-to-any", src.Namespace, src.Pod))
	}

	pkt, err := parseFlow()
	if err != nil {
		return nil, fmt.Errorf("failed to parse flow: %w", err)
	}

	tf := &v1alpha1.Traceflow{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.TraceflowSpec{
			Source:      src,
			Destination: dst,
			Packet:      *pkt,
			Timeout:     uint16(option.timeout.Seconds()),
			LiveTraffic: option.liveTraffic,
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

func parseFlow() (*v1alpha1.Packet, error) {
	cleanFlow := strings.ReplaceAll(option.flow, " ", "")
	fields, err := getPortFields(cleanFlow)
	if err != nil {
		return nil, fmt.Errorf("error when parsing the flow: %w", err)
	}

	var pkt v1alpha1.Packet

	_, isIPv6 := fields["ipv6"]
	if isIPv6 {
		pkt.IPv6Header = new(v1alpha1.IPv6Header)
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
		pkt.TransportHeader.TCP = new(v1alpha1.TCPHeader)
		pkt.TransportHeader.TCP.SrcPort = int32(r)
	}
	if r, ok := fields["tcp_dst"]; ok {
		if pkt.TransportHeader.TCP == nil {
			pkt.TransportHeader.TCP = new(v1alpha1.TCPHeader)
		}
		pkt.TransportHeader.TCP.DstPort = int32(r)
	}
	if r, ok := fields["tcp_flags"]; ok {
		if pkt.TransportHeader.TCP == nil {
			pkt.TransportHeader.TCP = new(v1alpha1.TCPHeader)
		}
		pkt.TransportHeader.TCP.Flags = int32(r)
	}
	if r, ok := fields["udp_src"]; ok {
		pkt.TransportHeader.UDP = new(v1alpha1.UDPHeader)
		pkt.TransportHeader.UDP.SrcPort = int32(r)
	}
	if r, ok := fields["udp_dst"]; ok {
		if pkt.TransportHeader.UDP == nil {
			pkt.TransportHeader.UDP = new(v1alpha1.UDPHeader)
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

func output(tf *v1alpha1.Traceflow) error {
	r := Response{
		Name:        tf.Name,
		Phase:       tf.Status.Phase,
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
	if option.outputType == "json" {
		if err := jsonOutput(&r); err != nil {
			return fmt.Errorf("error when converting output to json: %w", err)
		}
	} else if option.outputType == "yaml" {
		if err := yamlOutput(&r); err != nil {
			return fmt.Errorf("error when converting output to yaml: %w", err)
		}
	} else {
		return fmt.Errorf("output types should be yaml or json")
	}
	return nil
}

func yamlOutput(r *Response) error {
	o, err := yaml.Marshal(&r)
	if err != nil {
		return err
	}
	fmt.Println(string(o))
	return nil
}

func jsonOutput(r *Response) error {
	o, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	if err = json.Indent(&b, o, "", "  "); err != nil {
		return err
	}
	fmt.Println(string(b.Bytes()))
	return nil
}

func getTFName(prefix string) string {
	if option.nowait {
		return prefix
	}
	return fmt.Sprintf("%s-%s", prefix, rand.String(8))
}

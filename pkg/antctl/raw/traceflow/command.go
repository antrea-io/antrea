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
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/antctl/runtime"
	"github.com/vmware-tanzu/antrea/pkg/apis/ops/v1alpha1"
	clientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
)

var (
	Command *cobra.Command
	option  = &struct {
		source      string
		destination string
		outputType  string
		flow        string
		waiting     bool
	}{}
)

var protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

// Response is the response of antctl traceflow.
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
		Long:    "Start a Traceflows from one pod to another pod/service/IP.",
		Aliases: []string{"tf", "traceflows"},
		Example: `  Start a Traceflow from busybox0 to busybox1, both pods are in namespace default
  $antctl traceflow -S busybox0 -D busybox1
  Start a Traceflow from busybox0 to destination IP, source is in namespace default
  $antctl traceflow -S busybox0 -D 123.123.123.123
  Start a Traceflow from busybox0 to destination service, source and destination are in namespace default
  $antctl traceflow -S busybox0 -D svc0
  Start a Traceflow from busybox0 in namespace ns0 to busybox1 in namespace ns1, output type is json
  $antctl traceflow -S ns0/busybox0 -D ns1/busybox1 -o json
  Start a Traceflow from busybox0 to busybox1, with TCP header and 80 as destination port
  $antctl traceflow -S busybox0 -D busybox1 -f tcp,tcp_dst=80
`,
		RunE: runE,
	}

	Command.Flags().StringVarP(&option.source, "source", "S", "", "source of the traceflow: namespace/pod or pod")
	Command.Flags().StringVarP(&option.destination, "destination", "D", "", "destination of the traceflow: namespace/pod, pod, namespace/service, service or IP")
	Command.Flags().StringVarP(&option.outputType, "output", "o", "yaml", "output type: yaml (default), json")
	Command.Flags().BoolVarP(&option.waiting, "wait", "", true, "if false, command returns without retrieving results")
	Command.Flags().StringVarP(&option.flow, "flow", "f", "", "specify the flow (packet headers) of the traceflow packet")
}

func runE(cmd *cobra.Command, _ []string) error {
	if len(option.source) == 0 || len(option.destination) == 0 {
		fmt.Println("Please provide source and destination.")
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
	setupKubeconfig(kubeconfig, &v1alpha1.SchemeGroupVersion)

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
		return fmt.Errorf("error when filling up traceflow config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = client.OpsV1alpha1().Traceflows().Create(ctx, tf, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating traceflow, is traceflow feature gate enabled? %w", err)
	}
	defer func() {
		if option.waiting {
			if err = client.OpsV1alpha1().Traceflows().Delete(context.TODO(), tf.Name, metav1.DeleteOptions{}); err != nil {
				klog.Errorf("error when deleting traceflow: %+v", err)
			}
		}
	}()

	if !option.waiting {
		return nil
	}

	if err := wait.Poll(1*time.Second, 15*time.Second, func() (bool, error) {
		tf, err := client.OpsV1alpha1().Traceflows().Get(context.TODO(), tf.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if tf.Status.Phase != v1alpha1.Succeeded {
			return false, nil
		}
		if err := output(tf); err != nil {
			return false, fmt.Errorf("error when outputing result: %w", err)
		}
		return true, nil
	}); err != nil {
		return fmt.Errorf("error when retrieving traceflow: %w", err)
	}

	return nil
}

func setupKubeconfig(kubeconfig *rest.Config, groupVersion *schema.GroupVersion) {
	kubeconfig.APIPath = "/apis"
	kubeconfig.GroupVersion = groupVersion
	kubeconfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	kubeconfig.Insecure = true
	kubeconfig.CAFile = ""
	kubeconfig.CAData = nil
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
		return nil, fmt.Errorf("source should be in the format of namespace/pod or pod")
	}

	var dst v1alpha1.Destination
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
			return nil, fmt.Errorf("destination should be in the format of namespace/pod, pod, namespace/service or service")
		}
		if isPod, err = dstIsPod(client, dst.Namespace, dest); err != nil {
			return nil, fmt.Errorf("failed to check if destination is pod or service: %w", err)
		}
		if isPod {
			dst.Pod = dest
		} else {
			dst.Service = dest
		}
		name = getTFName(fmt.Sprintf("%s-%s-to-%s-%s", src.Namespace, src.Pod, dst.Namespace, dest))
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
		},
	}

	return tf, nil
}

func dstIsPod(client kubernetes.Interface, ns string, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get Pod from Kubernetes API: %w", err)
	}
	return true, nil
}

func parseFlow() (*v1alpha1.Packet, error) {
	cleanFlow := strings.ReplaceAll(option.flow, " ", "")
	pkt := new(v1alpha1.Packet)

	for _, v := range strings.Split(cleanFlow, ",") {
		n, ok := protocols[v]
		if ok {
			(*pkt).IPHeader.Protocol = n
			break
		}
	}

	r, ok, err := getFieldPortValue(cleanFlow, "tcp_src")
	if err != nil {
		return nil, fmt.Errorf("error when get tcp_src value: %w", err)
	}
	if ok {
		if (*pkt).TransportHeader.TCP == nil {
			(*pkt).TransportHeader.TCP = new(v1alpha1.TCPHeader)
		}
		(*pkt).TransportHeader.TCP.SrcPort = int32(r)
	}
	r, ok, err = getFieldPortValue(cleanFlow, "tcp_dst")
	if err != nil {
		return nil, fmt.Errorf("error when get tcp_dst value: %w", err)
	}
	if ok {
		if (*pkt).TransportHeader.TCP == nil {
			(*pkt).TransportHeader.TCP = new(v1alpha1.TCPHeader)
		}
		(*pkt).TransportHeader.TCP.DstPort = int32(r)
	}
	r, ok, err = getFieldPortValue(cleanFlow, "udp_src")
	if err != nil {
		return nil, fmt.Errorf("error when get udp_src value: %w", err)
	}
	if ok {
		if (*pkt).TransportHeader.UDP == nil {
			(*pkt).TransportHeader.UDP = new(v1alpha1.UDPHeader)
		}
		(*pkt).TransportHeader.UDP.SrcPort = int32(r)
	}
	r, ok, err = getFieldPortValue(cleanFlow, "udp_dst")
	if err != nil {
		return nil, fmt.Errorf("error when get udp_dst value: %w", err)
	}
	if ok {
		if (*pkt).TransportHeader.UDP == nil {
			(*pkt).TransportHeader.UDP = new(v1alpha1.UDPHeader)
		}
		(*pkt).TransportHeader.UDP.DstPort = int32(r)
	}

	return pkt, nil
}

func getFieldPortValue(cleanFlow string, f string) (int, bool, error) {
	for _, v := range strings.Split(cleanFlow, ",") {
		m, err := regexp.MatchString(fmt.Sprintf("%s=[0-9]+", f), v)
		if err != nil {
			return 0, false, err
		}
		if m {
			r, err := strconv.Atoi(v[len(f)+1:])
			if err != nil {
				return 0, false, err
			}
			return r, true, nil
		}
	}
	return 0, false, nil
}

func output(tf *v1alpha1.Traceflow) error {
	r := Response{
		Name:        tf.Name,
		Phase:       tf.Status.Phase,
		Source:      fmt.Sprintf("%s/%s", tf.Spec.Source.Namespace, tf.Spec.Source.Pod),
		Destination: tf.Spec.Destination.IP,
		NodeResults: tf.Status.Results,
	}
	if len(tf.Spec.Destination.IP) == 0 {
		if len(tf.Spec.Destination.Service) != 0 {
			r.Destination = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Service)
		} else {
			r.Destination = fmt.Sprintf("%s/%s", tf.Spec.Destination.Namespace, tf.Spec.Destination.Pod)
		}
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
		return fmt.Errorf("output types are yaml and json")
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
	if !option.waiting {
		return prefix
	}
	var lettersAndDigits = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, 8)
	for i := range b {
		randIdx := rand.Intn(len(lettersAndDigits))
		b[i] = lettersAndDigits[randIdx]
	}
	return fmt.Sprintf("%s-%s", prefix, string(b))
}

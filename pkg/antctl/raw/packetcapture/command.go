package packetcapture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const defaultTimeout time.Duration = time.Second * 60

var Command *cobra.Command

var option = &struct {
	source  string
	dest    string
	nowait  bool
	timeout time.Duration
	number  int32
	flow    string
}{}

var packetCaptureExample = strings.TrimSpace(`
  Start capture packets from pod1 to pod2, both Pods are in Namespace default
  $ antctl packetcaputre -S pod1 -D pod2
  Start capture packets from pod1 in Namespace ns1 to a destination IP
  $ antctl packetcapture -S ns1/pod1 -D 192.168.123.123
`)

func init() {
	Command = &cobra.Command{
		Use:     "packetcapture",
		Short:   "Start capture packets",
		Long:    "Start capture packets on the target flow.",
		Example: packetCaptureExample,
		RunE:    packetCaptureRunE,
	}

	Command.Flags().StringVarP(&option.source, "source", "S", "", "source of the the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().StringVarP(&option.dest, "destination", "D", "", "destination of the PacketCapture: Namespace/Pod, Pod, or IP")
	Command.Flags().Int32VarP(&option.number, "number", "n", 0, "target packets number")
	Command.Flags().StringVarP(&option.flow, "flow", "f", "", "specify the flow (packet headers) of the PacketCapture , including tcp_src, tcp_dst , udp_src, udp_dst")
	Command.Flags().BoolVarP(&option.nowait, "nowait", "", false, "TODO")
}

func packetCaptureRunE(cmd *cobra.Command, args []string) error {
	option.timeout, _ = cmd.Flags().GetDuration("timeout")
	if option.timeout > time.Hour {
		return errors.New("Timeout cannot be longer than 1 hour")
	}
	if option.timeout == 0 {
		option.timeout = defaultTimeout
	}
	if option.number == 0 {
		return errors.New("Packet number should be larger than 0")
	}

	_, client, err := raw.GetClients(cmd)
	if err != nil {
		return err
	}
	pc, err := newPacketCapture()
	if err != nil {
		return fmt.Errorf("error when filling up PacketCapture config: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.CrdV1alpha1().PacketCaptures().Create(ctx, pc, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("error when creating PacketCapture, is PacketCapture feature gate enabled? %w", err)
	}
	defer func() {
		if !option.nowait {
			if err = client.CrdV1alpha1().PacketCaptures().Delete(context.TODO(), pc.Name, metav1.DeleteOptions{}); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "error when deleting PacketCapture: %s", err.Error())
			}
		}
	}()

	if option.nowait {
		fmt.Fprintf(cmd.OutOrStdout(), "PacketCapture Name:  %s", pc.Name)
		return nil
	}

	var latestPC *v1alpha1.PacketCapture
	err = wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, option.timeout, false, func(ctx context.Context) (bool, error) {
		res, err := client.CrdV1alpha1().PacketCaptures().Get(ctx, pc.Name, metav1.GetOptions{})
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
	// err checked before
	restConfig, _ := raw.ResolveKubeconfig(cmd)
	coreV1Client, err := initCoreV1Client(restConfig)
	if err != nil {
		return err
	}
	fileName := filepath.Base(splits[1])

	pod := podFile{
		namespace:     "kube-system",
		name:          splits[0],
		containerName: "antrea-agent",
		restConfig:    restConfig,
		coreClient:    coreV1Client,
	}
	err = pod.copyFromPod(context.TODO(), splits[1], fileName)
	if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Packet File: %s\n", fileName)
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
	fields, err := raw.GetFlowFields(cleanFlow)
	if err != nil {
		return nil, fmt.Errorf("error when parsing the flow: %w", err)
	}
	var pkt v1alpha1.Packet
	pkt.IPFamily = v1.IPv4Protocol
	for k, v := range raw.Protocols {
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

package raw

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	antrea "antrea.io/antrea/pkg/client/clientset/versioned"
)

var Protocols = map[string]int32{
	"icmp": 1,
	"tcp":  6,
	"udp":  17,
}

func GetClients(cmd *cobra.Command) (kubernetes.Interface, antrea.Interface, error) {
	kubeconfig, err := ResolveKubeconfig(cmd)
	if err != nil {
		return nil, nil, err
	}
	k8sClientset, client, err := SetupClients(kubeconfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create clientset: %w", err)
	}
	return k8sClientset, client, nil
}

func GetFlowFields(flow string) (map[string]int, error) {
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

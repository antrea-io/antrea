package antctl

import (
	"context"
	"fmt"

	"antrea.io/antrea/pkg/antctl/raw"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	multiclusterv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var Command *cobra.Command

var getClustersCmd = &cobra.Command{
	Use:     "clusterset",
	Aliases: []string{"clustersets"},
	Short:   "Show Antrea multicluster clustersets",
	Long:    `Show Antrea multicluster clustersets`,
	Run:     runE,
}

func runE(cmd *cobra.Command, _ []string) error {
	kubeconfig, err := raw.ResolveKubeconfig(cmd)
	if err != nil {
		return err
	}
	kubeconfig.GroupVersion = &schema.GroupVersion{Group: "", Version: ""}
	restconfigTmpl := rest.CopyConfig(kubeconfig)
	raw.SetupKubeconfig(restconfigTmpl)
	if server, err := Command.Flags().GetString("server"); err != nil {
		kubeconfig.Host = server
	}

	k8sClientset, client, err := raw.SetupClients(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to setup: %w", err)
	}

	var res multiclusterv1alpha1.ClusterSet

	res, err = client.MulticlusV1alpha1(namespace).Clustersets().Get(context.TODO(), metav1.GetOptions{})

	if err != nil {
		return err
	}

	if err := output(res); err != nil {
		return fmt.Errorf("error when outputting result: %w", err)
	}
}

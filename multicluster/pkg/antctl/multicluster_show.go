package antctl

import (
	"github.com/spf13/cobra"
)

var multiclusterShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show multicluster resources",
	Long:  `Show multicluster resources`,
}

func init() {
	multiclusterCmd.AddCommand(multiclusterShowCmd)
}

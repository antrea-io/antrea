package antctl

import (
	"github.com/spf13/cobra"
)

var multiclusterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List multicluster resources",
	Long:  `List multicluster resources`,
}

func init() {
	multiclusterCmd.AddCommand(multiclusterListCmd)
}
